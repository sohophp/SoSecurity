<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/upload-quarantine-backend-support.php';

use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Upload\Candidate;
use SoSecurity\Upload\Policy;
use SoSecurity\Upload\Quarantine;
use SoSecurity\Upload\Scanner;

if (!extension_loaded('fileinfo')) { echo "NOT RUN quarantine: fileinfo required\n"; exit(1); }
final class QuarantineTestScanner implements Scanner
{
    public $calls = 0;
    public $action;
    public function scan(Candidate $candidate): bool { ++$this->calls; return ($this->action)($candidate); }
}
final class QuarantineTestStore implements AtomicStore
{
    public $delegate;
    public $afterCommit = false;
    public $tamper;
    public $inside = false;
    public function __construct(AtomicStore $delegate) { $this->delegate = $delegate; }
    public function transact(string $key, callable $callback)
    {
        $result = $this->delegate->transact($key, function ($value) use ($callback) {
            if ($this->tamper !== null) { $value = ($this->tamper)($value); }
            $this->inside = true;
            try {
                $first = $callback($value); $second = $callback($value);
                Check::same($first->value(), $second->value());
                return $second;
            } finally { $this->inside = false; }
        });
        if ($this->afterCommit) { $this->afterCommit = false; throw new StorageException('Injected lost commit confirmation.'); }
        return $result;
    }
}
$source = privateDirectory(); $spool = privateDirectory(); $web = privateDirectory(); $ledger = privateDirectory();
$clock = new TestClock(); $scanner = new QuarantineTestScanner(); $scanner->action = static function (Candidate $file): bool { return true; };
$backend = in_array($argv[1] ?? '', ['redis', 'mysql'], true) ? $argv[1] : 'file';
$imagesProfile = in_array('images', $argv, true);
$store = new QuarantineTestStore($backend === 'file' ? new FileStore($ledger, 'quarantine-test', $clock) : quarantineBackendStore($backend, $clock, true));
$options = ['lease_seconds' => 2, 'scan_milliseconds' => 100, 'retry_seconds' => 3, 'maximum_attempts' => 2, 'lifetime_seconds' => 60];
$policy = new Policy(['extensions' => ['txt'], 'maximum_bytes' => 1024, 'working_bytes' => 2097152, 'require_scan' => true]);
$make = static function (string $scope = 'files', ?Scanner $adapter = null, array $overrides = []) use ($store, $policy, $scanner, $spool, $web, $options, $clock): Quarantine {
    return new Quarantine($store, $policy, $adapter ?? $scanner, $spool, $web, $scope, array_replace($options, $overrides), $clock);
};
$path = static function (string $id) use ($spool): string { return $spool . '/' . $id . '.txt'; };
try {
    file_put_contents($source . '/text', "alpha\n");
    $queue = $make(); Check::same([], array_diff(scandir($spool), ['.', '..']));
    $pending = $queue->enqueueFile($source . '/text', 'source.txt'); $id = $pending->id();
    Check::same('pending', $pending->state()); Check::same(0, $scanner->calls); Check::same("alpha\n", file_get_contents($path($id)));
    Check::same(0600, fileperms($path($id)) & 0777); Check::same(0600, fileperms($spool . '/.quarantine.lock') & 0777);
    Check::throws(SecurityException::class, static function () use ($queue, $id): void { $queue->readAvailable($id); });
    // A separately constructed process adapter sees the same persisted job and validated bytes.
    $queue = $make(); $scanner->action = static function (Candidate $file) use ($store): bool {
        Check::same(false, $store->inside); Check::same("alpha\n", $file->contents()); return true;
    };
    Check::same('available', $queue->process()->state()); Check::same("alpha\n", $queue->readAvailable($id)->contents());
    Check::same(null, $queue->process()); Check::same(1, $scanner->calls);
    Check::throws(SecurityException::class, static function () use ($queue, $id): void { $queue->remove($id); });
    Check::same('pending', $queue->rescan($id)->state());
    Check::throws(SecurityException::class, static function () use ($queue, $id): void { $queue->readAvailable($id); });
    $scanner->action = static function (Candidate $file): bool { return false; };
    Check::same('rejected', $queue->process($id)->state()); Check::same(1, $queue->inspect($id)->attempts());
    Check::same(true, $queue->remove($id)); Check::same(false, file_exists($path($id))); Check::same(false, $queue->remove($id));
    Check::same(null, $queue->inspect($id)); Check::same("alpha\n", file_get_contents($source . '/text'));

    $scanner->action = static function (Candidate $file): bool { throw new RuntimeException('private engine diagnostics'); };
    $id = $queue->enqueueFile($source . '/text', 'retry.txt')->id();
    Check::same('retry', $queue->process($id)->state()); $calls = $scanner->calls;
    Check::same('retry', $queue->process($id)->state()); Check::same($calls, $scanner->calls);
    $clock->time += 3; Check::same('failed', $queue->process($id)->state()); Check::same(2, $queue->inspect($id)->attempts());
    Check::same('scan.failed', $queue->inspect($id)->error()); Check::same(true, $queue->remove($id));

    // An administrator changing the generation during scanning wins over the old clean result.
    $id = $queue->enqueueFile($source . '/text', 'racing.txt')->id();
    $scanner->action = static function (Candidate $file) use ($queue, $id): bool { $queue->reject($id); return true; };
    Check::same('rejected', $queue->process($id)->state());
    Check::throws(SecurityException::class, static function () use ($queue, $id): void { $queue->readAvailable($id); });
    $queue->remove($id);
    $id = $queue->enqueueFile($source . '/text', 'lease.txt')->id(); $second = new QuarantineTestScanner();
    $second->action = static function (Candidate $file): bool { return false; }; $other = $make('files', $second);
    $scanner->action = static function (Candidate $file) use ($clock, $other, $id): bool { $clock->time += 2; Check::same('rejected', $other->process($id)->state()); return true; };
    Check::same('rejected', $queue->process($id)->state()); Check::same(2, $queue->inspect($id)->attempts()); $queue->remove($id);

    // Full digest checking detects equal-length changes, not only size changes.
    $scanner->action = static function (Candidate $file): bool { return true; };
    $id = $queue->enqueueFile($source . '/text', 'tamper.txt')->id(); $queue->process($id);
    file_put_contents($path($id), "omega\n");
    Check::throws(StorageException::class, static function () use ($queue, $id): void { $queue->readAvailable($id); });
    $queue->rescan($id); Check::same('failed', $queue->process($id)->state()); Check::same('content.invalid', $queue->inspect($id)->error()); $queue->remove($id);
    $id = $queue->enqueueFile($source . '/text', 'expire.txt')->id(); $clock->time += 60;
    Check::same('expired', $queue->inspect($id)->state()); Check::same(null, $queue->process()); $queue->remove($id);

    // An uncertain reservation does not start writing. An uncertain cleanup does not unlink.
    $store->afterCommit = true;
    Check::throws(StorageException::class, static function () use ($queue, $source): void { $queue->enqueueFile($source . '/text', 'unknown.txt'); });
    $items = $queue->items(); Check::same(1, count($items)); $id = $items[0]->id(); Check::same('staging', $items[0]->state());
    Check::same(false, file_exists($path($id))); Check::same(true, $queue->remove($id));
    $id = $queue->enqueueFile($source . '/text', 'cleanup.txt')->id(); $queue->reject($id); $store->afterCommit = true;
    Check::throws(StorageException::class, static function () use ($queue, $id): void { $queue->remove($id); });
    Check::same(true, file_exists($path($id))); Check::same('deleting', $queue->inspect($id)->state());
    Check::throws(SecurityException::class, static function () use ($queue, $id): void { $queue->readAvailable($id); });
    Check::same(true, $queue->remove($id));

    $small = $make('capacity', null, ['maximum_entries' => 1]); $id = $small->enqueueFile($source . '/text', 'one.txt')->id();
    $files = scandir($spool);
    Check::throws(StorageException::class, static function () use ($small, $source): void { $small->enqueueFile($source . '/text', 'two.txt'); });
    Check::same($files, scandir($spool)); $small->reject($id); $small->remove($id);
    $bytesQueue = $make('bytes-capacity', null, ['maximum_total_bytes' => 6]);
    $id = $bytesQueue->enqueueFile($source . '/text', 'exact.txt')->id(); $files = scandir($spool);
    Check::throws(StorageException::class, static function () use ($bytesQueue, $source): void { $bytesQueue->enqueueFile($source . '/text', 'over.txt'); });
    Check::same($files, scandir($spool)); $bytesQueue->reject($id); $bytesQueue->remove($id);
    $full = $make('full-capacity'); $ids = [];
    for ($index = 0; $index < 64; ++$index) { $ids[] = $full->enqueueFile($source . '/text', 'full.txt')->id(); }
    Check::same(64, count($full->items()));
    Check::throws(StorageException::class, static function () use ($full, $source): void { $full->enqueueFile($source . '/text', 'extra.txt'); });
    foreach ($ids as $fullId) { $full->reject($fullId); $full->remove($fullId); }
    Check::same([], $full->items());
    file_put_contents($source . '/nul', "a\0b"); file_put_contents($source . '/large', str_repeat('x', 1025));
    foreach (['nul', 'large'] as $name) { Check::throws(ValidationException::class, static function () use ($queue, $source, $name): void { $queue->enqueueFile($source . '/' . $name, 'bad.txt'); }); }
    Check::same([], $queue->items());
    $id = $queue->enqueueFile($source . '/text', 'corrupt.txt')->id();
    $store->tamper = static function (?array $state) use ($id): ?array { $state['entries'][$id]['file']['bytes'] = 16777216; return $state; };
    Check::throws(StorageException::class, static function () use ($queue, $id): void { $queue->process($id); });
    $store->tamper = null; $queue->reject($id); $queue->remove($id);
    $badPolicy = $make('files', null, ['maximum_attempts' => 3]);
    Check::throws(StorageException::class, static function () use ($badPolicy): void { $badPolicy->items(); });

    $id = $queue->enqueueFile($source . '/text', 'timeout.txt')->id();
    $scanner->action = static function (Candidate $file): bool { usleep(130000); return true; };
    Check::same('retry', $queue->process($id)->state()); Check::same('scan.timeout', $queue->inspect($id)->error()); $queue->reject($id); $queue->remove($id);
    // Mutation after a clean scan is not treated as the scanned bytes.
    $id = $queue->enqueueFile($source . '/text', 'changed.txt')->id();
    $scanner->action = static function (Candidate $file) use ($path, $id): bool { file_put_contents($path($id), "omega\n"); return true; };
    Check::same('failed', $queue->process($id)->state()); Check::same('content.invalid', $queue->inspect($id)->error()); $queue->remove($id);
    $scanner->action = static function (Candidate $file): bool { return true; };
    foreach (['permissions', 'hardlink', 'symlink'] as $mutation) {
        $id = $queue->enqueueFile($source . '/text', 'protected.txt')->id(); $queue->process($id);
        if ($mutation === 'permissions') { chmod($path($id), 0644); }
        elseif ($mutation === 'hardlink') { link($path($id), $source . '/hardlink'); }
        else { unlink($path($id)); symlink($source . '/text', $path($id)); }
        Check::throws(StorageException::class, static function () use ($queue, $id): void { $queue->readAvailable($id); });
        if ($mutation === 'permissions') { chmod($path($id), 0600); }
        elseif ($mutation === 'hardlink') { unlink($source . '/hardlink'); }
        else {
            $queue->reject($id);
            Check::throws(StorageException::class, static function () use ($queue, $id): void { $queue->remove($id); });
            Check::same('deleting', $queue->inspect($id)->state()); unlink($path($id)); $queue->remove($id); continue;
        }
        $queue->reject($id); $queue->remove($id);
    }
    $clock->time -= 1;
    Check::throws(StorageException::class, static function () use ($queue): void { $queue->items(); });
    Check::throws(StorageException::class, static function () use ($make): void { $make()->items(); });
    ++$clock->time;
    // Binary PNG bytes (including NUL) are scanned and returned without a second re-encoding pass.
    if ($imagesProfile && extension_loaded('gd')) {
        $image = imagecreatetruecolor(2, 2); imagepng($image, $source . '/png'); if (is_resource($image)) { imagedestroy($image); } unset($image);
        $binary = new QuarantineTestScanner(); $scanned = null;
        $binary->action = static function (Candidate $file) use (&$scanned): bool { Check::same(true, strpos($file->contents(), "\0") !== false); $scanned = $file->contents(); return true; };
        $images = new Quarantine($store, new Policy(['extensions' => ['png']]), $binary, $spool, $web, 'images', $options, $clock);
        $id = $images->enqueueFile($source . '/png', 'picture.png')->id(); Check::same('available', $images->process($id)->state());
        Check::same($scanned, $images->readAvailable($id)->contents()); $images->reject($id); $images->remove($id);
        $image = imagecreatetruecolor(2, 2); imagejpeg($image, $source . '/jpeg'); if (is_resource($image)) { imagedestroy($image); } unset($image);
        $jpegs = new Quarantine($store, new Policy(['extensions' => ['jpeg']]), $binary, $spool, $web, 'jpeg-alias', $options, $clock);
        $id = $jpegs->enqueueFile($source . '/jpeg', 'picture.jpeg')->id(); Check::same('available', $jpegs->process($id)->state());
        Check::same('jpg', $jpegs->readAvailable($id)->extension()); Check::same($scanned, $jpegs->readAvailable($id)->contents());
        $jpegs->reject($id); $jpegs->remove($id);
    } elseif ($imagesProfile) { throw new RuntimeException('NOT RUN binary quarantine image path: GD required'); }
    foreach ([$queue, $scanner] as $object) { if ($object instanceof Quarantine) { Check::throws(SoSecurity\Exception\ConfigurationException::class, static function () use ($object): void { serialize($object); }); } }
    ob_start(); var_dump($queue); $debug = ob_get_clean(); $export = var_export($queue, true);
    foreach ([$debug, $export] as $value) { Check::same(false, strpos($value, $spool) !== false); Check::same(false, strpos($value, $ledger) !== false); Check::same(false, strpos($value, 'private engine diagnostics') !== false); }
    Check::same(true, memory_get_peak_usage(true) < 8388608);
    echo 'PASS persistent upload quarantine: ' . Check::$assertions . ' assertions PHP ' . PHP_VERSION . '; profile=' . ($imagesProfile ? 'images' : 'core') . '; backend=' . $backend . "; retries, fencing, corruption, expiry and unknown commits\n";
} finally {
    cleanDirectory($source); cleanDirectory($spool); cleanDirectory($web); cleanDirectory($ledger);
}
