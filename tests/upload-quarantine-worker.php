<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/upload-quarantine-backend-support.php';

use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\FileStore;
use SoSecurity\Upload\Candidate;
use SoSecurity\Upload\Policy;
use SoSecurity\Upload\Quarantine;
use SoSecurity\Upload\Scanner;

$root = $argv[1] ?? ''; $mode = $argv[2] ?? ''; $id = $argv[3] ?? null;
if (strpos($root, '/tmp/sosecurity-quarantine-race-') !== 0 || realpath($root) !== $root || !is_dir($root) || (fileperms($root) & 0777) !== 0700) { throw new RuntimeException('Owned local test root required.'); }
$variant = getenv('SOSECURITY_TEST_QUARANTINE_CLASS');
if ($variant !== false && $variant !== '') {
    if (strpos($variant, '/tmp/sosecurity-quarantine-sdk-') !== 0 || !is_file($variant)) { throw new RuntimeException('Owned test-only class variant required.'); }
    require $variant;
}
final class QuarantineRaceScanner implements Scanner
{
    private $root;
    private $wait;
    public function __construct(string $root, bool $wait) { $this->root = $root; $this->wait = $wait; }
    public function scan(Candidate $candidate): bool
    {
        if ($candidate->contents() !== "scan me\n") { throw new RuntimeException('Full validated snapshot required.'); }
        if ($this->wait) {
            file_put_contents($this->root . '/entered', 'scanner'); $until = microtime(true) + 12;
            while (!is_file($this->root . '/release')) { clearstatcache(); if (microtime(true) >= $until) { throw new RuntimeException('Owned test barrier timed out.'); } usleep(1000); }
        }
        return true;
    }
}
final class QuarantineStagingStore implements AtomicStore
{
    private $delegate;
    private $root;
    public function __construct(AtomicStore $delegate, string $root) { $this->delegate = $delegate; $this->root = $root; }
    public function transact(string $key, callable $callback)
    {
        $result = $this->delegate->transact($key, $callback);
        file_put_contents($this->root . '/entered', 'reserved'); $until = microtime(true) + 12;
        while (!is_file($this->root . '/release')) { clearstatcache(); if (microtime(true) >= $until) { throw new RuntimeException('Owned test barrier timed out.'); } usleep(1000); }
        return $result;
    }
}
$backend = getenv('SOSECURITY_TEST_QUARANTINE_BACKEND');
$store = in_array($backend, ['redis', 'mysql'], true) ? quarantineBackendStore($backend) : new FileStore($root . '/ledger', 'quarantine-race');
if ($mode === 'staging') { $store = new QuarantineStagingStore($store, $root); }
$queue = new Quarantine($store, new Policy(['extensions' => ['txt'], 'maximum_bytes' => 1024, 'working_bytes' => 2097152]),
    new QuarantineRaceScanner($root, $mode === 'scan-wait'), $root . '/spool', $root . '/web', 'files',
    ['lease_seconds' => 6, 'scan_milliseconds' => 5000, 'maximum_attempts' => 2, 'retry_seconds' => 1, 'lifetime_seconds' => 60]);
if ($mode === 'enqueue' || $mode === 'staging') { $result = $queue->enqueueFile($root . '/source', 'file.txt')->metadata(); }
elseif ($mode === 'scan-wait' || $mode === 'scan') { $result = $queue->process($id)->metadata(); }
elseif ($mode === 'reject') { $result = $queue->reject($id)->metadata(); }
elseif ($mode === 'inspect') { $result = $queue->inspect($id)->metadata(); }
elseif ($mode === 'items') { $result = array_map(static function ($status): array { return $status->metadata(); }, $queue->items()); }
elseif ($mode === 'remove') { $result = ['removed' => $queue->remove($id)]; }
elseif ($mode === 'read') {
    try { $contents = $queue->readAvailable($id)->contents(); }
    catch (SoSecurity\Exception\SecurityException $error) { echo json_encode(['denied' => true]) . "\n"; exit(0); }
    $result = ['contents' => $contents];
} else { throw new RuntimeException('Unknown owned test command.'); }
echo json_encode($result) . "\n";
