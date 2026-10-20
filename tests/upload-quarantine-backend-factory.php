<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/upload-quarantine-backend-support.php';

use SoSecurity\Security;
use SoSecurity\Storage\StorageException;
use SoSecurity\Upload\Candidate;
use SoSecurity\Upload\Scanner;

final class QuarantineBackendScanner implements Scanner
{
    public $calls = 0;
    public function scan(Candidate $candidate): bool
    {
        ++$this->calls;
        Check::same("safe bytes\n", $candidate->contents());
        return true;
    }
}

$backend = $argv[1] ?? '';
if (!in_array($backend, ['redis', 'mysql'], true)) { throw new RuntimeException('Select an owned local metadata backend.'); }
$client = quarantineBackendConnection($backend);
$source = privateDirectory(); $spool = privateDirectory(); $web = privateDirectory();
try {
    $clock = new TestClock(); $scanner = new QuarantineBackendScanner();
    $config = ['site' => 'quarantine-factory', 'storage' => ['driver' => $backend, 'connection' => 'metadata'],
        'upload_quarantine' => ['directory' => $spool, 'document_root' => $web, 'scanner' => 'scanner',
            'scope' => 'files', 'policy' => ['extensions' => ['txt'], 'maximum_bytes' => 1024]]];
    $services = ['metadata' => $client, 'scanner' => $scanner];
    $make = static function (array $settings) use ($services, $clock): Security { return Security::fromArray($settings, $services, $clock); };
    $factory = $make($config);
    if ($backend === 'redis') {
        Check::throws(StorageException::class, static function () use ($factory): void { $factory->quarantine()->items(); });
    }
    $deployment = $factory->initializeStorage();
    Check::same($backend === 'redis' ? 'initialized' : 'schema_verified', $deployment['shared']);
    Check::same(0, $scanner->calls);
    file_put_contents($source . '/safe.txt', "safe bytes\n");
    $id = $factory->quarantine()->enqueueFile($source . '/safe.txt', 'safe.txt')->id();
    $fresh = $make($config)->quarantine();
    Check::same('pending', $fresh->inspect($id)->state());
    Check::same('available', $fresh->process($id)->state());
    Check::same("safe bytes\n", $make($config)->quarantine()->readAvailable($id)->contents());
    Check::same(1, $scanner->calls);
    $other = $config; $other['upload_quarantine']['scope'] = 'other-files';
    Check::same(null, $make($other)->quarantine()->inspect($id));
    Check::same('rejected', $fresh->reject($id)->state());
    Check::same(true, $fresh->remove($id));
    Check::same([], $make($config)->quarantine()->items());
    echo 'PASS native quarantine factory ' . $backend . ': ' . Check::$assertions . ' assertions PHP ' . PHP_VERSION . "\n";
} finally {
    cleanDirectory($source); cleanDirectory($spool); cleanDirectory($web);
    if ($backend === 'redis') { $client->close(); }
}
