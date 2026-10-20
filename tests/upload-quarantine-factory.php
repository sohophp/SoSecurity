<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Security;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Upload\Candidate;
use SoSecurity\Upload\Scanner;

if (!extension_loaded('fileinfo')) { throw new RuntimeException('NOT RUN quarantine factory: fileinfo required'); }
final class FactoryQuarantineScanner implements Scanner
{
    public $calls = 0;
    public function scan(Candidate $candidate): bool { ++$this->calls; Check::same("factory payload\n", $candidate->contents()); return true; }
}
final class FactoryQuarantineStore implements AtomicStore
{
    public $calls = 0;
    private $store;
    public function __construct(AtomicStore $store) { $this->store = $store; }
    public function transact(string $key, callable $callback) { ++$this->calls; return $this->store->transact($key, $callback); }
}
$source = privateDirectory(); $spool = privateDirectory(); $ledger = privateDirectory(); $web = privateDirectory(); $otherWeb = privateDirectory();
try {
    $clock = new TestClock(); $scanner = new FactoryQuarantineScanner(); $custom = new FactoryQuarantineStore(new FileStore($ledger, 'physical', $clock));
    $options = ['directory' => $spool, 'document_root' => $web, 'scanner' => 'scanner', 'policy' => ['extensions' => ['txt'], 'maximum_bytes' => 1024],
        'queue' => ['maximum_attempts' => 2, 'scan_milliseconds' => 1000, 'lease_seconds' => 3]];
    $base = ['site' => 'alpha', 'storage' => ['driver' => 'provided', 'connection' => 'state'], 'upload_quarantine' => $options];
    $services = ['scanner' => $scanner, 'state' => $custom];
    $make = static function (array $changes = [], array $injected = []) use ($base, $services, $clock): Security {
        return Security::fromArray(array_replace($base, $changes), array_replace($services, $injected), $clock);
    };
    $plain = Security::fromArray(['site' => 'plain']); Check::same(null, $plain->config()->uploadQuarantine());
    Check::throws(ConfigurationException::class, static function () use ($plain): void { $plain->quarantine(); });
    Check::same('not_configured', array_column($plain->diagnose(), null, 'check')['quarantine']['status']);
    $factory = $make(); Check::same(true, $factory->config()->uploadQuarantine()['policy']['require_scan']);
    Check::throws(ConfigurationException::class, static function () use ($factory): void { $factory->uploader(); });
    $syncOnly = Security::fromArray(['site' => 'sync-only', 'upload' => ['directory' => $spool, 'document_root' => $web, 'extensions' => ['txt']]]);
    Check::throws(ConfigurationException::class, static function () use ($syncOnly): void { $syncOnly->quarantine(); });
    Check::same('uploads', $factory->config()->uploadQuarantine()['scope']);
    $factory->quarantine(); Check::same(0, $custom->calls); Check::same(0, $scanner->calls);
    $before = [scandir($spool), scandir($ledger)];
    $checks = $factory->diagnose($web); $byName = array_column($checks, null, 'check');
    foreach (['quarantine.scanner', 'quarantine.storage', 'quarantine.workflow'] as $name) { Check::same('manual', $byName[$name]['status']); }
    foreach (['quarantine.directory', 'quarantine.inspection', 'quarantine.document_root'] as $name) { Check::same('pass', $byName[$name]['status']); }
    Check::same($before, [scandir($spool), scandir($ledger)]); Check::same(0, $custom->calls); Check::same(0, $scanner->calls);
    $factory->diagnose($web, true); Check::same(0, $custom->calls); Check::same(0, $scanner->calls);
    Check::same($before, [scandir($spool), scandir($ledger)]);
    foreach ([$spool, $ledger, $web] as $private) { Check::same(false, strpos(json_encode($checks), $private) !== false); }
    Check::same('manual', array_column($factory->diagnose(), null, 'check')['quarantine.document_root']['status']);
    foreach ([$otherWeb, $web . '/missing'] as $badRoot) { Check::same('fail', array_column($factory->diagnose($badRoot), null, 'check')['quarantine.document_root']['status']); }
    chmod($spool, 0755); Check::same('fail', array_column($factory->diagnose($web), null, 'check')['quarantine.directory']['status']); chmod($spool, 0700);
    $uncreated = $options; $uncreated['directory'] = $spool . '/does-not-exist'; $lazy = $make(['upload_quarantine' => $uncreated]);
    Check::same(false, file_exists($uncreated['directory']));
    Check::same('fail', array_column($lazy->diagnose($web), null, 'check')['quarantine.directory']['status']);
    Check::throws(ConfigurationException::class, static function () use ($lazy): void { $lazy->quarantine(); });
    Check::same(false, file_exists($uncreated['directory']));
    foreach ([null, [], ['unexpected' => true]] as $bad) {
        Check::throws(ConfigurationException::class, static function () use ($make, $bad): void { $make(['upload_quarantine' => $bad]); });
    }
    foreach ([['scanner' => null], ['scope' => "bad\0scope"], ['scope' => str_repeat('s', 257)], ['policy' => null], ['queue' => null],
        ['policy' => ['require_scan' => false]], ['policy' => ['require_scan' => 'true']], ['policy' => ['extensions' => ['exe']]],
        ['queue' => ['maximum_entries' => 65]], ['queue' => ['maximum_total_bytes' => 0]], ['queue' => ['maximum_attempts' => '3']],
        ['queue' => ['lease_seconds' => 2, 'scan_milliseconds' => 2000]], ['queue' => ['unknown' => true]]] as $bad) {
        Check::throws(ConfigurationException::class, static function () use ($make, $options, $bad): void { $make(['upload_quarantine' => array_replace($options, $bad)]); });
    }
    foreach ([null, new stdClass()] as $badScanner) {
        $invalid = $make([], ['scanner' => $badScanner]);
        Check::throws(ConfigurationException::class, static function () use ($invalid): void { $invalid->quarantine(); });
        Check::same('fail', array_column($invalid->diagnose($web), null, 'check')['quarantine.scanner']['status']);
    }
    foreach ([null, ['driver' => 'memory'], ['driver' => 'session']] as $badStore) {
        $config = $base; if ($badStore === null) { unset($config['storage']); } else { $config['storage'] = $badStore; }
        $invalid = Security::fromArray($config, $services, $clock);
        Check::throws(ConfigurationException::class, static function () use ($invalid): void { $invalid->quarantine(); });
        Check::same('fail', array_column($invalid->diagnose($web), null, 'check')['quarantine.storage']['status']);
    }
    $invalid = $make([], ['state' => new MemoryStore($clock)]);
    Check::throws(ConfigurationException::class, static function () use ($invalid): void { $invalid->quarantine(); });
    Check::same('fail', array_column($invalid->diagnose($web), null, 'check')['quarantine.storage']['status']);
    $publicState = $make(['storage' => ['driver' => 'file', 'directory' => $web]]);
    Check::throws(ConfigurationException::class, static function () use ($publicState): void { $publicState->quarantine(); });
    Check::same('fail', array_column($publicState->diagnose($web), null, 'check')['quarantine.storage']['status']);
    Check::same([], array_values(array_diff(scandir($web), ['.', '..'])));
    // Configuration references are copied before any service can be used.
    $maximum = 1; $extensions = ['txt']; $bound = $options;
    $bound['queue']['maximum_entries'] = &$maximum; $bound['policy']['extensions'] = &$extensions;
    $pinned = $make(['upload_quarantine' => $bound]); $maximum = 64; $extensions[] = 'png';
    Check::same(1, $pinned->config()->uploadQuarantine()['queue']['maximum_entries']);
    Check::same(['txt'], $pinned->config()->uploadQuarantine()['policy']['extensions']);
    $scope = str_repeat('s', 256); $site = str_repeat('a', 128);
    $long = $make(['site' => $site, 'upload_quarantine' => array_replace($options, ['scope' => $scope])]); $long->quarantine();
    Check::same(0, $scanner->calls); Check::same(0, $custom->calls);
    file_put_contents($source . '/source', "factory payload\n");
    $queue = $factory->quarantine(); $id = $queue->enqueueFile($source . '/source', 'test.txt')->id();
    $other = $make(['site' => 'beta'])->quarantine();
    Check::same(null, $other->inspect($id)); Check::same([], $other->items());
    Check::throws(SecurityException::class, static function () use ($other, $id): void { $other->readAvailable($id); });
    Check::throws(SecurityException::class, static function () use ($other, $id): void { $other->reject($id); });
    $otherScope = $make(['upload_quarantine' => array_replace($options, ['scope' => 'different'])])->quarantine();
    Check::same(null, $otherScope->inspect($id));
    Check::same('pending', $make()->quarantine()->inspect($id)->state());
    Check::same('available', $make()->quarantine()->process($id)->state()); Check::same(1, $scanner->calls);
    Check::same("factory payload\n", $make()->quarantine()->readAvailable($id)->contents());
    Check::throws(SecurityException::class, static function () use ($other, $id): void { $other->readAvailable($id); });
    $queue->reject($id); Check::same(true, $queue->remove($id)); Check::same("factory payload\n", file_get_contents($source . '/source'));
    // Native file-driver configuration follows the same path without a provided-store adapter.
    $native = $make(['storage' => ['driver' => 'file', 'directory' => $ledger]])->quarantine();
    $id = $native->enqueueFile($source . '/source', 'native.txt')->id(); Check::same('available', $native->process($id)->state());
    $native->reject($id); Check::same(true, $native->remove($id));
    Check::same(PHP_SESSION_NONE, session_status()); Check::same(false, headers_sent());
    Check::same(true, memory_get_peak_usage(true) < 8388608);
    echo 'PASS quarantine factory/configuration/readonly diagnostics: ' . Check::$assertions . ' assertions PHP ' . PHP_VERSION . "; lazy construction, required services, site/scope isolation and installed-compatible flow\n";
} finally { cleanDirectory($source); cleanDirectory($spool); cleanDirectory($ledger); cleanDirectory($web); cleanDirectory($otherWeb); }
