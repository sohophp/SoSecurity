<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Audit\AuditLogger;
use SoSecurity\Audit\BudgetedSink;
use SoSecurity\Audit\Diagnostics;
use SoSecurity\Audit\MetricsSink;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;

$directory = privateDirectory();
try {
    $clock = new TestClock();
    $store = new FileStore($directory, 'audit-diagnostics', $clock);
    $records = [];
    $metrics = new MetricsSink($store, 'site', ['login.failed' => 'authentication'],
        ['authentication' => 1], 3, 60,
        static function (array $record) use (&$records): void { $records[] = $record; }, $clock);
    $budget = new BudgetedSink($store, 'site', 2, 60, $metrics, $clock);
    $audit = new AuditLogger($budget, str_repeat('K', 32));
    $audit->record('login.failed', 'tenant', "private\0actor");
    $authorized = false;
    $checks = 0;
    $diagnostics = new Diagnostics($metrics, $budget, static function () use (&$authorized, &$checks): bool {
        ++$checks; return $authorized;
    });
    Check::throws(SecurityException::class, static function () use ($diagnostics): void { $diagnostics->inspect(); });
    Check::same(1, $checks);
    $authorized = true;
    $snapshot = $diagnostics->inspect();
    Check::same(['window_start', 'expires_at', 'counts', 'total', 'alerts', 'budget'], array_keys($snapshot));
    Check::same(1, $snapshot['total']);
    Check::same(['authentication'], $snapshot['alerts']);
    Check::same(['allowed' => true, 'remaining' => 1, 'retry_after' => 0], $snapshot['budget']);
    Check::same(false, strpos(json_encode($snapshot), 'private') !== false);
    Check::same(2, $checks);
    $audit->record('login.failed', 'tenant', 'another');
    Check::same(['allowed' => false, 'remaining' => 0, 'retry_after' => 60], $diagnostics->inspect()['budget']);
    Check::same(3, $checks);
    Check::same(2, count($records));
    $broken = new class implements AtomicStore {
        public function transact(string $key, callable $callback) { throw new StorageException('private backend fault', 'storage.io'); }
    };
    $unavailable = new MetricsSink($broken, 'site', ['login.failed' => 'authentication'],
        ['authentication' => 1], 3, 60, static function (array $record): void {}, $clock);
    $denied = new Diagnostics($unavailable, $budget, static function (): bool { return false; });
    $granted = new Diagnostics($unavailable, $budget, static function (): bool { return true; });
    Check::throws(SecurityException::class, static function () use ($denied): void { $denied->inspect(); });
    Check::throws(StorageException::class, static function () use ($granted): void { $granted->inspect(); });
    $throwing = new Diagnostics($metrics, $budget, static function (): bool { throw new RuntimeException('private auth fault'); });
    Check::throws(SecurityException::class, static function () use ($throwing): void { $throwing->inspect(); });
    $truthy = new Diagnostics($metrics, $budget, static function () { return 1; });
    Check::throws(SecurityException::class, static function () use ($truthy): void { $truthy->inspect(); });
    Check::throws(ConfigurationException::class, static function () use ($diagnostics): void { serialize($diagnostics); });
    Check::same(false, strpos(var_export($diagnostics, true), $directory) !== false);
    Check::same(false, strpos(var_export($diagnostics, true), 'private') !== false);
    Check::same(PHP_SESSION_NONE, session_status());
    Check::same(false, headers_sent());
    echo 'PASS audit diagnostics: ' . Check::$assertions . ' assertions PHP ' . PHP_VERSION . "\n";
} finally { cleanDirectory($directory); }
