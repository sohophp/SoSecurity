<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Audit\AuditLogger;
use SoSecurity\Audit\MetricsSink;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\StorageException;

$directory = privateDirectory();
try {
    $clock = new TestClock();
    $store = new FileStore($directory, 'audit-metrics', $clock);
    $events = ['login.failed' => 'authentication', 'authorization.denied' => 'authorization'];
    $thresholds = ['authentication' => 2, 'authorization' => 1];
    $written = [];
    $writer = static function (array $record) use (&$written): void { $written[] = $record; };
    $metrics = new MetricsSink($store, 'site', $events, $thresholds, 3, 60, $writer, $clock);
    $other = new MetricsSink(new FileStore($directory, 'audit-metrics', $clock), 'site', $events, $thresholds, 3, 60, $writer, $clock);
    $audit = new AuditLogger($metrics, str_repeat('K', 32));
    Check::same(0, $metrics->inspect()['total']);
    $audit->record('login.failed', 'tenant', "actor\0one", ['allowed' => false]);
    Check::same(1, $other->inspect()['counts']['authentication']);
    Check::same([], $other->inspect()['alerts']);
    $audit->record('authorization.denied', 'tenant', 'actor', ['allowed' => false]);
    Check::same(['authorization'], $metrics->inspect()['alerts']);
    $audit->record('login.failed', 'tenant', 'actor');
    $snapshot = $other->inspect();
    Check::same(3, $snapshot['total']);
    Check::same(['authentication', 'authorization'], $snapshot['alerts']);
    Check::same(false, strpos(json_encode($snapshot), 'actor') !== false);
    Check::same(3, count($written));
    Check::throws(SecurityException::class, static function () use ($audit): void { $audit->record('login.failed', 'tenant', 'extra'); });
    Check::throws(ConfigurationException::class, static function () use ($audit): void { $audit->record('unknown.event', 'tenant'); });
    Check::throws(ConfigurationException::class, static function () use ($metrics): void {
        $metrics(['time' => 1, 'event' => 'login.failed', 'scope' => 'tenant', 'subject' => null,
            'context' => [], 'password' => 'private']);
    });
    Check::same(3, count($written));
    Check::same(3, $metrics->inspect()['total']);
    $changed = new MetricsSink($store, 'site', $events, ['authentication' => 1], 3, 60, $writer, $clock);
    Check::throws(ConfigurationException::class, static function () use ($changed): void { $changed->inspect(); });
    $clock->time += 60;
    Check::same(0, $changed->inspect()['total']);
    Check::same([], $changed->inspect()['alerts']);
    $private = 'SYNTHETIC-PRIVATE-METRIC-SINK';
    $failing = new MetricsSink($store, 'failing', $events, [], 3, 60,
        static function () use ($private): void { throw new RuntimeException('local writer failure'); }, $clock);
    Check::same(false, strpos(var_export($failing, true), $private) !== false);
    Check::same(false, strpos(var_export($failing, true), $directory) !== false);
    Check::throws(ConfigurationException::class, static function () use ($failing): void { serialize($failing); });
    Check::throws(RuntimeException::class, static function () use ($failing): void {
        (new AuditLogger($failing, str_repeat('K', 32)))->record('login.failed', 'tenant', 'actor');
    });
    Check::same(1, $failing->inspect()['total']);
    Check::throws(ConfigurationException::class, static function () use ($events, $writer, $clock): void {
        new MetricsSink(new MemoryStore($clock), 'site', $events, [], 3, 60, $writer, $clock);
    });
    $broken = new class implements AtomicStore {
        public function transact(string $key, callable $callback) { throw new StorageException('local test fault'); }
    };
    $unavailable = new MetricsSink($broken, 'broken', $events, [], 3, 60, $writer, $clock);
    Check::throws(StorageException::class, static function () use ($unavailable): void { $unavailable->inspect(); });
    $corrupt = new class implements AtomicStore {
        public function transact(string $key, callable $callback) { return $callback(['v' => 1])->result(); }
    };
    $tampered = new MetricsSink($corrupt, 'tampered', $events, [], 3, 60, $writer, $clock);
    Check::throws(StorageException::class, static function () use ($tampered): void { $tampered->inspect(); });
    Check::same(3, count($written));
    Check::same(PHP_SESSION_NONE, session_status());
    Check::same(false, headers_sent());
    echo 'PASS fixed audit metrics: ' . Check::$assertions . ' assertions PHP ' . PHP_VERSION . "\n";
} finally { cleanDirectory($directory); }
