<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/outbox-support.php';

use SoSecurity\Audit\AlertOutboxPublisher;
use SoSecurity\Audit\AuditLogger;
use SoSecurity\Audit\MetricsSink;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\StorageException;

$mysql = ($argv[1] ?? '') === 'mysql';
$directory = privateDirectory();
try {
    outboxCase($mysql, static function (OutboxEnvironment $e) use ($mysql, $directory): void {
        $store = new FileStore($directory, 'audit-alert-metrics', $e->clock);
        $records = [];
        $writer = static function (array $record) use (&$records): void { $records[] = $record; };
        $metrics = new MetricsSink($store, 'site', ['login.failed' => 'authentication'],
            ['authentication' => 1], 8, 60, $writer, $e->clock);
        $queue = $e->service();
        $queue->initialize('tenant', AlertOutboxPublisher::producer(), 'admin');
        $publisher = new AlertOutboxPublisher($metrics, $queue, 'tenant', 'operator');
        $second = new AlertOutboxPublisher(new MetricsSink(
            new FileStore($directory, 'audit-alert-metrics', $e->clock), 'site',
            ['login.failed' => 'authentication'], ['authentication' => 1], 8, 60,
            $writer, $e->clock), $queue, 'tenant', 'operator');
        $audit = new AuditLogger($metrics, str_repeat('K', 32));
        Check::same([], $publisher->publish());
        Check::same(0, $e->count(true));
        $audit->record('login.failed', 'tenant', "private\0actor");
        $submit = static function (AlertOutboxPublisher $source) use ($e, $mysql): array {
            $e->pdo->exec($mysql ? 'START TRANSACTION' : 'BEGIN IMMEDIATE');
            try { $result = $source->publish(); $e->pdo->exec('COMMIT'); return $result; }
            catch (Throwable $error) { $e->pdo->exec('ROLLBACK'); throw $error; }
        };
        $first = $submit($publisher);
        Check::same(1, count($first));
        Check::same(1, $e->count(true));
        Check::same($first[0]->id(), $submit($second)[0]->id());
        Check::same(1, $e->count(true));
        $claim = $queue->claim('tenant', AlertOutboxPublisher::producer(), 'worker');
        Check::same($first[0]->id(), $claim->message()->id());
        Check::same('security-alert', $claim->message()->destination());
        Check::same('audit.threshold', $claim->message()->topic());
        $body = json_decode($claim->message()->body(), true);
        Check::same(['v' => 1, 'site_binding' => $metrics->siteBinding(),
            'class' => 'authentication', 'window_start' => $metrics->inspect()['window_start'],
            'expires_at' => $metrics->inspect()['expires_at']], $body);
        Check::same(false, strpos($claim->message()->body(), 'private') !== false);
        Check::same(true, $queue->acknowledge('tenant', AlertOutboxPublisher::producer(), 'worker', $claim->token()));
        Check::same('sent', $submit($publisher)[0]->state());
        Check::same(1, $e->count(true));
        $audit->record('login.failed', 'tenant', 'another-actor');
        Check::same($first[0]->id(), $submit($publisher)[0]->id());
        Check::same(1, $e->count(true));
        $e->clock->time += 60;
        $audit->record('login.failed', 'tenant', 'third-actor');
        Check::same(1, count($submit($publisher)));
        Check::same(2, $e->count(true));
        Check::throws(ConfigurationException::class, static function () use ($publisher): void { serialize($publisher); });
        $name = AlertOutboxPublisher::class;
        $serialized = 'O:' . strlen($name) . ':"' . $name . '":0:{}';
        Check::throws(ConfigurationException::class, static function () use ($serialized): void { unserialize($serialized); });
        Check::throws(ConfigurationException::class, static function () use ($publisher): void { $publisher->unexpected = true; });
        Check::same(false, strpos(var_export($publisher, true), $directory) !== false);
        Check::same(3, count($records));
    });
    outboxCase($mysql, static function (OutboxEnvironment $e) use ($mysql, $directory): void {
        $metrics = new MetricsSink(new FileStore($directory, 'audit-alert-retry', $e->clock),
            'retry-site', ['login.failed' => 'authentication'], ['authentication' => 1],
            2, 60, static function (): void {}, $e->clock);
        (new AuditLogger($metrics, str_repeat('K', 32)))->record('login.failed', 'tenant', 'actor');
        $queue = $e->service();
        $publisher = new AlertOutboxPublisher($metrics, $queue, 'tenant', 'operator');
        $e->pdo->exec($mysql ? 'START TRANSACTION' : 'BEGIN IMMEDIATE');
        Check::throws(SecurityException::class, static function () use ($publisher): void { $publisher->publish(); });
        $e->pdo->exec('ROLLBACK');
        Check::same(0, $e->count(true));
        $queue->initialize('tenant', AlertOutboxPublisher::producer(), 'admin');
        $broken = new class implements AtomicStore {
            public function transact(string $key, callable $callback)
            { throw new StorageException('Private test metrics backend unavailable.'); }
        };
        $unavailable = new MetricsSink($broken, 'unavailable-site',
            ['login.failed' => 'authentication'], ['authentication' => 1], 2, 60,
            static function (): void {}, $e->clock);
        $noMetric = new AlertOutboxPublisher($unavailable, $queue, 'tenant', 'operator');
        Check::throws(StorageException::class, static function () use ($noMetric): void { $noMetric->publish(); });
        Check::same(0, $e->count(true));
        $e->pdo->exec($mysql ? 'START TRANSACTION' : 'BEGIN IMMEDIATE');
        Check::same(1, count($publisher->publish()));
        $e->pdo->exec('ROLLBACK');
        Check::same(0, $e->count(true));
        $e->pdo->exec($mysql ? 'START TRANSACTION' : 'BEGIN IMMEDIATE');
        Check::same(1, count($publisher->publish()));
        $e->pdo->exec('COMMIT');
        Check::same(1, $e->count(true));
    });
    echo 'PASS audit alert Outbox publisher: ' . Check::$assertions . ' assertions on '
        . ($mysql ? 'MySQL' : 'SQLite') . ' PHP ' . PHP_VERSION . "\n";
} finally { cleanDirectory($directory); }
