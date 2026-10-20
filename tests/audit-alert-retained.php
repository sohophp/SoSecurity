<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/outbox-support.php';

use SoSecurity\Audit\AlertOutboxPublisher;
use SoSecurity\Audit\AuditLogger;
use SoSecurity\Audit\MetricsSink;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MySqlStore;

$mysql = ($argv[1] ?? '') === 'mysql';
$directory = privateDirectory();
try {
    outboxCase($mysql, static function (OutboxEnvironment $e) use ($mysql, $directory): void {
        $store = new FileStore($directory, 'retained-alerts', $e->clock);
        $metrics = new MetricsSink($store, 'retained-site', ['login.failed' => 'authentication'],
            ['authentication' => 1], 8, 60, static function (array $record): void {}, $e->clock, 2);
        $audit = new AuditLogger($metrics, str_repeat('K', 32));
        $queue = $e->service();
        $queue->initialize('tenant', AlertOutboxPublisher::producer(), 'admin');
        $publisher = new AlertOutboxPublisher($metrics, $queue, 'tenant', 'operator');
        $audit->record('login.failed', 'tenant', "private\0actor");
        $first = $metrics->inspect()['window_start'];
        $e->clock->time += 60;
        $audit->record('login.failed', 'tenant', 'another');
        $second = $metrics->inspect()['window_start'];
        $e->clock->time += 60;
        $retained = $metrics->inspectRetained();
        Check::same(3, count($retained));
        Check::same([$first, $second], array_column(array_slice($retained, 0, 2), 'window_start'));
        Check::same([], $retained[2]['alerts']);
        $submit = static function () use ($e, $mysql, $publisher): array {
            $e->pdo->exec($mysql ? 'START TRANSACTION' : 'BEGIN IMMEDIATE');
            try { $result = $publisher->publish(); $e->pdo->exec('COMMIT'); return $result; }
            catch (Throwable $error) { $e->pdo->exec('ROLLBACK'); throw $error; }
        };
        $statuses = $submit();
        Check::same(2, count($statuses));
        Check::same(2, $e->count(true));
        Check::same(array_map(static function ($status): string { return $status->id(); }, $statuses),
            array_map(static function ($status): string { return $status->id(); }, $submit()));
        Check::same(2, $e->count(true));
        $claim = $queue->claim('tenant', AlertOutboxPublisher::producer(), 'worker');
        Check::same($first, json_decode($claim->message()->body(), true)['window_start']);
        Check::same(false, strpos($claim->message()->body(), 'private') !== false);
        Check::same(true, $queue->acknowledge('tenant', AlertOutboxPublisher::producer(), 'worker', $claim->token()));
        $e->clock->time += 60;
        $remaining = $metrics->inspectRetained();
        Check::same([$second], array_column(array_slice($remaining, 0, -1), 'window_start'));
        Check::same(1, count($submit()));
        $legacy = new MetricsSink($store, 'retained-site', ['login.failed' => 'authentication'],
            ['authentication' => 1], 8, 60, static function (array $record): void {}, $e->clock);
        Check::throws(ConfigurationException::class, static function () use ($legacy): void { $legacy->inspect(); });
        Check::throws(ConfigurationException::class, static function () use ($store, $e): void {
            new MetricsSink($store, 'other-site', ['login.failed' => 'authentication'],
                ['authentication' => 1], 8, 60, static function (array $record): void {}, $e->clock, 65);
        });
        if ($mysql) {
            MySqlStore::install($e->observer);
            $sqlMetrics = new MetricsSink(new MySqlStore($e->observer, 'retained-alert-metrics', $e->clock),
                'retained-sql-site', ['login.failed' => 'authentication'], ['authentication' => 1],
                8, 60, static function (array $record): void {}, $e->clock, 2);
            (new AuditLogger($sqlMetrics, str_repeat('K', 32)))->record('login.failed', 'tenant', 'actor');
            $e->pdo->exec('START TRANSACTION');
            $sqlStatuses = (new AlertOutboxPublisher($sqlMetrics, $queue, 'tenant', 'operator'))->publish();
            $e->pdo->exec('COMMIT');
            Check::same(1, count($sqlStatuses));
        }
    });
    $clock = new TestClock();
    $bounded = new MetricsSink(new FileStore($directory, 'retained-bound', $clock), 'bounded-site',
        ['login.failed' => 'authentication'], ['authentication' => 1], 8, 1,
        static function (array $record): void {}, $clock, 2);
    $audit = new AuditLogger($bounded, str_repeat('K', 32));
    for ($i = 0; $i < 70; ++$i) { $audit->record('login.failed', 'tenant', 'actor'); ++$clock->time; }
    Check::same(3, count($bounded->inspectRetained()));
    Check::same([100068, 100069], array_column(array_slice($bounded->inspectRetained(), 0, 2), 'window_start'));
    $oldStore = new FileStore($directory, 'retained-migration', $clock);
    $legacy = new MetricsSink($oldStore, 'migration-site', ['login.failed' => 'authentication'],
        ['authentication' => 1], 8, 1, static function (array $record): void {}, $clock);
    (new AuditLogger($legacy, str_repeat('K', 32)))->record('login.failed', 'tenant', 'actor');
    $upgraded = new MetricsSink($oldStore, 'migration-site', ['login.failed' => 'authentication'],
        ['authentication' => 1], 8, 1, static function (array $record): void {}, $clock, 2);
    Check::throws(ConfigurationException::class, static function () use ($upgraded): void { $upgraded->inspectRetained(); });
    ++$clock->time;
    Check::same(1, count($upgraded->inspectRetained()));
    echo 'PASS retained audit alerts: ' . Check::$assertions . ' assertions on '
        . ($mysql ? 'MySQL' : 'SQLite') . ' PHP ' . PHP_VERSION . "\n";
} finally { cleanDirectory($directory); }
