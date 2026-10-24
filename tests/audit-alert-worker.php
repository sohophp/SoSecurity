<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/outbox-support.php';

use SoSecurity\Audit\AlertOutboxPublisher;
use SoSecurity\Audit\AlertOutboxWorker;
use SoSecurity\Audit\AuditLogger;
use SoSecurity\Audit\MetricsSink;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Outbox\Message;
use SoSecurity\Outbox\Policy;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;

$mysql = ($argv[1] ?? '') === 'mysql';
$directory = privateDirectory();
try {
    foreach (['success', 'retry', 'exception', 'invalid', 'unknown_ack'] as $case) {
        outboxCase($mysql, static function (OutboxEnvironment $e) use ($mysql, $directory, $case): void {
            $metrics = new MetricsSink(new FileStore($directory, 'alert-worker-' . $case, $e->clock),
                'worker-site-' . $case, ['login.failed' => 'authentication'],
                ['authentication' => 1], 8, 60, static function (array $record): void {}, $e->clock);
            $queue = $e->service();
            $queue->initialize('tenant', AlertOutboxPublisher::producer(), 'admin');
            if ($case === 'invalid') {
                $bad = new Message('tenant', AlertOutboxPublisher::producer(),
                    Message::identifier('bad-alert', $e->clock->time), 'security-alert',
                    'audit.unknown', 'authentication:' . $e->clock->time, '{}');
                $e->append($queue, $bad);
                $called = 0;
                $worker = new AlertOutboxWorker($metrics, $queue, 'tenant', 'worker',
                    static function () use (&$called): bool { ++$called; return true; });
                outboxRefused('audit.alert_message', static function () use ($worker): void { $worker->runOne(); });
                Check::same(0, $called);
                Check::same('dead', $queue->status('tenant', AlertOutboxPublisher::producer(), $bad->id(), 'operator')->state());
                return;
            }
            (new AuditLogger($metrics, str_repeat('K', 32)))->record('login.failed', 'tenant', "actor\0private");
            $publisher = new AlertOutboxPublisher($metrics, $queue, 'tenant', 'operator');
            $e->pdo->exec($mysql ? 'START TRANSACTION' : 'BEGIN IMMEDIATE');
            $id = $publisher->publish()[0]->id();
            $e->pdo->exec('COMMIT');
            $ids = [];
            $attempts = 0;
            $worker = new AlertOutboxWorker($metrics, $queue, 'tenant', 'worker',
                static function (string $deliveryId, array $alert) use (&$ids, &$attempts, $e, $case): bool {
                    $ids[] = $deliveryId; ++$attempts;
                    Check::same('authentication', $alert['class']);
                    Check::same(false, isset($alert['subject']));
                    if ($case === 'exception' && $attempts === 1) { throw new RuntimeException('PRIVATE-TRANSPORT-CREDENTIAL'); }
                    if ($case === 'retry' && $attempts === 1) { return false; }
                    if ($case === 'unknown_ack' && $attempts === 1) { $e->clock->time += 2; }
                    return true;
                });
            if ($case === 'retry' || $case === 'exception') {
                try { $worker->runOne(); throw new LogicException('Expected transport refusal'); }
                catch (DependencyException $error) {
                    Check::same('audit.alert_delivery', $error->reason());
                    Check::same(null, $error->getPrevious());
                    Check::same(false, strpos((string)$error, 'PRIVATE-TRANSPORT-CREDENTIAL') !== false);
                }
                $pending = $queue->status('tenant', AlertOutboxPublisher::producer(), $id, 'operator');
                Check::same('pending', $pending->state());
                $e->clock->time = $pending->availableAt();
            } elseif ($case === 'unknown_ack') {
                outboxRefused('audit.alert_ack_unknown', static function () use ($worker): void { $worker->runOne(); });
                Check::same('leased', $queue->status('tenant', AlertOutboxPublisher::producer(), $id, 'operator')->state());
            }
            Check::same(true, $worker->runOne());
            Check::same(false, $worker->runOne());
            Check::same('sent', $queue->status('tenant', AlertOutboxPublisher::producer(), $id, 'operator')->state());
            Check::same($case === 'success' ? 1 : 2, $attempts);
            Check::same(1, count(array_unique($ids)));
            Check::throws(ConfigurationException::class, static function () use ($worker): void { serialize($worker); });
            Check::same(false, strpos(var_export($worker, true), $directory) !== false);
        }, $case === 'unknown_ack' ? new Policy(['lease_seconds' => 1]) : null);
    }
    echo 'PASS audit alert Outbox worker: ' . Check::$assertions . ' assertions on '
        . ($mysql ? 'MySQL' : 'SQLite') . ' PHP ' . PHP_VERSION . "\n";
} finally { cleanDirectory($directory); }
