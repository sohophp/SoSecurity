<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/audit-sql-support.php';
require __DIR__ . '/outbox-support.php';

use SoSecurity\Audit\AlertOutboxPublisher;
use SoSecurity\Audit\AlertOutboxWorker;
use SoSecurity\Audit\AuditLogger;
use SoSecurity\Audit\BudgetedSink;
use SoSecurity\Audit\Diagnostics;
use SoSecurity\Audit\MetricsSink;
use SoSecurity\Audit\SqlSink;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Outbox\Policy;
use SoSecurity\Storage\FileStore;

$mysql = ($argv[1] ?? '') === 'mysql';
$audit = new AuditSqlEnvironment($mysql);
try {
    outboxCase($mysql, static function (OutboxEnvironment $e) use ($audit): void {
        $sql = new SqlSink($audit->pdo, 'pipeline-site', 2, 3600, $e->clock);
        $sql->initialize();
        $store = new FileStore($audit->directory, 'pipeline-metrics', $e->clock);
        $metrics = new MetricsSink($store, 'pipeline-site', ['login.failed' => 'authentication'],
            ['authentication' => 1], 10, 60, $sql, $e->clock, 2);
        $budget = new BudgetedSink(new FileStore($audit->directory, 'pipeline-budget', $e->clock),
            'pipeline-site', 10, 60, $metrics, $e->clock);
        $logger = new AuditLogger($budget, str_repeat('P', 32));
        $logger->record('login.failed', 'tenant', 'actor-one');
        $logger->record('login.failed', 'tenant', 'actor-two');
        Check::same(2, $audit->count());
        Check::same(8, $budget->inspect()->remaining());
        $queue = $e->service(); $queue->initialize('tenant', AlertOutboxPublisher::producer(), 'admin');
        $publisher = new AlertOutboxPublisher($metrics, $queue, 'tenant', 'operator');
        $publish = static function () use ($e, $publisher): array {
            $e->pdo->exec($e->mysql ? 'START TRANSACTION' : 'BEGIN IMMEDIATE');
            try { $result = $publisher->publish(); $e->pdo->exec('COMMIT'); return $result; }
            catch (Throwable $error) { $e->pdo->exec('ROLLBACK'); throw $error; }
        };
        $first = $publish(); $second = $publish();
        Check::same(1, count($first)); Check::same($first[0]->id(), $second[0]->id());

        // Real local recipient storage. A confirmed receipt is committed independently of the sender ACK.
        $receiver = new PDO('sqlite:' . $audit->directory . '/receipts.sqlite', null, null,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $receiver->exec('PRAGMA synchronous=FULL');
        $receiver->exec('CREATE TABLE receipts (id TEXT NOT NULL PRIMARY KEY,body TEXT NOT NULL)');
        $calls = 0; $ids = [];
        $worker = new AlertOutboxWorker($metrics, $queue, 'tenant', 'worker',
            static function (string $id, array $alert) use ($receiver, &$calls, &$ids, $e): bool {
                ++$calls; $ids[] = $id; $body = json_encode($alert);
                $receiver->exec('BEGIN IMMEDIATE');
                try {
                    $q = $receiver->prepare('SELECT body FROM receipts WHERE id=?'); $q->execute([$id]);
                    $old = $q->fetchColumn(); $q->closeCursor();
                    if ($old === false) { $receiver->prepare('INSERT INTO receipts VALUES (?,?)')->execute([$id, $body]); }
                    elseif ($old !== $body) { throw new RuntimeException('Synthetic receiver rejected an identity/body mismatch.'); }
                    $receiver->exec('COMMIT');
                } catch (Throwable $error) { $receiver->exec('ROLLBACK'); throw $error; }
                if ($calls === 1) { $e->clock->time += 2; }
                return true;
            });
        outboxRefused('audit.alert_ack_unknown', static function () use ($worker): void { $worker->runOne(); });
        Check::same(1, (int)$receiver->query('SELECT COUNT(*) FROM receipts')->fetchColumn());
        Check::same(true, $worker->runOne()); Check::same(false, $worker->runOne());
        Check::same(2, $calls); Check::same(1, count(array_unique($ids)));
        Check::same(1, (int)$receiver->query('SELECT COUNT(*) FROM receipts')->fetchColumn());
        Check::same('sent', $queue->status('tenant', AlertOutboxPublisher::producer(), $first[0]->id(), 'operator')->state());
        Check::same(2, $audit->count());

        // Metrics/budget record attempts, not durable SQL rows or recipient receipts.
        Check::throws(SecurityException::class, static function () use ($logger): void {
            $logger->record('login.failed', 'tenant', 'actor-three');
        });
        Check::same(3, $metrics->inspect()['total']); Check::same(7, $budget->inspect()->remaining());
        Check::same(2, $audit->count());
        $denied = new Diagnostics($metrics, $budget, static function (): bool { return false; });
        Check::throws(SecurityException::class, static function () use ($denied): void { $denied->inspect(); });
        $view = (new Diagnostics($metrics, $budget, static function (): bool { return true; }))->inspect();
        Check::same(3, $view['total']); Check::same(false, isset($view['subject']));
    }, new Policy(['lease_seconds' => 1]));
    echo 'PASS persistent SQL audit alert pipeline: ' . Check::$assertions . ' assertions '
        . ($mysql ? 'MySQL' : 'SQLite') . ' PHP ' . PHP_VERSION
        . "; real SQL log, stable publication, durable local recipient dedupe, uncertain ACK redelivery and diagnostics boundary\n";
} finally { $audit->close(); }
