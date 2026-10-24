<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/audit-sql-support.php';

use SoSecurity\Audit\AuditLogger;
use SoSecurity\Audit\SqlSink;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;

$mysql = ($argv[1] ?? '') === 'mysql';
$e = new AuditSqlEnvironment($mysql);
try {
    $sink = new SqlSink($e->pdo, 'audit-site', 3, 60, $e->clock);
    Check::throws(StorageException::class, static function () use ($sink): void { $sink(auditSqlRecord()); });
    Check::same(0, $e->count());
    $sink->initialize(); $sink->initialize();
    $before = $e->pdo->query('SELECT * FROM sosecurity_audit_roots')->fetchAll(PDO::FETCH_ASSOC);
    foreach (['extra', 'scope', 'context', 'subject', 'encoding'] as $case) {
        $bad = auditSqlRecord();
        if ($case === 'extra') { $bad['password'] = 'SYNTHETIC-NOT-A-REAL-SECRET'; }
        if ($case === 'scope') { $bad['scope'] = "tenant\0other"; }
        if ($case === 'context') { $bad['context']['raw'] = 'SYNTHETIC-NOT-A-REAL-SECRET'; }
        if ($case === 'subject') { $bad['subject'] = 'raw-subject'; }
        if ($case === 'encoding') { $bad['scope'] = "\xff"; }
        Check::throws(ConfigurationException::class, static function () use ($sink, $bad): void { $sink($bad); });
    }
    Check::same($before, $e->pdo->query('SELECT * FROM sosecurity_audit_roots')->fetchAll(PDO::FETCH_ASSOC));
    Check::same(0, $e->count());
    (new AuditLogger($sink, str_repeat('K', 32)))->record('login.failed', 'tenant', 'SYNTHETIC-USER');
    $reopened = new SqlSink($e->connection(), 'audit-site', 3, 60, $e->clock);
    $reopened(auditSqlRecord('permission.denied'));
    Check::same(2, $e->count());
    $body = $e->pdo->query('SELECT record FROM sosecurity_audit_records ORDER BY sequence_no')->fetchAll(PDO::FETCH_COLUMN);
    Check::same(false, strpos(implode('', $body), 'SYNTHETIC-USER') !== false);
    Check::same(hash_hmac('sha256', 'SYNTHETIC-USER', str_repeat('K', 32)), json_decode($body[0], true)['subject']);
    $sink(auditSqlRecord());
    Check::throws(SecurityException::class, static function () use ($sink): void { $sink(auditSqlRecord()); });
    Check::same(3, $e->count());
    $sequence = $e->pdo->query('SELECT next_sequence FROM sosecurity_audit_roots')->fetchColumn();
    Check::throws(StorageException::class, static function () use ($e): void {
        (new SqlSink($e->connection(), 'audit-site', 4, 60, $e->clock))->initialize();
    });
    Check::same($sequence, $e->pdo->query('SELECT next_sequence FROM sosecurity_audit_roots')->fetchColumn());
    $e->clock->time += 60;
    Check::throws(SecurityException::class, static function () use ($sink): void { $sink->prune(); });
    Check::same(3, $e->count());
    $allow = true; $calls = 0;
    $operator = new SqlSink($e->connection(), 'audit-site', 3, 60, $e->clock, 1000,
        static function () use (&$allow, &$calls): bool { ++$calls; return $allow && $calls === 1; });
    Check::throws(SecurityException::class, static function () use ($operator): void { $operator->prune(1); });
    Check::same(3, $e->count());
    $operator = new SqlSink($e->connection(), 'audit-site', 3, 60, $e->clock, 1000, static function (): bool { return true; });
    Check::same(1, $operator->prune(1));
    Check::same(2, $e->count());
    $sink(auditSqlRecord('log.after_retention'));
    Check::same(1, $e->count());
    Check::same(4, (int)$e->pdo->query('SELECT sequence_no FROM sosecurity_audit_records')->fetchColumn());
    Check::same(100060, (int)$e->pdo->query('SELECT recorded_at FROM sosecurity_audit_records')->fetchColumn());

    // A business rollback cannot revoke an independently committed audit attempt.
    $business = new PDO('sqlite:' . $e->directory . '/business.sqlite', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $business->exec('CREATE TABLE business (v INTEGER NOT NULL)'); $business->beginTransaction();
    $business->exec('INSERT INTO business VALUES (1)'); $sink(auditSqlRecord('business.attempt')); $business->rollBack();
    Check::same(0, (int)$business->query('SELECT COUNT(*) FROM business')->fetchColumn());
    Check::same(2, $e->count());

    // Enlisting a logger into its caller's transaction is explicitly refused; the caller still owns it.
    $e->pdo->beginTransaction();
    Check::throws(ConfigurationException::class, static function () use ($sink): void { $sink(auditSqlRecord()); });
    Check::same(true, $e->pdo->inTransaction()); $e->pdo->rollBack();
    Check::same(2, $e->count());
    $e->clock->time -= 1;
    Check::throws(StorageException::class, static function () use ($reopened): void { $reopened(auditSqlRecord()); });
    $e->clock->time += 1;
    Check::same(2, $e->count());
    Check::throws(ConfigurationException::class, static function () use ($sink): void { serialize($sink); });
    Check::throws(ConfigurationException::class, static function () use ($sink): void { $copy = clone $sink; });
    Check::same(false, strpos(var_export($sink, true), 'SYNTHETIC-USER') !== false);
    Check::same(false, strpos(var_export($sink, true), $e->directory) !== false);
    foreach ([0, 100001] as $limit) {
        Check::throws(ConfigurationException::class, static function () use ($e, $limit): void { new SqlSink($e->pdo, 'invalid', $limit); });
    }
    if (!$mysql) {
        $memory = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        Check::throws(ConfigurationException::class, static function () use ($memory): void { (new SqlSink($memory, 'memory'))->initialize(); });
        $e->pdo->exec('PRAGMA synchronous=OFF');
        Check::throws(ConfigurationException::class, static function () use ($sink): void { $sink(auditSqlRecord()); });
        $e->pdo->exec('PRAGMA synchronous=FULL');
        Check::same(2, $e->count());
    }
    echo 'PASS independent SQL audit sink: ' . Check::$assertions . ' assertions '
        . ($mysql ? 'MySQL' : 'SQLite') . ' PHP ' . PHP_VERSION . "; durable commit, strict bounded records, retention, capacity and maintenance rollback\n";
} finally { $e->close(); }
