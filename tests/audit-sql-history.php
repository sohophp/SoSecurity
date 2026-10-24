<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/audit-sql-support.php';

use SoSecurity\Audit\SqlSink;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;

$mysql = ($argv[1] ?? '') === 'mysql';
$e = new AuditSqlEnvironment($mysql);
try {
    $writer = new SqlSink($e->pdo, 'history-site', 10, 604800, $e->clock);
    $writer->initialize();
    foreach (['first.event', 'second.event', 'third.event'] as $event) { $writer(auditSqlRecord($event)); }
    Check::throws(SecurityException::class, static function () use ($writer): void { $writer->records(); });
    $maintenance = new SqlSink($e->connection(), 'history-site', 10, 604800, $e->clock, 1000, static function (): bool { return true; });
    Check::throws(SecurityException::class, static function () use ($maintenance): void { $maintenance->records(); });
    $reader = new SqlSink($e->connection(), 'history-site', 10, 604800, $e->clock, 1000, null, static function (): bool { return true; });
    Check::throws(SecurityException::class, static function () use ($reader): void { $reader->prune(); });
    Check::same([1, 2], array_column($reader->records(0, 2), 'sequence'));
    $next = $reader->records(2, 2);
    Check::same([3], array_column($next, 'sequence'));
    Check::same('third.event', $next[0]['record']['event']);
    Check::same([], $reader->records(PHP_INT_MAX, 1));
    Check::same(3, $e->count());
    foreach ([[-1,1], [0,0], [0,101]] as $args) {
        Check::throws(ConfigurationException::class, static function () use ($reader,$args): void { $reader->records(...$args); });
    }
    $calls = 0;
    $revoked = new SqlSink($e->connection(), 'history-site', 10, 604800, $e->clock, 1000, null,
        static function () use (&$calls): bool { return ++$calls === 1; });
    Check::throws(SecurityException::class, static function () use ($revoked): void { $revoked->records(); });
    Check::same(2, $calls); Check::same(3, $e->count());
    $other = new SqlSink($e->connection(), 'other-history-site', 10, 604800, $e->clock, 1000, null, static function (): bool { return true; });
    $other->initialize(); Check::same([], $other->records());
    $other(auditSqlRecord('other.site'));
    Check::same('other.site', $other->records()[0]['record']['event']);
    Check::same(3, count($reader->records()));
    $site = hash('sha256', 'SoSecurity.AuditSql.Site.1.history-site');
    $q = $e->pdo->prepare('SELECT record FROM sosecurity_audit_records WHERE site=? AND sequence_no=1');
    $q->execute([$site]); $original = $q->fetchColumn(); $q->closeCursor();
    $corrupt = $e->pdo->prepare('UPDATE sosecurity_audit_records SET record=? WHERE site=? AND sequence_no=1');
    $corrupt->bindValue(1, '{"password":"SYNTHETIC"}', PDO::PARAM_LOB); $corrupt->bindValue(2, $site); $corrupt->execute(); $corrupt->closeCursor();
    Check::throws(StorageException::class, static function () use ($reader): void { $reader->records(); });
    $e->pdo->exec('UPDATE sosecurity_audit_records SET record=' . ($mysql ? "REPEAT('x',8388608)" : 'zeroblob(8388608)') . ' WHERE sequence_no=1');
    Check::throws(StorageException::class, static function () use ($reader): void { $reader->records(); });
    $restore = static function () use ($corrupt,$original,$site): void {
        $corrupt->bindValue(1, $original, PDO::PARAM_LOB); $corrupt->bindValue(2, $site); $corrupt->execute(); $corrupt->closeCursor();
    };
    $restore();
    if (!$mysql) {
        $e->pdo->exec('UPDATE sosecurity_audit_records SET record=CAST(record AS TEXT) WHERE site=' . $e->pdo->quote($site));
        Check::throws(StorageException::class, static function () use ($reader): void { $reader->records(0,1); });
        // Only row1 is read below; restore its exact BLOB type.
        $restore();
    }
    Check::same('first.event', $reader->records(0,1)[0]['record']['event']);
    $e->clock->time += 172800;
    // Persisted history can outlive RecentEvents' 24-hour maximum, but remains within configured retention.
    $fresh = new SqlSink($e->connection(), 'history-site', 10, 604800, $e->clock, 1000, null, static function (): bool { return true; });
    Check::same('first.event', $fresh->records(0,1)[0]['record']['event']);
    $e->clock->time = 704800;
    Check::same([], $fresh->records());
    Check::same(4, $e->count()); // Reads do not silently delete expired records.
    echo 'PASS authorized SQL audit history: ' . Check::$assertions . ' assertions '
        . ($mysql ? 'MySQL' : 'SQLite') . ' PHP ' . PHP_VERSION
        . "; separate permissions, bounded cursor, post-read revocation, 48h persistence and SQL-side oversized BLOB refusal\n";
} finally { $e->close(); }
