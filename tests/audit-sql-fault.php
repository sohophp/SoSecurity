<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/audit-sql-support.php';

use SoSecurity\Audit\SqlSink;
use SoSecurity\Storage\StorageException;

final class AuditSqlFaultConnection extends PDO
{
    public $phase;
    public $inserts = 0;
    public function exec($statement): int
    {
        if (strtoupper(trim($statement)) === 'COMMIT' && $this->phase === 'before_commit') {
            throw new RuntimeException('SYNTHETIC-COMMIT-BEFORE');
        }
        $result = parent::exec($statement);
        if ($result === false) { throw new RuntimeException('Test statement unavailable.'); }
        if (strtoupper(trim($statement)) === 'COMMIT' && $this->phase === 'after_commit') {
            throw new RuntimeException('SYNTHETIC-COMMIT-AFTER');
        }
        return $result;
    }
    public function commit(): bool
    {
        if ($this->phase === 'before_commit') { throw new RuntimeException('SYNTHETIC-COMMIT-BEFORE'); }
        $result = parent::commit();
        if ($this->phase === 'after_commit') { throw new RuntimeException('SYNTHETIC-COMMIT-AFTER'); }
        return $result;
    }
}
final class AuditSqlFaultStatement extends PDOStatement
{
    private $connection;
    protected function __construct(AuditSqlFaultConnection $connection) { $this->connection = $connection; }
    public function execute($params = null): bool
    {
        $result = $params === null ? parent::execute() : parent::execute($params);
        if (strpos($this->queryString, 'INSERT INTO ') === 0 && strpos($this->queryString, 'sosecurity_audit_records') !== false) {
            ++$this->connection->inserts;
            if ($this->connection->phase === 'after_insert') { throw new RuntimeException('SYNTHETIC-INSERT-AFTER'); }
        }
        return $result;
    }
}

$mysql = ($argv[1] ?? '') === 'mysql';
foreach (['after_insert', 'before_commit', 'after_commit'] as $phase) {
    $e = new AuditSqlEnvironment($mysql);
    try {
        $dsn = $mysql ? 'mysql:unix_socket=' . getenv('SOSECURITY_TEST_MYSQL_SOCKET') . ';dbname=sosecurity_test;charset=utf8mb4'
            : 'sqlite:' . $e->directory . '/audit.sqlite';
        $pdo = new AuditSqlFaultConnection($dsn, $mysql ? 'sosecurity_test' : null, $mysql ? 'integration-only' : null,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]);
        $pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS, [AuditSqlFaultStatement::class, [$pdo]]);
        $sink = new SqlSink($pdo, 'fault-site', 3, 60, $e->clock);
        $sink->initialize(); $pdo->phase = $phase;
        Check::throws(StorageException::class, static function () use ($sink): void { $sink(auditSqlRecord()); });
        Check::same(1, $pdo->inserts);
        Check::same($phase === 'after_commit' ? 1 : 0, $e->count());
        Check::same($phase === 'after_commit' ? 1 : 0,
            (int)$e->pdo->query('SELECT next_sequence FROM sosecurity_audit_roots')->fetchColumn());
        if ($phase !== 'after_insert') {
            $pdo->phase = null;
            Check::throws(StorageException::class, static function () use ($sink): void { $sink(auditSqlRecord()); });
            Check::same(1, $pdo->inserts);
        }
        $pdo = null; $sink = null;
    } finally { $e->close(); }
}
echo 'PASS SQL audit transaction faults: ' . Check::$assertions . ' assertions '
    . ($mysql ? 'MySQL' : 'SQLite') . ' PHP ' . PHP_VERSION . "; insert rollback, before/after commit uncertainty and no implicit retry\n";
