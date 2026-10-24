<?php
declare(strict_types=1);

final class AuditSqlEnvironment
{
    public $directory;
    public $pdo;
    public $clock;
    private $dsn;
    private $mysql;

    public function __construct(bool $mysql)
    {
        $this->directory = privateDirectory();
        $this->mysql = $mysql;
        if ($mysql) {
            $socket = getenv('SOSECURITY_TEST_MYSQL_SOCKET');
            if (!is_string($socket) || !preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql.sock\z~D', $socket)
                || !is_file(dirname($socket) . '/account-test-owner')) {
                throw new RuntimeException('Use the owned no-TCP MySQL test controller.');
            }
            $this->dsn = 'mysql:unix_socket=' . $socket . ';dbname=sosecurity_test;charset=utf8mb4';
        } else { $this->dsn = 'sqlite:' . $this->directory . '/audit.sqlite'; }
        $this->pdo = $this->connection();
        $this->pdo->exec('DROP TABLE IF EXISTS sosecurity_audit_records');
        $this->pdo->exec('DROP TABLE IF EXISTS sosecurity_audit_roots');
        $this->pdo->exec(file_get_contents(dirname(__DIR__) . '/resources/sql/audit-' . ($mysql ? 'mysql' : 'sqlite') . '.sql'));
        if (!$mysql) { chmod($this->directory . '/audit.sqlite', 0600); }
        $this->clock = new TestClock();
    }

    public function connection(): PDO
    {
        $pdo = new PDO($this->dsn, $this->mysql ? 'sosecurity_test' : null,
            $this->mysql ? 'integration-only' : null,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]);
        if (!$this->mysql) { $pdo->exec('PRAGMA busy_timeout=2000'); $pdo->exec('PRAGMA synchronous=FULL'); }
        return $pdo;
    }

    public function count(): int { return (int)$this->pdo->query('SELECT COUNT(*) FROM sosecurity_audit_records')->fetchColumn(); }
    public function close(): void { $this->pdo = null; cleanDirectory($this->directory); }
}

function auditSqlRecord(string $event = 'login.failed'): array
{
    return ['time' => 100000, 'event' => $event, 'scope' => 'tenant', 'subject' => null,
        'context' => ['allowed' => false, 'status' => 401]];
}
