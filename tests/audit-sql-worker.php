<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Audit\SqlSink;
use SoSecurity\Exception\SecurityException;

$directory = $argv[1] ?? '';
$action = $argv[2] ?? '';
$backend = $argv[3] ?? 'sqlite';
if (!preg_match('~\A/tmp/sosecurity-audit-sql-[a-zA-Z0-9_-]+\z~D', $directory)
    || !is_file($directory . '/owner') || !in_array($action, ['initialize', 'write', 'inspect'], true)) {
    throw new RuntimeException('Use a controller-owned audit test directory.');
}
if ($backend === 'mysql') {
    $socket = getenv('SOSECURITY_TEST_MYSQL_SOCKET');
    if (!is_string($socket) || !preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql.sock\z~D', $socket)
        || !is_file(dirname($socket) . '/account-test-owner')) { throw new RuntimeException('Use the owned test socket.'); }
    $pdo = new PDO('mysql:unix_socket=' . $socket . ';dbname=sosecurity_test;charset=utf8mb4', 'sosecurity_test', 'integration-only',
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]);
} elseif ($backend === 'sqlite') {
    $pdo = new PDO('sqlite:' . $directory . '/log.sqlite', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo->exec('PRAGMA busy_timeout=5000'); $pdo->exec('PRAGMA synchronous=FULL');
} else { throw new RuntimeException('Unknown audit backend.'); }
$sink = new SqlSink($pdo, 'process-site', 7, 3600, new TestClock(), 10000);
if ($action === 'initialize') {
    $pdo->exec('DROP TABLE IF EXISTS sosecurity_audit_records'); $pdo->exec('DROP TABLE IF EXISTS sosecurity_audit_roots');
    $pdo->exec(file_get_contents(dirname(__DIR__) . '/resources/sql/audit-' . $backend . '.sql'));
    $sink->initialize(); echo "READY\n"; exit;
}
if ($action === 'inspect') {
    echo json_encode($pdo->query('SELECT sequence_no,record FROM sosecurity_audit_records ORDER BY sequence_no')->fetchAll(PDO::FETCH_ASSOC));
    exit;
}
try {
    (new SoSecurity\Audit\AuditLogger($sink, str_repeat('P', 32)))->record('worker.accepted', 'tenant', $argv[4] ?? 'worker');
    echo "ACCEPTED\n";
} catch (SecurityException $error) {
    if ($error->reason() !== 'audit.sql_capacity') { throw $error; }
    echo "FULL\n";
}
