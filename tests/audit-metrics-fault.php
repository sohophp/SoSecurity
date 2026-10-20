<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Audit\AuditLogger;
use SoSecurity\Audit\MetricsSink;
use SoSecurity\Storage\MySqlStore;
use SoSecurity\Storage\RedisStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;

$backend = $argv[1] ?? '';
$variable = $backend === 'redis' ? 'SOSECURITY_TEST_REDIS_SOCKET' : 'SOSECURITY_TEST_MYSQL_SOCKET';
$socket = getenv($variable);
$prefix = $backend === 'redis' ? 'sosecurity-redis.' : 'sosecurity-mysql-';
$name = $backend === 'redis' ? 'redis.sock' : 'mysql.sock';
$marker = $backend === 'redis' ? 'audit-metrics-owner' : 'account-test-owner';
if (!in_array($backend, ['redis', 'mysql'], true) || !is_string($socket)
    || strpos($socket, '/tmp/' . $prefix) !== 0 || basename($socket) !== $name
    || !is_file(dirname($socket) . '/' . $marker) || !file_exists($socket)) {
    throw new RuntimeException('Audit metrics fault tests require a controller-owned private socket.');
}

$clock = new TestClock();
$clock->time = (intdiv(time(), 86400) + 1) * 86400 + 43200;
$namespace = 'audit-metrics-fault-' . bin2hex(random_bytes(8));
$site = 'audit-metrics-fault-' . bin2hex(random_bytes(8));
if ($backend === 'redis') {
    $client = new Redis(); $client->connect($socket, 0, 2.0);
    $store = new RedisStore($client, $namespace, $clock);
    $store->initialize();
} else {
    $pdo = new PDO('mysql:unix_socket=' . $socket . ';dbname=sosecurity_test;charset=utf8mb4',
        'sosecurity_test', 'integration-only', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $store = new MySqlStore($pdo, $namespace, $clock);
}
$written = [];
$metrics = new MetricsSink($store, $site, ['login.failed' => 'authentication'],
    ['authentication' => 1], 2, 86400, static function (array $record) use (&$written): void {
        $written[] = $record;
    }, $clock);
$audit = new AuditLogger($metrics, str_repeat('K', 32));
$audit->record('login.failed', 'tenant', 'actor');
Check::same(1, $metrics->inspect()['total']);
Check::same(1, count($written));
$retained = new MetricsSink($store, $site . '-retained', ['login.failed' => 'authentication'],
    ['authentication' => 1], 2, 86400, static function (array $record): void {}, $clock, 2);
(new AuditLogger($retained, str_repeat('K', 32)))->record('login.failed', 'tenant', 'actor');
$oldWindow = $retained->inspect()['window_start'];
$clock->time += 86400;
Check::same($oldWindow, $retained->inspectRetained()[0]['window_start']);
Check::same(['authentication'], $retained->inspectRetained()[0]['alerts']);
if ($backend === 'redis') {
    $namespaceHash = hash('sha256', $namespace);
    $ready = json_decode($client->get('sosecurity:' . $namespaceHash . ':ready'), true);
    $stateKey = 'sosecurity:' . $namespaceHash . ':' . $ready['epoch'] . ':'
        . hash('sha256', Guard::key('audit-metrics', $site, 'fixed-window'));
    // Build the oversized value inside the private server, not the 8 MiB PHP process.
    $client->eval("return redis.call('SET',KEYS[1],string.rep('x',12582912))", [$stateKey], 1);
} else {
    // The server constructs this value; the 8 MiB PHP worker must never fetch it.
    $pdo->exec("UPDATE sosecurity_state SET payload=REPEAT('x',12582912) WHERE namespace_hash='" . hash('sha256', $namespace) . "'");
}
Check::throws(StorageException::class, static function () use ($metrics): void { $metrics->inspect(); });
Check::throws(StorageException::class, static function () use ($audit): void {
    $audit->record('login.failed', 'tenant', 'actor');
});
Check::same(1, count($written));
if ($backend === 'mysql') { Check::same(false, $pdo->inTransaction()); }
echo 'PASS fixed audit metrics ' . $backend . ' fault refusal: ' . Check::$assertions
    . ' assertions under ' . ini_get('memory_limit') . ' PHP ' . PHP_VERSION . "\n";
