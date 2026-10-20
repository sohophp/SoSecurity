<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Audit\AuditLogger;
use SoSecurity\Audit\RecentEvents;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MySqlStore;
use SoSecurity\Storage\RedisStore;

$backend = $argv[3] ?? 'file';
$clock = new TestClock();
$clock->time = (int) ($argv[5] ?? 100000);
if ($backend === 'redis') {
    $client = new Redis();
    $client->connect($argv[1], 0, 2.0);
    $store = new RedisStore($client, $argv[4], $clock);
} elseif ($backend === 'mysql') {
    $pdo = new PDO('mysql:unix_socket=' . $argv[1] . ';dbname=sosecurity_test;charset=utf8mb4',
        'sosecurity_test', 'integration-only', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $store = new MySqlStore($pdo, $argv[4], $clock, 5);
} elseif ($backend === 'file') {
    $store = new FileStore($argv[1], $argv[4], $clock);
} else { throw new RuntimeException('Unknown private recent-event backend.'); }

if ($argv[2] === 'initialize') {
    if ($backend !== 'redis') { throw new RuntimeException('Redis initialization only.'); }
    $store->initialize();
    exit;
}
$recent = new RecentEvents($store, 'site', str_repeat('S', 32), 3, 3600,
    static function (array $record): void {}, static function (): bool { return true; }, $clock);
if ($argv[2] === 'inspect') {
    echo json_encode($recent->recent(3));
    exit;
}
if ($argv[2] !== 'write' || !isset($argv[6])) { throw new RuntimeException('Invalid recent-event worker action.'); }
try {
    (new AuditLogger($recent, str_repeat('K', 32)))->record('login.failed', 'tenant', $argv[6]);
    echo 'ACCEPTED';
} catch (SecurityException $failure) {
    if ($failure->reason() !== 'audit.recent_capacity') { throw $failure; }
    echo 'REFUSED';
}
