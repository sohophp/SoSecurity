<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Audit\AuditLogger;
use SoSecurity\Audit\MetricsSink;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MySqlStore;
use SoSecurity\Storage\RedisStore;

$backend = $argv[3] ?? 'file';
$site = $argv[4] ?? 'site';
$clock = new TestClock();
if (isset($argv[5])) { $clock->time = (int) $argv[5]; }
if ($backend === 'redis') {
    $redis = new Redis();
    $redis->connect($argv[1], 0, 2.0);
    $store = new RedisStore($redis, 'audit-metrics-process', $clock);
} elseif ($backend === 'mysql') {
    $pdo = new PDO('mysql:unix_socket=' . $argv[1] . ';dbname=sosecurity_test;charset=utf8mb4',
        'sosecurity_test', 'integration-only', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $store = new MySqlStore($pdo, 'audit-metrics-process', $clock, 5);
} else {
    $store = new FileStore($argv[1], 'audit-metrics-process', $clock);
}
$metrics = new MetricsSink($store, $site,
    ['login.failed' => 'authentication'], ['authentication' => 40], 80, 86400,
    static function (array $record): void {}, $clock);
if (($argv[2] ?? '') === 'initialize') {
    if ($backend !== 'redis') { throw new RuntimeException('Redis initialization only'); }
    $store->initialize();
} elseif (($argv[2] ?? '') === 'inspect') {
    echo json_encode($metrics->inspect());
} elseif (($argv[2] ?? '') === 'reject') {
    try {
        (new AuditLogger($metrics, str_repeat('K', 32)))->record('login.failed', 'tenant', 'actor');
        throw new RuntimeException('Capacity exhaustion was accepted');
    } catch (SoSecurity\Exception\SecurityException $e) {
        if ($e->reason() !== 'audit.metrics_capacity') { throw $e; }
        echo 'capacity-denied';
    }
} else {
    $audit = new AuditLogger($metrics, str_repeat('K', 32));
    for ($index = 0; $index < 10; ++$index) { $audit->record('login.failed', 'tenant', 'actor'); }
}
