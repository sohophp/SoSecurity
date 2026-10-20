<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Audit\AuditLogger;
use SoSecurity\Audit\RecentEvents;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MySqlStore;
use SoSecurity\Storage\RedisStore;
use SoSecurity\Storage\StorageException;

$backend = $argv[1] ?? 'file';
$directory = privateDirectory();
try {
    $clock = new TestClock();
    if ($backend === 'redis') { $clock->time = (intdiv(time(), 86400) + 1) * 86400 + 43200; }
    if ($backend === 'file') {
        $store = new FileStore($directory, 'audit-recent', $clock);
    } elseif ($backend === 'redis' || $backend === 'mysql') {
        $socket = getenv($backend === 'redis' ? 'SOSECURITY_TEST_REDIS_SOCKET' : 'SOSECURITY_TEST_MYSQL_SOCKET');
        $prefix = $backend === 'redis' ? '/tmp/sosecurity-redis.' : '/tmp/sosecurity-mysql-';
        $marker = $backend === 'redis' ? 'audit-metrics-owner' : 'account-test-owner';
        if (!is_string($socket) || strpos($socket, $prefix) !== 0
            || basename($socket) !== ($backend === 'redis' ? 'redis.sock' : 'mysql.sock')
            || !is_file(dirname($socket) . '/' . $marker) || !file_exists($socket)) {
            throw new RuntimeException('Recent-event tests require a controller-owned private socket.');
        }
        if ($backend === 'redis') {
            $client = new Redis(); $client->connect($socket, 0, 2.0);
            $store = new RedisStore($client, 'audit-recent-' . bin2hex(random_bytes(8)), $clock);
            $store->initialize();
        } else {
            $pdo = new PDO('mysql:unix_socket=' . $socket . ';dbname=sosecurity_test;charset=utf8mb4',
                'sosecurity_test', 'integration-only', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $store = new MySqlStore($pdo, 'audit-recent-' . bin2hex(random_bytes(8)), $clock);
        }
    } else { throw new RuntimeException('Unknown recent-event test backend.'); }
    $written = []; $allowed = false; $checks = 0;
    $index = new RecentEvents($store, 'site', str_repeat('S', 32), 2, 60,
        static function (array $record) use (&$written): void { $written[] = $record; },
        static function () use (&$allowed, &$checks): bool { ++$checks; return $allowed; }, $clock);
    $audit = new AuditLogger($index, str_repeat('K', 32));
    Check::throws(SecurityException::class, static function () use ($index): void { $index->recent(2); });
    Check::same(1, $checks);
    $audit->record('login.failed', 'tenant-one', "private\0actor", ['allowed' => false]);
    ++$clock->time;
    $audit->record('csrf.failed', 'tenant-two', null, ['status' => 403]);
    $allowed = true;
    $events = $index->recent(2);
    Check::same(2, count($events));
    Check::same(['at', 'event', 'scope_binding', 'subject', 'context'], array_keys($events[0]));
    Check::same('csrf.failed', $events[0]['event']);
    Check::same('login.failed', $events[1]['event']);
    Check::same(hash_hmac('sha256', "private\0actor", str_repeat('K', 32)), $events[1]['subject']);
    Check::same(false, strpos(json_encode($events), 'tenant-one') !== false);
    Check::same(false, strpos(json_encode($events), 'private') !== false);
    Check::same(1, count($index->recent(2, 'login.failed', 'tenant-one')));
    Check::same([], $index->recent(2, 'login.failed', 'tenant-two'));
    Check::same(2, count($written));
    Check::throws(SecurityException::class, static function () use ($audit): void {
        $audit->record('login.failed', 'tenant-one', 'overflow');
    });
    Check::same(2, count($written));
    Check::throws(ConfigurationException::class, static function () use ($index): void {
        $index(['time' => 1, 'event' => 'login.failed', 'scope' => 'tenant-one',
            'subject' => null, 'context' => [], 'password' => 'private']);
    });
    Check::same(2, count($written));
    $allowed = false;
    Check::throws(SecurityException::class, static function () use ($index): void { $index->recent(2, 'bad event'); });
    $allowed = true;
    Check::throws(ConfigurationException::class, static function () use ($index): void { $index->recent(2, 'bad event'); });
    $clock->time += 59;
    Check::same(1, count($index->recent(2)));
    $audit->record('login.failed', 'tenant-one', 'new');
    Check::same(2, count($index->recent(2)));
    $clock->time += 61;
    Check::same([], $index->recent(2));
    Check::same(3, count($written));
    $broken = new class implements AtomicStore {
        public function transact(string $key, callable $callback) { throw new StorageException('private backend fault', 'storage.io'); }
    };
    $denied = new RecentEvents($broken, 'site', str_repeat('S', 32), 2, 60,
        static function (array $record): void {}, static function (): bool { return false; }, $clock);
    $granted = new RecentEvents($broken, 'site', str_repeat('S', 32), 2, 60,
        static function (array $record): void {}, static function (): bool { return true; }, $clock);
    Check::throws(SecurityException::class, static function () use ($denied): void { $denied->recent(2); });
    Check::throws(StorageException::class, static function () use ($granted): void { $granted->recent(2); });
    $throwing = new RecentEvents($store, 'site', str_repeat('S', 32), 2, 60,
        static function (array $record): void {}, static function (): bool { throw new RuntimeException('private authorization fault'); }, $clock);
    Check::throws(SecurityException::class, static function () use ($throwing): void { $throwing->recent(2); });
    $corrupt = new class implements AtomicStore {
        public function transact(string $key, callable $callback) { return $callback(['v' => 1, 'policy' => 'wrong', 'entries' => []])->result(); }
    };
    $notWritten = 0;
    $tampered = new RecentEvents($corrupt, 'site', str_repeat('S', 32), 2, 60,
        static function (array $record) use (&$notWritten): void { ++$notWritten; },
        static function (): bool { return true; }, $clock);
    Check::throws(StorageException::class, static function () use ($tampered): void {
        (new AuditLogger($tampered, str_repeat('K', 32)))->record('login.failed', 'tenant-one', 'actor');
    });
    Check::same(0, $notWritten);
    $maxWritten = 0;
    $maxIndex = new RecentEvents($store, 'site-max', str_repeat('M', 32), 64, 86400,
        static function (array $record) use (&$maxWritten): void { ++$maxWritten; },
        static function (): bool { return true; }, $clock);
    $maxAudit = new AuditLogger($maxIndex, str_repeat('P', 32));
    $longEvent = 'a' . str_repeat('b', 63);
    $longScope = 's' . str_repeat('x', 255);
    $maxContext = ['allowed' => false, 'retry_after' => PHP_INT_MAX, 'status' => PHP_INT_MAX];
    for ($number = 0; $number < 64; ++$number) {
        $maxAudit->record($longEvent, $longScope, sprintf('%04d', $number) . str_repeat('z', 1020), $maxContext);
    }
    Check::same(64, count($maxIndex->recent(64, $longEvent, $longScope)));
    Check::same(64, $maxWritten);
    Check::throws(SecurityException::class, static function () use ($maxAudit, $longEvent, $longScope, $maxContext): void {
        $maxAudit->record($longEvent, $longScope, str_repeat('z', 1024), $maxContext);
    });
    Check::same(64, $maxWritten);
    Check::throws(ConfigurationException::class, static function () use ($index): void { serialize($index); });
    Check::same(false, strpos(var_export($index, true), $directory) !== false);
    Check::same(false, strpos(var_export($index, true), str_repeat('S', 32)) !== false);
    echo 'PASS bounded recent audit events: ' . Check::$assertions . ' assertions on '
        . $backend . ' PHP ' . PHP_VERSION . "\n";
} finally { cleanDirectory($directory); }
