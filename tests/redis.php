<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Storage\RedisStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Storage\Change;

$socket = getenv('SOSECURITY_TEST_REDIS_SOCKET');
if (!$socket) { echo "NOT RUN Redis integration: isolated socket required\n"; exit(0); }
$redis = new Redis(); $redis->connect($socket, 0, 2.0);
$namespace = 'test-' . bin2hex(random_bytes(8));
$store = new RedisStore($redis, $namespace); $other = new RedisStore($redis, $namespace . '-other');
Check::same(null, $store->transact('key', function ($value) { return new Change(['n' => 1], time() + 2, $value); }));
Check::same(['n' => 1], $store->transact('key', function ($value) { return new Change($value, time() + 2, $value); }));
Check::same(null, $other->transact('key', function ($value) { return new Change(null, 0, $value); }));
Check::throws(RuntimeException::class, function () use ($store) {
    $store->transact('key', function () { throw new RuntimeException('callback'); });
});
// A later transaction must work after a callback exception.
Check::same(['n' => 1], $store->transact('key', function ($value) { return new Change($value, time() + 2, $value); }));
$key = 'sosecurity:' . hash('sha256', $namespace) . ':' . hash('sha256', 'key');
Check::same(true, $redis->ttl($key) > 0);
$store->transact('key', function ($value) { return new Change($value, 0, null); });
Check::same(-1, $redis->ttl($key));
$redis->set($key, '{broken');
Check::throws(StorageException::class, function () use ($store) { $store->transact('key', function () { return new Change(null, 0, true); }); });
$redis->del($key);
$redis->lPush($key, 'wrong-type');
Check::throws(StorageException::class, function () use ($store) { $store->transact('key', function () { return new Change(null, 0, true); }); });
$redis->del($key);
// Expired payload is rejected even if the Redis key itself has not expired.
$redis->set($key, '{"expires":1,"value":{"n":1}}');
Check::same(null, $store->transact('key', function ($value) { return new Change(null, 0, $value); }));
$conflict = new Redis(); $conflict->connect($socket, 0, 2.0);
$attempts = 0;
Check::same('ok', $store->transact('key', function ($value) use (&$attempts, $conflict, $key) {
    if (++$attempts === 1) { $conflict->set($key, '{"expires":0,"value":{"n":2}}'); }
    return new Change(['n' => ($value['n'] ?? 0) + 1], 0, 'ok');
}));
Check::same(2, $attempts);
Check::same(['n' => 3], $store->transact('key', function ($value) { return new Change(null, 0, $value); }));
$redis->close();
// Older phpredis reconnects after close; temporarily make this isolated socket unreachable.
rename($socket, $socket . '.offline');
try {
    Check::throws(StorageException::class, function () use ($store) { $store->transact('offline', function () { return new Change(null, 0, true); }); });
} finally {
    rename($socket . '.offline', $socket);
}
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " Redis integration assertions passed\n";
