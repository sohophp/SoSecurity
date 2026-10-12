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
$diagnostic = SoSecurity\Security::fromArray(['site' => 'probe', 'storage' => ['driver' => 'redis', 'connection' => 'r']], ['r' => $redis]);
$checks = array_column($diagnostic->diagnose(null, true), null, 'check');
Check::same('pass', $checks['storage.shared.connection']['status']);
Check::same('pass', $checks['storage.shared.eviction']['status']);
Check::same('pass', $checks['storage.shared.cas_permission']['status']);
$redis->setOption(Redis::OPT_PREFIX, 'wrong-prefix:');
try {
    $store->transact('key', function () { return new Change(['n' => 1], 0, true); });
    throw new RuntimeException('Changed Redis options were accepted.');
} catch (StorageException $e) { Check::same('storage.configuration', $e->reason()); }
$redis->setOption(Redis::OPT_PREFIX, '');
Check::same(true, (float) $redis->getOption(Redis::OPT_READ_TIMEOUT) > 0);
$bounded = new RedisStore($redis, $namespace . '-deadline', null, 10);
try {
    $bounded->transact('slow', function () { usleep(20000); return new Change(['n' => 1], 0, true); });
    throw new RuntimeException('Slow callback committed past the deadline.');
} catch (StorageException $e) { Check::same('storage.timeout', $e->reason()); }
Check::same(null, $bounded->transact('slow', function ($value) { return new Change(null, 0, $value); }));
$bounded = new RedisStore($redis, $namespace . '-conflict', null, 1000, 2);
$conflictKey = 'sosecurity:' . hash('sha256', $namespace . '-conflict') . ':' . hash('sha256', 'key');
$counter = 0;
try {
    $bounded->transact('key', function () use ($conflict, $conflictKey, &$counter) {
        $conflict->set($conflictKey, json_encode(['expires' => 0, 'value' => ['n' => ++$counter]]));
        return new Change(['n' => 99], 0, true);
    });
    throw new RuntimeException('Conflicting commit was accepted.');
} catch (StorageException $e) { Check::same('storage.contention', $e->reason()); }
Check::same(2, $counter);
$conflict->del($conflictKey);
// Exhaust only the isolated test server's memory; an existing record must survive the rejected write.
$store->transact('oom', function () { return new Change(['original' => true], 0, null); });
$oomKey = 'sosecurity:' . hash('sha256', $namespace) . ':' . hash('sha256', 'oom');
$maximum = $conflict->config('GET', 'maxmemory')['maxmemory'];
$conflict->config('SET', 'maxmemory', '1');
try {
    Check::throws(StorageException::class, function () use ($store) {
        $store->transact('oom', function () { return new Change(['replacement' => true], 0, true); });
    });
    Check::same(['original' => true], json_decode($conflict->get($oomKey), true)['value']);
} finally { $conflict->config('SET', 'maxmemory', (string) $maximum); $conflict->del($oomKey); }
$redis = new Redis(); $redis->connect($socket, 0, 2.0);
$store = new RedisStore($redis, $namespace);
// Pause ONLY this isolated test server; actual socket waiting must respect the total budget.
$bounded = new RedisStore($redis, $namespace . '-socket', null, 20);
$conflict->rawCommand('CLIENT', 'PAUSE', '200');
$started = microtime(true);
try {
    $bounded->transact('key', function () { return new Change(['n' => 1], 0, true); });
    throw new RuntimeException('Paused server unexpectedly committed.');
} catch (StorageException $e) { Check::same(true, in_array($e->reason(), ['storage.timeout', 'storage.connection'], true)); }
Check::same(true, microtime(true) - $started < .15);
$redis = new Redis(); $redis->connect($socket, 0, 2.0);
$store = new RedisStore($redis, $namespace);
$redis->close();
// Older phpredis reconnects after close; temporarily make this isolated socket unreachable.
rename($socket, $socket . '.offline');
try {
    Check::throws(StorageException::class, function () use ($store) { $store->transact('offline', function () { return new Change(null, 0, true); }); });
} finally {
    rename($socket . '.offline', $socket);
}
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " Redis integration assertions passed\n";
