<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/upload-quarantine-backend-support.php';

$reserve = str_repeat('r', 65536);
register_shutdown_function(static function () use (&$reserve): void {
    $reserve = null; $error = error_get_last();
    if ($error !== null && $error['type'] === E_ERROR && strpos($error['message'], 'Allowed memory size') !== false) { fwrite(STDERR, 'UNSAFE_REDIS_UNBOUNDED_ALLOCATION ' . $error['message'] . "\n"); }
});
$variant = getenv('SOSECURITY_TEST_REDIS_CLASS');
if (is_string($variant) && $variant !== '') {
    if (strpos($variant, '/tmp/sosecurity-quarantine-backends-') !== 0 || !is_file($variant)) { throw new RuntimeException('Owned test class copy required.'); }
    require $variant;
}
$redis = quarantineBackendConnection('redis'); $namespace = quarantineBackendNamespace();
$store = new SoSecurity\Storage\RedisStore($redis, $namespace); $store->initialize();
$readyKey = 'sosecurity:' . hash('sha256', $namespace) . ':ready'; $ready = $redis->get($readyKey); $metadata = json_decode($ready, true);
$key = 'sosecurity:' . hash('sha256', $namespace) . ':' . $metadata['epoch'] . ':' . hash('sha256', 'probe');
$mode = $argv[1] ?? 'all'; $callbacks = 0;
function refuseRedisRead(callable $operation): void
{
    try { $operation(); } catch (SoSecurity\Storage\StorageException $error) { Check::same('storage.capacity', $error->reason()); return; }
    throw new RuntimeException('Oversized Redis input was accepted.');
}
$callback = static function ($value) use (&$callbacks) { ++$callbacks; return new SoSecurity\Storage\Change($value, 0, $value); };
try {
    if ($mode !== 'ready-large') {
        $redis->eval("return redis.call('SET',KEYS[1],string.rep(string.char(0),16777216))", [$key], 1);
        refuseRedisRead(static function () use ($store, $callback): void { $store->transact('probe', $callback); });
        Check::same(0, $callbacks); Check::same(16777216, $redis->strlen($key)); $redis->del($key);
    }
    if ($mode !== 'payload-large') {
        $redis->eval("return redis.call('SET',KEYS[1],string.rep(string.char(0),16777216))", [$readyKey], 1);
        refuseRedisRead(static function () use ($store, $callback): void { $store->transact('probe', $callback); });
        refuseRedisRead(static function () use ($store): void { $store->initialize(); });
        Check::same(0, $callbacks); Check::same(16777216, $redis->strlen($readyKey)); $redis->set($readyKey, $ready);
    }
    if ($mode === 'all') {
        $template = json_encode(['expires' => 0, 'value' => ['data' => '']]); $padding = str_repeat('x', 65536 - strlen($template));
        $raw = json_encode(['expires' => 0, 'value' => ['data' => $padding]]); Check::same(65536, strlen($raw)); $redis->set($key, $raw);
        Check::same(['data' => $padding], $store->transact('probe', $callback));
        $redis->set($key, $raw . "\0"); $calls = $callbacks;
        refuseRedisRead(static function () use ($store, $callback): void { $store->transact('probe', $callback); }); Check::same($calls, $callbacks);
        // Use a legal JSON NUL value without silently dropping its suffix.
        $redis->set($key, json_encode(['expires' => 0, 'value' => ['data' => "a\0b"]]));
        Check::same(['data' => "a\0b"], $store->transact('probe', $callback));
        $redis->set($key, json_encode(['expires' => 0, 'value' => ['data' => "a\0c"]]));
        Check::same(['data' => "a\0c"], $store->transact('probe', $callback));
        $padded = $metadata + ['padding' => '']; $base = json_encode($padded); $padded['padding'] = str_repeat('x', 512 - strlen($base)); $bounded = json_encode($padded);
        Check::same(512, strlen($bounded)); $redis->set($readyKey, $bounded); Check::same(false, $store->initialize());
        $redis->set($readyKey, $bounded . "\0"); refuseRedisRead(static function () use ($store): void { $store->initialize(); });
        $redis->set($readyKey, $ready);
        Check::same(true, memory_get_peak_usage(true) < 8388608);
    }
    echo 'PASS Redis atomic read bounds: ' . Check::$assertions . ' assertions PHP ' . PHP_VERSION . '; ' . $mode . "; 16MiB server-generated NUL fields rejected under 8MiB, callbacks protected\n";
} finally { $redis->set($readyKey, $ready); $redis->del($key); $redis->close(); }
