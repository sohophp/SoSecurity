<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\RateLimit\Policy;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\Codec;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Http\Cookie;

$seconds = 5; $policy = new Policy(3, 10, [&$seconds], 60);
$seconds = -1;
Check::same([5], $policy->banDurations());
Check::throws(ConfigurationException::class, function () use ($policy) { $policy->limit = 0; });
Check::same(3, $policy->limit());
$change = new Change(['valid' => true], 20, 'result');
Check::throws(ConfigurationException::class, function () use ($change) { $change->expiresAt = -1; });
Check::same(20, $change->expiresAt());
$called = false;
$hook = new class($called) implements JsonSerializable {
    private $called;
    public function __construct(&$called) { $this->called = &$called; }
    public function jsonSerialize(): array { $this->called = true; return ['hidden' => true]; }
};
Check::throws(StorageException::class, function () use ($hook) { Codec::encode(new Change(['hook' => $hook], 0, null)); });
Check::same(false, $called);
try { Codec::decode('broken', 0); }
catch (StorageException $e) { Check::same('storage.corrupt', $e->reason()); }
Check::same(true, strpos(Cookie::header('session', 'v', '/admin', true, true, 'Lax', 300, '.example.com'), 'Domain=example.com') !== false);
Check::throws(ConfigurationException::class, function () { Cookie::header('__Host-session', 'v', '/', true, true, 'Lax', null, 'example.com'); });
Check::throws(ConfigurationException::class, function () { Cookie::header('session', 'v', '/', true, true, 'Lax', null, "evil\r\nInjected: yes"); });
$directory = privateDirectory();
try {
    $clock = new TestClock();
    $store = new FileStore($directory, 'hardening', $clock, 20);
    $key = 'held-lock';
    $hash = hash('sha256', "hardening\0" . $key);
    $lock = fopen($directory . '/lock-' . (hexdec(substr($hash, 0, 2)) % 64), 'c');
    flock($lock, LOCK_EX);
    $started = microtime(true);
    try {
        $store->transact($key, function () { return new Change(['n' => 1], 0, true); });
        throw new RuntimeException('Lock contention incorrectly committed.');
    } catch (StorageException $e) { Check::same('storage.lock_timeout', $e->reason()); }
    Check::same(true, microtime(true) - $started < .5);
    Check::same(false, file_exists($directory . '/' . $hash . '.json'));
    flock($lock, LOCK_UN); fclose($lock);
    Check::same(true, $store->transact($key, function () { return new Change(['n' => 1], 0, true); }));
    for ($i = 0; $i < 11; ++$i) {
        $store->transact('expire-' . $i, function () use ($clock) { return new Change(['n' => 1], $clock->time + 1, null); });
    }
    $clock->time++;
    $deleted = 0; $batches = 0;
    do {
        $batch = $store->pruneBatch(3); ++$batches;
        Check::same(true, $batch->scanned() <= 3);
        $deleted += $batch->removed();
        if ($batches > 100) { throw new RuntimeException('Prune never completed.'); }
    } while (!$batch->complete());
    Check::same(11, $deleted);
    Check::same(['n' => 1], $store->transact($key, function ($value) { return new Change($value, 0, $value); }));
    Check::same(true, $batches > 1);
    Check::throws(ConfigurationException::class, function () use ($store) { $store->pruneBatch(0); });
    Check::throws(ConfigurationException::class, function () use ($directory) { new FileStore($directory, 'x', null, 0); });
} finally { cleanDirectory($directory); }
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " hardening assertions passed\n";
