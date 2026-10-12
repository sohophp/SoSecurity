<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Storage\RedisStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Csrf\CsrfTokens;

$phase = $argv[1]; $socket = $argv[2]; $stateFile = $argv[3];
$redis = new Redis(); $redis->connect($socket, 0, 1.0);
$store = new RedisStore($redis, 'restart-test');
$tokens = new CsrfTokens($store);
if ($phase === 'seed') {
    Check::same(true, $store->initialize());
    $token = $tokens->issue('form', 'binding');
    file_put_contents($stateFile, json_encode(['token' => $token])); chmod($stateFile, 0600);
} elseif ($phase === 'consume') {
    $state = json_decode(file_get_contents($stateFile), true);
    Check::same(true, $tokens->verify('form', 'binding', $state['token'], true));
} elseif ($phase === 'reject') {
    $state = json_decode(file_get_contents($stateFile), true);
    try { $tokens->verify('form', 'binding', $state['token'], true); throw new RuntimeException('Old snapshot replay accepted.'); }
    catch (StorageException $e) { Check::same('storage.restart', $e->reason()); }
    try { $store->initialize(); throw new RuntimeException('Restart resumed without explicit recovery.'); }
    catch (StorageException $e) { Check::same('storage.restart', $e->reason()); }
    Check::same(true, $store->initialize(true));
    Check::same(false, $tokens->verify('form', 'binding', $state['token'], true));
    $new = $tokens->issue('form', 'binding');
    Check::same(true, $tokens->verify('form', 'binding', $new, true));
    $redis->del('sosecurity:' . hash('sha256', 'restart-test') . ':ready');
    try { $tokens->verify('form', 'binding', $new); throw new RuntimeException('Lost readiness marker ignored.'); }
    catch (StorageException $e) { Check::same('storage.uninitialized', $e->reason()); }
} else { throw new RuntimeException('Unknown phase.'); }
echo "PASS Redis restart phase $phase: " . Check::$assertions . " assertions\n";
