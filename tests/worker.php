<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\RedisStore;
use SoSecurity\RateLimit\RateLimiter;
use SoSecurity\RateLimit\Policy;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Captcha\Captcha;

$kind = $argv[1]; $target = $argv[2]; $operation = $argv[3];
if ($kind === 'redis') {
    $redis = new Redis(); $redis->connect($target, 0, 2.0);
    $store = new RedisStore($redis, 'concurrency');
} else { $store = new FileStore($target, 'concurrency'); }
if ($operation === 'rate') {
    echo (new RateLimiter($store, new Policy(5, 60)))->consume('login', 'subject')->allowed ? '1' : '0';
} elseif ($operation === 'csrf') {
    echo (new CsrfTokens($store))->verify('form', 'binding', $argv[4], true) ? '1' : '0';
} elseif ($operation === 'captcha') {
    echo (new Captcha($store))->verify('form', 'binding', $argv[4], $argv[5]) ? '1' : '0';
} else { throw new RuntimeException('Unknown operation.'); }
