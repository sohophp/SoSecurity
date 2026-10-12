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
} elseif ($kind === 'mysql') {
    $pdo = new PDO('mysql:unix_socket=' . $target . ';dbname=sosecurity_test;charset=utf8mb4', 'sosecurity_test', 'integration-only', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $store = new SoSecurity\Storage\MySqlStore($pdo, 'concurrency', null, 5);
} else { $store = new FileStore($target, 'concurrency'); }
if ($operation === 'rate') {
    echo (new RateLimiter($store, new Policy(5, 60)))->consume('login', 'subject')->allowed ? '1' : '0';
} elseif ($operation === 'csrf') {
    echo (new CsrfTokens($store))->verify('form', 'binding', $argv[4], true) ? '1' : '0';
} elseif ($operation === 'captcha') {
    echo (new Captcha($store))->verify('form', 'binding', $argv[4], $argv[5]) ? '1' : '0';
} elseif ($operation === 'upload') {
    (new SoSecurity\Upload\Saver(new SoSecurity\Upload\Validator(), $target, $argv[5]))->saveFile($argv[4], 'same-name.png');
    echo '1';
} elseif ($operation === 'reset' && $kind === 'mysql') {
    require dirname(__DIR__) . '/examples/password-reset.php';
    $tokens = explode(',', $argv[4]);
    $result = SoSecurity\Examples\resetPassword($pdo, new SoSecurity\Password\ResetTokens($store),
        new SoSecurity\Password\PasswordHasher('bcrypt', ['cost' => 10]), 'concurrency-demo', 1,
        $tokens[(int) $argv[5] % count($tokens)], 'Replacement-concurrent-password');
    echo in_array($result, ['reset.applied', 'reset.applied_cleanup_pending'], true) ? '1' : '0';
} else { throw new RuntimeException('Unknown operation.'); }
