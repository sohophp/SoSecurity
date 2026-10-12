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
} elseif ($operation === 'hmac') {
    // Public fixed test material only. Never pass production credentials on a process command line.
    $key=new SoSecurity\Api\SigningKey('concurrency-key',str_repeat('k',32),'worker',['read']);
    $policy=new SoSecurity\Api\SignaturePolicy(['origin'=>'https://api.example.com']);
    $headers=json_decode(base64_decode($argv[4],true),true);
    $verifier=new SoSecurity\Api\HmacVerifier($policy,new SoSecurity\Api\KeyRing([$key]),new SoSecurity\Api\NonceStore($store));
    echo $verifier->verify('POST','https://api.example.com/task','{}',$headers,'read')!==null ? '1' : '0';
} elseif ($operation === 'api-rotate') {
    try { $credential=(new SoSecurity\Api\ApiKeys($store))->rotate($argv[4]); }
    catch (SoSecurity\Storage\StorageException $e) {
        $previous=$e->getPrevious();
        if ($kind==='mysql' && $previous instanceof PDOException && isset($previous->errorInfo[1]) && $previous->errorInfo[1]===1205) {
            // Explicit, expected bounded rejection under contention; never count it as a successful rotation.
            echo 'T'; exit;
        }
        throw $e;
    }
    // Every successful replacement may be superseded by another; only the final digest remains valid.
    echo $credential!==null ? '1' : '0';
} elseif ($operation === 'reset' && $kind === 'mysql') {
    require dirname(__DIR__) . '/examples/password-reset.php';
    $tokens = explode(',', $argv[4]);
    $result = SoSecurity\Examples\resetPassword($pdo, new SoSecurity\Password\ResetTokens($store),
        new SoSecurity\Password\PasswordHasher('bcrypt', ['cost' => 10]), 'concurrency-demo', 1,
        $tokens[(int) $argv[5] % count($tokens)], 'Replacement-concurrent-password');
    echo in_array($result, ['reset.applied', 'reset.applied_cleanup_pending'], true) ? '1' : '0';
} else { throw new RuntimeException('Unknown operation.'); }
