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
if(strpos($operation,'credential-')===0){
    require __DIR__.'/credential-concurrency-support.php';$clock=new TestClock();$clock->time=(int)$argv[4];$services=concurrentCredentials($store,$clock);$registry=$services['registry'];
    // Public fixed test key and private synthetic credentials only; production tokens never belong in argv.
    if($operation==='credential-auth'){echo $registry->authenticate('credential-concurrency',$argv[5],$argv[6])!==null?'1':'0';}
    elseif($operation==='credential-issue'){try{$registry->issue('credential-concurrency','worker',$argv[5],'Concurrent',['documents:read']);echo '1';}catch(SoSecurity\Exception\SecurityException $error){if($error->reason()!=='api_credentials.capacity'){throw $error;}echo '0';}}
    elseif($operation==='credential-rotate'||$operation==='credential-replace'){
        $credential=$operation==='credential-rotate'?$registry->rotate('credential-concurrency','worker',$argv[5],$argv[6],(int)$argv[7]):$registry->replace('credential-concurrency','worker',$argv[5],$argv[6],(int)$argv[7],'Narrowed',['documents:read']);
        if($credential===null){echo '0';}else{$handle=fopen($argv[8],'x');if($handle===false){throw new RuntimeException('Duplicate credential generation winner.');}chmod($argv[8],0600);$token=$credential->token();$written=fwrite($handle,$token);fclose($handle);if($written!==strlen($token)){throw new RuntimeException('Incomplete private credential test channel.');}echo '1';}
    }elseif($operation==='credential-revoke'){echo $registry->revoke('credential-concurrency','worker',$argv[5],$argv[6])?'1':'0';}
    elseif($operation==='credential-revoke-all'){echo $registry->revokeAll('credential-concurrency','worker',$argv[5])>0?'1':'0';}
    else{throw new RuntimeException('Unknown managed credential test.');}
}elseif(strpos($operation,'link-')===0){
    require __DIR__.'/link-concurrency-support.php';$clock=new TestClock();$clock->time=(int)$argv[4];list($links,$linkTarget)=concurrentLinks($store,$clock);
    // Public test key/credentials only; never pass production signed URLs on process command lines.
    if($operation==='link-verify'){echo $links->verify($linkTarget,$argv[5])!==null?'1':'0';}
    elseif($operation==='link-issue'){try{$links->issue($linkTarget);echo '1';}catch(SoSecurity\Exception\SecurityException $error){if($error->reason()!=='link.capacity'){throw $error;}echo '0';}}
    else{throw new RuntimeException('Unknown signed-link test.');}
} elseif (strpos($operation,'op-')===0) {
    require __DIR__.'/operation-concurrency-support.php';$clock=new TestClock();$clock->time=(int)$argv[4];$services=concurrentOperations($store,$clock);$grants=$services['grants'];$intent=$services['intent'];
    if ($operation==='op-confirm') {
        $grant=$grants->confirm('operation-concurrency','worker',$argv[5],$intent,$argv[6]);
        if ($grant===null) {echo '0';}else {$file=fopen($argv[7],'x');if($file===false){throw new RuntimeException('Duplicate operation confirmation winner.');}chmod($argv[7],0600);$written=fwrite($file,$grant->token());fclose($file);if($written!==101){throw new RuntimeException('Incomplete private test credential channel.');}echo '1';}
    } elseif ($operation==='op-consume') {echo $grants->consume('operation-concurrency','worker',$argv[5],$intent,$argv[6])!==null ? '1':'0';}
    elseif ($operation==='op-begin') {
        try {$grants->begin('operation-concurrency','worker',$argv[5],$intent);echo '1';}
        catch (SoSecurity\Exception\SecurityException $error) {if($error->reason()!=='operation.capacity'){throw $error;}echo '0';}
    } else {throw new RuntimeException('Unknown operation test.');}
} elseif (in_array($operation, ['auth-register', 'auth-replace', 'auth-flow', 'auth-remember'], true)) {
    require __DIR__ . '/auth-support.php';
    $clock = new TestClock(); $clock->time = (int) $argv[4]; $provider = concurrentAuthProvider(); $factor = null;
    if ($operation === 'auth-remember') {
        $remember = new SoSecurity\Auth\RememberedLogin($store, $provider,
            new SoSecurity\Auth\SessionRegistry($store, $provider, null, $clock, 60, 300, 5),
            new SoSecurity\Support\HmacKeys('test', ['test' => str_repeat('r', 32)]), static function (): bool { return true; }, null, $clock);
        echo $remember->resume('form', $argv[5])->status() === 'authenticated' ? '1' : '0';
        exit;
    }
    if ($operation === 'auth-flow') {
        $cipher = new SoSecurity\Crypto\Cipher('test', ['test' => str_repeat('k', 32)], 'concurrency-mfa');
        $factor = new SoSecurity\Auth\TotpSecondFactor(new SoSecurity\Mfa\TotpFactors($store, $cipher, 'Concurrency', $clock));
    }
    $sessions = new SoSecurity\Auth\SessionRegistry($store, $provider, $factor, $clock, 60, 300, 5);
    if ($operation === 'auth-flow') {
        $flow = new SoSecurity\Auth\AuthenticationFlow($store, $provider, $sessions, static function (): bool { return true; }, $factor, $clock);
        echo $flow->secondFactor('form', 'auth-binding', $argv[5], ['type' => 'recovery', 'code' => $argv[6]])->status() === 'authenticated' ? '1' : '0';
    } else {
        try {
            $credential = $operation === 'auth-register' ? $sessions->register('form', 'auth-worker', $argv[5], $argv[6])
                : $sessions->replace('form', 'auth-worker', $argv[5], $argv[6], 'password', $argv[7], $argv[8]);
            echo $credential === null ? '0' : '1';
        } catch (SoSecurity\Exception\SecurityException $e) {
            if ($e->reason() !== 'auth.session_capacity') { throw $e; }
            echo '0';
        }
    }
} elseif (in_array($operation, ['mfa-confirm', 'mfa-code', 'mfa-recovery'], true)) {
    $clock = new TestClock(); $clock->time = (int) $argv[4];
    $cipher = new SoSecurity\Crypto\Cipher('test', ['test' => str_repeat('k', 32)], 'concurrency-mfa');
    $mfa = new SoSecurity\Mfa\TotpFactors($store, $cipher, 'Concurrency', $clock);
    if ($operation === 'mfa-confirm') { echo $mfa->confirm('form', 'confirmation', $argv[5], $argv[6]) !== null ? '1' : '0'; }
    elseif ($operation === 'mfa-code') { echo $mfa->verify('form', 'subject', $argv[5]) ? '1' : '0'; }
    else { echo $mfa->verifyRecovery('form', 'subject', $argv[5]) ? '1' : '0'; }
} elseif (strpos($operation, 'lease-') === 0) {
    $clock = new TestClock(); $clock->time = (int) $argv[4]; $leases = new SoSecurity\Concurrency\LeaseManager($store, new SoSecurity\Concurrency\LeasePolicy(5, 60, 300), $clock);
    if ($operation === 'lease-acquire') { echo $leases->acquire('concurrent-leases', 'resource', 'worker-' . $argv[5]) !== null ? '1' : '0'; }
    elseif ($operation === 'lease-renew') { echo $leases->renew('concurrent-leases', 'resource', 'controller', $argv[5]) !== null ? '1' : '0'; }
    elseif ($operation === 'lease-release') { echo $leases->release('concurrent-leases', 'resource', 'controller', $argv[5]) ? '1' : '0'; }
    elseif ($operation === 'lease-hold') {
        $lease = $leases->acquire('concurrent-leases', 'resource', 'crashed-worker');
        if ($lease === null) { throw new RuntimeException('Crash worker lease rejected.'); }
        echo json_encode(['token'=>$lease->token(),'fence'=>$lease->fence()]) . "\n"; flush();
        while (true) { sleep(60); }
    } else { throw new RuntimeException('Unknown lease operation.'); }
} elseif (strpos($operation, 'budget-') === 0) {
    $clock = new TestClock(); $clock->time = (int) $argv[4];
    if ($operation === 'budget-group') {
        $limiter = new SoSecurity\RateLimit\BudgetGroup($store, ['requests' => new SoSecurity\RateLimit\BudgetPolicy('fixed_window', 10, 300), 'work' => new SoSecurity\RateLimit\BudgetPolicy('sliding_window', 15, 300)], $clock);
        $result = $limiter->consume($operation, 'subject', ['requests' => 2, 'work' => 3]);
    } elseif ($operation === 'budget-ordered') {
        $limiter = new SoSecurity\RateLimit\CompositeLimiter(['ip' => new SoSecurity\RateLimit\BudgetLimiter($store, new SoSecurity\RateLimit\BudgetPolicy('fixed_window', 100, 300), $clock), 'account' => new SoSecurity\RateLimit\BudgetLimiter($store, new SoSecurity\RateLimit\BudgetPolicy('fixed_window', 10, 300), $clock)], $clock);
        $result = $limiter->consume($operation, ['ip' => '192.0.2.1', 'account' => 'tenant:subject'], ['ip' => 1, 'account' => 2]);
    } else {
        $algorithm = ['budget-token' => 'token_bucket', 'budget-fixed' => 'fixed_window', 'budget-sliding' => 'sliding_window'][$operation];
        $result = (new SoSecurity\RateLimit\BudgetLimiter($store, new SoSecurity\RateLimit\BudgetPolicy($algorithm, 10, 300), $clock))->consume($operation, 'subject', 2);
    }
    echo $result->allowed() ? '1' : '0';
} elseif ($operation === 'rate') {
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
