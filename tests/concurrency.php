<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/captcha-support.php';
require __DIR__ . '/auth-support.php';
require __DIR__ . '/operation-concurrency-support.php';
require __DIR__ . '/link-concurrency-support.php';
require __DIR__ . '/credential-concurrency-support.php';
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\RedisStore;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Captcha\Captcha;

function parallelSuccesses(string $kind, string $target, string $operation, array $arguments = []): int
{
    $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/worker.php');
    foreach (array_merge([$kind, $target, $operation], $arguments) as $argument) { $command .= ' ' . escapeshellarg($argument); }
    $processes = [];
    for ($i = 0; $i < 24; ++$i) {
        $pipes = [];
        $workerCommand = in_array($operation, ['reset','lease-acquire'], true) ? $command . ' ' . $i : $command;
        $process = proc_open($workerCommand, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) { throw new RuntimeException('Cannot start test worker.'); }
        fclose($pipes[0]); $processes[] = [$process, $pipes];
    }
    $successes = 0; $lockTimeouts = 0;
    foreach ($processes as list($process, $pipes)) {
        $stdout = stream_get_contents($pipes[1]); $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]); $code = proc_close($process);
        if ($code===0 && $stderr==='' && $stdout==='T' && $kind==='mysql' && $operation==='api-rotate') { ++$lockTimeouts; continue; }
        if ($code !== 0 || $stderr !== '' || !in_array($stdout, ['0', '1'], true)) {
            throw new RuntimeException('Worker failed: ' . $stderr . $stdout);
        }
        $successes += (int) $stdout;
    }
    if ($operation==='api-rotate') { echo "RESULT $kind API rotation: $successes succeeded, $lockTimeouts explicitly rejected on bounded SQL lock wait\n"; }
    return $successes;
}

$directory = privateDirectory();
try {
    $backends = ['file' => $directory];
    $socket = getenv('SOSECURITY_TEST_REDIS_SOCKET');
    if ($socket) { $backends['redis'] = $socket; }
    $mysql = getenv('SOSECURITY_TEST_MYSQL_SOCKET');
    if ($mysql) { $backends['mysql'] = $mysql; }
    foreach ($backends as $kind => $target) {
        if ($kind === 'redis') {
            $redis = new Redis(); $redis->connect($target, 0, 2.0);
            $store = new RedisStore($redis, 'concurrency'); $store->initialize();
            // Only dedicated test-instance keys; never FLUSHDB or touch unrelated namespaces.
            (new SoSecurity\RateLimit\RateLimiter($store))->reset('login', 'subject');
        } elseif ($kind === 'mysql') {
            $pdo = new PDO('mysql:unix_socket=' . $target . ';dbname=sosecurity_test;charset=utf8mb4', 'sosecurity_test', 'integration-only', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $store = new SoSecurity\Storage\MySqlStore($pdo, 'concurrency');
            (new SoSecurity\RateLimit\RateLimiter($store))->reset('login', 'subject');
        } else { $store = new FileStore($target, 'concurrency'); }
        credentialConcurrencySuite($kind,$target,$store,$directory);
        if(($argv[1] ?? null)==='credentials'){continue;}
        Check::same(5, parallelSuccesses($kind, $target, 'rate'));
        $linkClock=new TestClock();$linkClock->time=time();list($linkService,$linkTarget)=concurrentLinks($store,$linkClock);$linkService->revokeAll($linkTarget);
        $singleLink=$linkService->issue($linkTarget,true);Check::same(null,$linkService->verify($linkTarget,$singleLink->url(),'HEAD'));
        Check::same(1,parallelSuccesses($kind,$target,'link-verify',[(string)$linkClock->time,$singleLink->url()]));
        Check::same(0,parallelSuccesses($kind,$target,'link-verify',[(string)$linkClock->time,$singleLink->url()]));
        $reusableLink=$linkService->issue($linkTarget);Check::same(24,parallelSuccesses($kind,$target,'link-verify',[(string)$linkClock->time,$reusableLink->url()]));
        Check::same(true,$linkService->revoke($linkTarget,$reusableLink->id()));Check::same(0,parallelSuccesses($kind,$target,'link-verify',[(string)$linkClock->time,$reusableLink->url()]));
        Check::same(8,parallelSuccesses($kind,$target,'link-issue',[(string)$linkClock->time]));Check::same(8,count($linkService->all($linkTarget)));$linkService->revokeAll($linkTarget);
        $expiredLink=$linkService->issue($linkTarget,true);$linkClock->time+=300;Check::same(0,parallelSuccesses($kind,$target,'link-verify',[(string)$linkClock->time,$expiredLink->url()]));$linkService->revokeAll($linkTarget);
        echo "PASS $kind signed links: 24 processes consume once, reuse 24 times, reject replay/revocation/expiry and admit 8 at capacity; HEAD preserves one-use link\n";
        $operationClock=new TestClock();$operationClock->time=time();$operation=concurrentOperations($store,$operationClock);
        $operationSession=concurrentOperationProof($operation);
        $pending=$operation['grants']->begin('operation-concurrency','worker',$operationSession->token(),$operation['intent']);
        $operationSession=concurrentOperationProof($operation,$operationSession->token());$channel=$directory.'/operation-grant-'.bin2hex(random_bytes(8));
        Check::same(1,parallelSuccesses($kind,$target,'op-confirm',[(string)$operationClock->time,$operationSession->token(),$pending->token(),$channel]));
        $operationGrant=file_get_contents($channel);Check::same(101,strlen($operationGrant));Check::same(0600,fileperms($channel)&0777);unlink($channel);
        Check::same(1,parallelSuccesses($kind,$target,'op-consume',[(string)$operationClock->time,$operationSession->token(),$operationGrant]));
        Check::same(0,parallelSuccesses($kind,$target,'op-consume',[(string)$operationClock->time,$operationSession->token(),$operationGrant]));
        Check::same(8,parallelSuccesses($kind,$target,'op-begin',[(string)$operationClock->time,$operationSession->token()]));
        $operation['grants']->revokeAll('operation-concurrency','worker',$operationSession->token());
        $pending=$operation['grants']->begin('operation-concurrency','worker',$operationSession->token(),$operation['intent']);
        $operationSession=concurrentOperationProof($operation,$operationSession->token());
        $operationGrant=$operation['grants']->confirm('operation-concurrency','worker',$operationSession->token(),$operation['intent'],$pending->token());
        Check::same(true,$operationGrant!==null);$operationClock->time+=300;
        Check::same(0,parallelSuccesses($kind,$target,'op-consume',[(string)$operationClock->time,$operationSession->token(),$operationGrant->token()]));
        $operation['grants']->revokeAll('operation-concurrency','worker',$operationSession->token());
        // Remove only this synthetic future-clock identity before another suite reuses the dedicated test backend.
        $store->transact(SoSecurity\Support\Guard::key('auth-sessions','operation-concurrency','worker'),static function () {return new SoSecurity\Storage\Change(null,0,null);});
        echo "PASS $kind operations: 24 processes confirm once, consume once, replay/expiry reject all and capacity admits 8; synthetic proof, shared ledger\n";
        $leaseClock = new TestClock(); $leaseClock->time = time(); $leasePolicy = new SoSecurity\Concurrency\LeasePolicy(5, 60, 300);
        $leases = new SoSecurity\Concurrency\LeaseManager($store, $leasePolicy, $leaseClock); $leaseEpoch = $leases->initialize('concurrent-leases', 'resource');
        Check::same(5, parallelSuccesses($kind, $target, 'lease-acquire', [(string) $leaseClock->time]));
        Check::same(5, $leases->inspect('concurrent-leases', 'resource')->active()); Check::same(5, $leases->inspect('concurrent-leases', 'resource')->sequence());
        $leaseClock->time += 60;
        Check::same(0, $leases->inspect('concurrent-leases', 'resource')->active());
        $lease = $leases->acquire('concurrent-leases', 'resource', 'controller'); Check::same(6, $lease->fence());
        Check::same(24, parallelSuccesses($kind, $target, 'lease-renew', [(string) $leaseClock->time, $lease->token()]));
        Check::same(1, parallelSuccesses($kind, $target, 'lease-release', [(string) $leaseClock->time, $lease->token()]));
        $replacement = $leases->acquire('concurrent-leases', 'resource', 'controller'); Check::same(7, $replacement->fence());
        Check::same(0, parallelSuccesses($kind, $target, 'lease-release', [(string) $leaseClock->time, $lease->token()]));
        Check::same(0, parallelSuccesses($kind, $target, 'lease-renew', [(string) $leaseClock->time, $lease->token()]));
        Check::same(1, $leases->inspect('concurrent-leases', 'resource')->active());
        $leases->release('concurrent-leases', 'resource', 'controller', $replacement->token());
        // Kill the actual PHP worker; no destructor/finally release can run. Clock advance models deadline recovery.
        $command = 'exec ' . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/worker.php');
        foreach ([$kind,$target,'lease-hold',(string) $leaseClock->time] as $argument) { $command .= ' ' . escapeshellarg($argument); }
        $pipes = []; $process = proc_open($command, [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']], $pipes);
        if (!is_resource($process)) { throw new RuntimeException('Cannot start crash worker.'); }
        try {
            fclose($pipes[0]); stream_set_timeout($pipes[1], 5); $line = fgets($pipes[1]);
            if ($line === false) { throw new RuntimeException('Crash worker did not acquire a lease.'); }
            $crashed = json_decode($line, true); Check::same(true, is_array($crashed) && isset($crashed['token']));
            Check::same(true, proc_terminate($process, 9));
            for ($wait = 0; $wait < 200 && proc_get_status($process)['running']; ++$wait) { usleep(10000); }
            Check::same(false, proc_get_status($process)['running']);
        } finally {
            if (proc_get_status($process)['running']) { proc_terminate($process, 9); }
            fclose($pipes[1]); $stderr = stream_get_contents($pipes[2]); fclose($pipes[2]); proc_close($process);
        }
        Check::same('', $stderr); Check::same(1, $leases->inspect('concurrent-leases', 'resource')->active());
        $leaseClock->time += 60; $recovered = $leases->acquire('concurrent-leases', 'resource', 'recovered');
        Check::same(true, $recovered->fence() > $crashed['fence']); Check::same(false, $leases->release('concurrent-leases', 'resource', 'crashed-worker', $crashed['token']));
        $leases->release('concurrent-leases', 'resource', 'recovered', $recovered->token()); Check::same(true, $leases->remove('concurrent-leases', 'resource', $leaseEpoch));
        echo "PASS $kind leases: 24 processes admit 5 holders; bounded renewals, one release, stale rejection and SIGKILL recovery preserve fencing sequence\n";
        $budgetClock = new TestClock(); $budgetClock->time = time();
        foreach (['budget-token' => 'token_bucket', 'budget-fixed' => 'fixed_window', 'budget-sliding' => 'sliding_window'] as $operation => $algorithm) {
            $limiter = new SoSecurity\RateLimit\BudgetLimiter($store, new SoSecurity\RateLimit\BudgetPolicy($algorithm, 10, 300), $budgetClock);
            $limiter->reset($operation, 'subject');
            Check::same(5, parallelSuccesses($kind, $target, $operation, [(string) $budgetClock->time]));
            Check::same(0, $limiter->inspect($operation, 'subject')->remaining());
        }
        $group = new SoSecurity\RateLimit\BudgetGroup($store, ['requests' => new SoSecurity\RateLimit\BudgetPolicy('fixed_window', 10, 300), 'work' => new SoSecurity\RateLimit\BudgetPolicy('sliding_window', 15, 300)], $budgetClock);
        $group->reset('budget-group', 'subject');
        Check::same(5, parallelSuccesses($kind, $target, 'budget-group', [(string) $budgetClock->time]));
        $groupState = $group->inspect('budget-group', 'subject');
        Check::same(0, $groupState->decisions()['requests']->remaining()); Check::same(0, $groupState->decisions()['work']->remaining());
        $orderedIp = new SoSecurity\RateLimit\BudgetLimiter($store, new SoSecurity\RateLimit\BudgetPolicy('fixed_window', 100, 300), $budgetClock);
        $orderedAccount = new SoSecurity\RateLimit\BudgetLimiter($store, new SoSecurity\RateLimit\BudgetPolicy('fixed_window', 10, 300), $budgetClock);
        $orderedIp->reset(SoSecurity\RateLimit\CompositeLimiter::scopeFor('budget-ordered', 'ip'), '192.0.2.1');
        $orderedAccount->reset(SoSecurity\RateLimit\CompositeLimiter::scopeFor('budget-ordered', 'account'), 'tenant:subject');
        Check::same(5, parallelSuccesses($kind, $target, 'budget-ordered', [(string) $budgetClock->time]));
        Check::same(76, $orderedIp->inspect(SoSecurity\RateLimit\CompositeLimiter::scopeFor('budget-ordered', 'ip'), '192.0.2.1')->remaining());
        Check::same(0, $orderedAccount->inspect(SoSecurity\RateLimit\CompositeLimiter::scopeFor('budget-ordered', 'account'), 'tenant:subject')->remaining());
        echo "PASS $kind budgets: 24 processes; three weighted algorithms and atomic groups admit exactly 5; ordered combination retains all 24 entry charges\n";
        $csrf = new CsrfTokens($store); $token = $csrf->issue('form', 'binding');
        Check::same(1, parallelSuccesses($kind, $target, 'csrf', [$token]));
        $captcha = new Captcha($store); $challenge = $captcha->arithmetic('form', 'binding');
        preg_match('/^(\d+) \+ (\d+)/', $challenge->prompt, $parts);
        Check::same(1, parallelSuccesses($kind, $target, 'captcha', [$challenge->id, (string) ($parts[1] + $parts[2])]));
        foreach (['slider', 'click'] as $method) {
            $interactive = $captcha->$method('form', 'binding');
            $solution = captchaTestSolution($store, $interactive);
            Check::same(1, parallelSuccesses($kind, $target, 'captcha', [$interactive->id, $solution]));
        }
        echo "PASS $kind interactive CAPTCHA: 24 simultaneous slider/click solutions, exactly one accepted per challenge\n";
        $key=new SoSecurity\Api\SigningKey('concurrency-key',str_repeat('k',32),'worker',['read']);
        $signer=new SoSecurity\Api\HmacSigner(new SoSecurity\Api\SignaturePolicy(['origin'=>'https://api.example.com']),$key);
        $headers=$signer->sign('POST','https://api.example.com/task','{}');
        Check::same(1,parallelSuccesses($kind,$target,'hmac',[base64_encode(json_encode($headers))]));
        $apiKeys=new SoSecurity\Api\ApiKeys($store); $credential=$apiKeys->issue('worker',['read'],120);
        $rotated=parallelSuccesses($kind,$target,'api-rotate',[$credential->identity()->id()]);
        Check::same(true,$kind==='mysql' ? $rotated>=1 && $rotated<=24 : $rotated===24);
        Check::same(null,$apiKeys->authenticate($credential->token()));
        $finalCredential=$apiKeys->rotate($credential->identity()->id());
        Check::same('worker',$apiKeys->authenticate($finalCredential->token())->subject());
        Check::same(true,$apiKeys->revoke($credential->identity()->id()));
        Check::same(null,$apiKeys->authenticate($finalCredential->token()));
        Check::same(null,$apiKeys->rotate($credential->identity()->id()));
        echo "PASS $kind API: 24 identical signed requests / exactly one nonce accepted; concurrent rotation invalidates original credential; revocation cannot revive it\n";
        if ($kind === 'mysql') {
            $pdo->exec('DROP TABLE IF EXISTS accounts');
            $pdo->exec('CREATE TABLE accounts (id VARCHAR(128) PRIMARY KEY, version BIGINT NOT NULL, password_hash VARCHAR(255) NOT NULL) ENGINE=InnoDB');
            $pdo->exec("INSERT INTO accounts VALUES ('concurrency-demo',1,'OLD')");
            $reset = new SoSecurity\Password\ResetTokens($store); $tokens = [];
            for ($i = 0; $i < 4; ++$i) { $tokens[] = $reset->issue('concurrency-demo:1'); }
            Check::same(1, parallelSuccesses($kind, $target, 'reset', [implode(',', $tokens)]));
            Check::same(2, (int) $pdo->query("SELECT version FROM accounts WHERE id='concurrency-demo'")->fetchColumn());
            Check::same(true, (new SoSecurity\Password\PasswordHasher())->verify('Replacement-concurrent-password', $pdo->query("SELECT password_hash FROM accounts WHERE id='concurrency-demo'")->fetchColumn()));
            $pdo->exec('DROP TABLE accounts');
            echo "PASS MySQL password reset: 24 workers / 4 valid tokens; exactly one host version update\n";
        }
        $authClock = new TestClock(); $authClock->time = time(); $authProvider = concurrentAuthProvider();
        $authSessions = new SoSecurity\Auth\SessionRegistry($store, $authProvider, null, $authClock, 60, 300, 5);
        $authSessions->revokeAll('form', 'auth-worker'); $epoch = $authSessions->epoch('form', 'auth-worker');
        $fingerprint = (new SoSecurity\Auth\IdentityState($authProvider, null))->load('form', 'auth-worker')['fingerprint'];
        Check::same(5, parallelSuccesses($kind, $target, 'auth-register', [(string) $authClock->time, $fingerprint, $epoch]));
        $authSessions->revokeAll('form', 'auth-worker'); $epoch = $authSessions->epoch('form', 'auth-worker');
        $credential = $authSessions->register('form', 'auth-worker', $fingerprint, $epoch); $reference = SoSecurity\Auth\SessionRegistry::reference($credential->token());
        Check::same(1, parallelSuccesses($kind, $target, 'auth-replace', [(string) $authClock->time, $fingerprint, $epoch, $reference['id'], $reference['digest']]));
        Check::same(null, $authSessions->verify('form', 'auth-worker', $credential->token()));
        $authSessions->revokeAll('form', 'auth-worker');
        Check::same(0, parallelSuccesses($kind, $target, 'auth-register', [(string) $authClock->time, $fingerprint, $epoch]));
        Check::same([], $authSessions->all('form', 'auth-worker'));
        echo "PASS $kind auth registry: 24 processes; capacity admits 5, reauthentication rotates once, revoked epoch admits none\n";
        $remember = new SoSecurity\Auth\RememberedLogin($store, $authProvider, $authSessions,
            new SoSecurity\Support\HmacKeys('test', ['test' => str_repeat('r', 32)]), static function (): bool { return true; }, null, $authClock);
        $epoch = $authSessions->epoch('form', 'auth-worker');
        $credential = $authSessions->register('form', 'auth-worker', $fingerprint, $epoch);
        $persistent = $remember->issue('form', 'auth-worker', $credential->token());
        Check::same(1, parallelSuccesses($kind, $target, 'auth-remember', [(string) $authClock->time, $persistent->token()]));
        Check::same(1, count($authSessions->all('form', 'auth-worker')));
        $authClock->time += 5;
        Check::same('replayed', $remember->resume('form', $persistent->token())->status());
        Check::same([], $authSessions->all('form', 'auth-worker')); Check::same([], $remember->all('form', 'auth-worker'));
        // Reset to real time only after removing the ledger; do not hide clock regressions.
        $store->transact(SoSecurity\Support\Guard::key('auth-sessions', 'form', 'auth-worker'), static function () { return new SoSecurity\Storage\Change(null, 0, null); });
        $authClock->time = time();
        echo "PASS $kind persistent login: 24 processes; one rotation, concurrent retry, expired-grace replay atomically revokes both session and grants\n";
        if (extension_loaded('sodium')) {
            $mfaClock = new TestClock(); $mfaClock->time = time();
            $cipher = new SoSecurity\Crypto\Cipher('test', ['test' => str_repeat('k', 32)], 'concurrency-mfa');
            $mfa = new SoSecurity\Mfa\TotpFactors($store, $cipher, 'Concurrency', $mfaClock);
            $totp = new SoSecurity\Mfa\Totp();
            $mfa->revoke('form', 'confirmation'); $mfa->revoke('form', 'subject');
            $authMfa = new SoSecurity\Mfa\TotpFactors($store, $cipher, 'Concurrency', $authClock);
            $pending = $authMfa->begin('form', 'auth-worker', 'auth@example.test');
            parse_str(parse_url($pending->provisioningUri(), PHP_URL_QUERY), $authProvision);
            $authCodes = $authMfa->confirm('form', 'auth-worker', $pending->id(), $totp->codeAt($authProvision['secret'], $authClock->time));
            $secondFactor = new SoSecurity\Auth\TotpSecondFactor($authMfa);
            $authSessions = new SoSecurity\Auth\SessionRegistry($store, $authProvider, $secondFactor, $authClock, 60, 300, 5);
            $flow = new SoSecurity\Auth\AuthenticationFlow($store, $authProvider, $authSessions, static function (): bool { return true; }, $secondFactor, $authClock);
            $login = $flow->password('form', 'auth-binding', 'auth-worker', 'auth-test-password');
            Check::same(1, parallelSuccesses($kind, $target, 'auth-flow', [(string) $authClock->time, $login->challenge(), $authCodes[0]]));
            Check::same(1, count($authSessions->all('form', 'auth-worker')));
            $authSessions->revokeAll('form', 'auth-worker'); $authMfa->revoke('form', 'auth-worker');
            echo "PASS $kind auth flow: 24 completions for one MFA login, exactly one full session created\n";
            $pending = $mfa->begin('form', 'confirmation', 'confirm@example.test');
            parse_str(parse_url($pending->provisioningUri(), PHP_URL_QUERY), $provision);
            Check::same(1, parallelSuccesses($kind, $target, 'mfa-confirm', [(string) $mfaClock->time, $pending->id(), $totp->codeAt($provision['secret'], $mfaClock->time)]));
            $pending = $mfa->begin('form', 'subject', 'subject@example.test');
            parse_str(parse_url($pending->provisioningUri(), PHP_URL_QUERY), $provision);
            $codes = $mfa->confirm('form', 'subject', $pending->id(), $totp->codeAt($provision['secret'], $mfaClock->time));
            $mfaClock->time += 30;
            Check::same(1, parallelSuccesses($kind, $target, 'mfa-code', [(string) $mfaClock->time, $totp->codeAt($provision['secret'], $mfaClock->time)]));
            $mfaClock->time += 60;
            Check::same(1, parallelSuccesses($kind, $target, 'mfa-recovery', [(string) $mfaClock->time, $codes[0]]));
            // Later suites reuse this isolated backend; remove this test's simulated-future records first.
            $mfa->revoke('form', 'confirmation'); $mfa->revoke('form', 'subject');
            echo "PASS $kind MFA: 24 concurrent confirmations, TOTP proofs and recovery-code consumptions; exactly one accepted per scenario\n";
        } else {
            echo "NOT RUN $kind encrypted MFA concurrency: ext-sodium required\n";
            if (getenv('SOSECURITY_REQUIRE_CRYPTO') === '1') { throw new RuntimeException('Required ext-sodium is missing.'); }
        }
        echo "PASS $kind: 24 competing processes per scenario; exactly 5 requests, 1 CSRF consume, 1 CAPTCHA consume accepted\n";
    }
    if (extension_loaded('gd') && extension_loaded('fileinfo')) {
        $web = privateDirectory(); $source = $directory . '/upload-source';
        try {
            $image = imagecreatetruecolor(2, 2); imagepng($image, $source);
            if (is_resource($image)) { imagedestroy($image); } unset($image);
            Check::same(24, parallelSuccesses('file', $directory, 'upload', [$source, $web]));
            $files = glob($directory . '/*.png'); Check::same(24, count($files));
            foreach ($files as $file) {
                Check::same(0600, fileperms($file) & 0777);
                Check::same('image/png', (new finfo(FILEINFO_MIME_TYPE))->file($file));
            }
            echo "PASS uploads: 24 concurrent exclusive random files, no overwrite, private permissions\n";
        } finally { cleanDirectory($web); }
    } else { echo "NOT RUN concurrent uploads: fileinfo and GD required\n"; }
    if (!$socket) { echo "NOT RUN Redis: set SOSECURITY_TEST_REDIS_SOCKET for an isolated instance\n"; }
    echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " concurrency assertions passed\n";
} finally { cleanDirectory($directory); }
