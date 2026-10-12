<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Storage\Change;
use SoSecurity\Storage\Codec;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Captcha\Captcha;
use SoSecurity\Captcha\ImageRenderer;
use SoSecurity\Captcha\Turnstile;
use SoSecurity\RateLimit\RateLimiter;
use SoSecurity\RateLimit\Policy;
use SoSecurity\Password\PasswordHasher;
use SoSecurity\Password\PasswordPolicy;
use SoSecurity\Password\ResetTokens;
use SoSecurity\Http\IpRules;
use SoSecurity\Http\ClientIp;
use SoSecurity\Http\Cookie;
use SoSecurity\Http\SecurityHeaders;
use SoSecurity\Output\Escaper;
use SoSecurity\Audit\AuditLogger;

$tests = [];
$tests['atomic store contract: memory and file'] = function () {
    $directory = privateDirectory();
    $clock = new TestClock();
    try {
        foreach ([new MemoryStore($clock), new FileStore($directory, 'contract', $clock)] as $store) {
            Check::same(null, $store->transact('a', function ($value) { return new Change(['n' => 1], 100001, $value); }));
            Check::same(['n' => 1], $store->transact('a', function ($value) { return new Change($value, 100001, $value); }));
            Check::throws(RuntimeException::class, function () use ($store) {
                $store->transact('a', function () { throw new RuntimeException('callback'); });
            });
            Check::same(['n' => 1], $store->transact('a', function ($value) { return new Change($value, 100001, $value); }));
            $clock->time = 100001;
            Check::same(null, $store->transact('a', function ($value) { return new Change(['n' => 2], 0, $value); }));
            $clock->time += 1000;
            Check::same(['n' => 2], $store->transact('a', function ($value) { return new Change(null, 0, $value); }));
            Check::same(null, $store->transact('a', function ($value) { return new Change(null, 0, $value); }));
            Check::throws(StorageException::class, function () use ($store) { $store->transact('a', function () { return true; }); });
            Check::throws(StorageException::class, function () use ($store) {
                $store->transact('a', function () { return new Change(['huge' => str_repeat('x', 65536)], 0, null); });
            });
            $clock->time = 100000;
        }
        $store = new FileStore($directory, 'contract', $clock);
        $other = new FileStore($directory, 'other', $clock);
        $store->transact('x', function () { return new Change(['secret' => 1], 100001, null); });
        Check::same(null, $other->transact('x', function ($value) { return new Change(null, 0, $value); }));
        Check::same(0, $store->prune());
        $clock->time++;
        Check::same(1, $store->prune());
        $store->transact('corrupt', function () { return new Change(['n' => 1], 0, null); });
        $path = $directory . '/' . hash('sha256', "contract\0corrupt") . '.json';
        file_put_contents($path, '{broken');
        Check::throws(StorageException::class, function () use ($store) { $store->transact('corrupt', function () { return new Change(null, 0, true); }); });
        unlink($path);
        symlink('/dev/null', $path);
        Check::throws(StorageException::class, function () use ($store) { $store->transact('corrupt', function () { return new Change(null, 0, true); }); });
        Check::throws(InvalidArgumentException::class, function () use ($store) { $store->transact('', function () {}); });
        Check::throws(StorageException::class, function () { new FileStore('/missing-sosecurity-directory', 'site'); });
        Check::throws(StorageException::class, function () { Codec::decode('{"expires":0,"value":false}', 0); });
    } finally { cleanDirectory($directory); }
};
$tests['CSRF binding, expiry, multi-tab, single-use, capacity'] = function () {
    $clock = new TestClock(); $store = new MemoryStore($clock); $csrf = new CsrfTokens($store, 30, 2, $clock);
    $a = $csrf->issue('form', 'session-a'); $b = $csrf->issue('form', 'session-a');
    Check::same(64, strlen($a)); Check::same(false, $a === $b);
    Check::same(true, $csrf->verify('form', 'session-a', $a));
    Check::same(true, $csrf->verify('form', 'session-a', $b));
    Check::same(false, $csrf->verify('other', 'session-a', $a));
    Check::same(false, $csrf->verify('form', 'session-b', $a));
    foreach ([null, [], 1, '', str_repeat('x', 100000), strtoupper($a), $a . "\n"] as $bad) {
        Check::same(false, $csrf->verify('form', 'session-a', $bad));
    }
    Check::same(true, $csrf->verify('form', 'session-a', $a, true));
    Check::same(false, $csrf->verify('form', 'session-a', $a, true));
    $clock->time += 30; Check::same(false, $csrf->verify('form', 'session-a', $b));
    $a = $csrf->issue('form', 'session-a'); $csrf->issue('form', 'session-a'); $csrf->issue('form', 'session-a');
    Check::same(false, $csrf->verify('form', 'session-a', $a));
    $a = $csrf->issue('form', 'session-a'); $csrf->revoke('form', 'session-a');
    Check::same(false, $csrf->verify('form', 'session-a', $a));
    Check::throws(InvalidArgumentException::class, function () use ($csrf) { $csrf->issue('form', ''); });
    Check::throws(InvalidArgumentException::class, function () use ($store) { new CsrfTokens($store, 0); });
    Check::throws(InvalidArgumentException::class, function () use ($store) { new CsrfTokens($store, 30, 65); });
};
$tests['CAPTCHA success, refresh, exhaustion, expiry and malformed input'] = function () {
    $clock = new TestClock(); $store = new MemoryStore($clock); $captcha = new Captcha($store, 20, 2, 2, $clock);
    $challenge = $captcha->arithmetic('login', 'a');
    preg_match('/^(\d+) \+ (\d+)/', $challenge->prompt, $parts); $answer = (string) ($parts[1] + $parts[2]);
    Check::same(false, $captcha->verify('login', 'b', $challenge->id, $answer));
    Check::same(false, $captcha->verify('comment', 'a', $challenge->id, $answer));
    Check::same(true, $captcha->verify('login', 'a', $challenge->id, $answer));
    Check::same(false, $captcha->verify('login', 'a', $challenge->id, $answer));
    $challenge = $captcha->arithmetic('login', 'a');
    Check::same(false, $captcha->verify('login', 'a', $challenge->id, []));
    Check::same(false, $captcha->verify('login', 'a', $challenge->id, '-1'));
    preg_match('/^(\d+) \+ (\d+)/', $challenge->prompt, $parts);
    Check::same(false, $captcha->verify('login', 'a', $challenge->id, (string) ($parts[1] + $parts[2])));
    $challenge = $captcha->arithmetic('login', 'a'); $clock->time += 20;
    Check::same(false, $captcha->verify('login', 'a', $challenge->id, '1'));
    $challenge = $captcha->arithmetic('login', 'a'); $captcha->revoke('login', 'a');
    Check::same(false, $captcha->verify('login', 'a', $challenge->id, '1'));
    $challenge = $captcha->arithmetic('login', 'a'); $captcha->arithmetic('login', 'a'); $captcha->arithmetic('login', 'a');
    Check::same(false, $captcha->verify('login', 'a', $challenge->id, '1'));
    Check::same(false, $captcha->verify('login', 'a', [], '1'));
    Check::throws(InvalidArgumentException::class, function () use ($captcha) { $captcha->image('x', 'a', null, 3); });
    Check::throws(InvalidArgumentException::class, function () use ($captcha) { $captcha->image('x', 'a', null, 5, 'AAAAAAAA'); });
    Check::throws(InvalidArgumentException::class, function () { new ImageRenderer(1); });
    Check::throws(InvalidArgumentException::class, function () use ($store) { new Captcha($store, 30, 0); });
};
$tests['PNG CAPTCHA contains image bytes but no answer API'] = function () {
    if (!extension_loaded('gd')) { throw new RuntimeException('This integration test requires ext-gd.'); }
    $challenge = (new Captcha(new MemoryStore()))->image('form', 'a');
    Check::same("\x89PNG\r\n\x1a\n", substr($challenge->image, 0, 8));
    Check::same([180, 60], array_slice(getimagesizefromstring($challenge->image), 0, 2));
    Check::same('', $challenge->prompt); Check::same(false, property_exists($challenge, 'answer'));
    Check::throws(InvalidArgumentException::class, function () { (new ImageRenderer(100))->render('ABCDEFGH'); });
};
$tests['Turnstile exact hostname/action and service failure'] = function () {
    $body = '{"success":true,"hostname":"example.com","action":"login"}'; $calls = 0;
    $provider = new Turnstile(str_repeat('s', 32), 'example.com', 'login', function ($payload) use (&$body, &$calls) {
        $calls++; Check::same('token', $payload['response']); return $body;
    });
    Check::same(true, $provider->verify('token', '203.0.113.2'));
    $body = '{"success":true,"hostname":"evil.com","action":"login"}'; Check::same(false, $provider->verify('token'));
    $body = '{"success":true,"hostname":"example.com","action":"register"}'; Check::same(false, $provider->verify('token'));
    $body = '{"success":false}'; Check::same(false, $provider->verify('token'));
    $body = '{"success":1}'; Check::throws(RuntimeException::class, function () use ($provider) { $provider->verify('token'); });
    $body = '{broken'; Check::throws(RuntimeException::class, function () use ($provider) { $provider->verify('token'); });
    foreach ([null, [], str_repeat('x', 2049), "a\nb"] as $bad) { Check::same(false, $provider->verify($bad)); }
    Check::same(6, $calls);
    Check::throws(InvalidArgumentException::class, function () use ($provider) { $provider->verify('token', 'forged'); });
    $provider = new Turnstile(str_repeat('s', 32), 'example.com', 'login', function () { throw new RuntimeException('network'); });
    Check::throws(RuntimeException::class, function () use ($provider) { $provider->verify('token'); });
};
$tests['rate limits, ladder, history reset, windows and manual bans'] = function () {
    $clock = new TestClock(); $store = new MemoryStore($clock); $rate = new RateLimiter($store, new Policy(2, 10, [5, 20], 30), $clock);
    Check::same(2, $rate->inspect('login', 'a')->remaining);
    Check::same(true, $rate->consume('login', 'a')->allowed);
    Check::same(0, $rate->consume('login', 'a')->remaining);
    Check::same(false, $rate->inspect('login', 'a')->allowed);
    $d = $rate->consume('login', 'a'); Check::same(false, $d->allowed); Check::same(5, $d->retryAfter);
    Check::same(true, $rate->consume('login', 'b')->allowed); Check::same(true, $rate->consume('other', 'a')->allowed);
    $clock->time += 4; Check::same(1, $rate->consume('login', 'a')->retryAfter);
    $clock->time++; Check::same(true, $rate->consume('login', 'a')->allowed); $rate->consume('login', 'a');
    Check::same(20, $rate->consume('login', 'a')->retryAfter);
    $clock->time += 30; Check::same(true, $rate->consume('login', 'a')->allowed); $rate->consume('login', 'a');
    Check::same(5, $rate->consume('login', 'a')->retryAfter);
    $rate->reset('login', 'a'); Check::same(2, $rate->inspect('login', 'a')->remaining);
    $rate->ban('login', 'a'); Check::same(true, $rate->consume('login', 'a')->permanent);
    $clock->time += 100000; Check::same(false, $rate->consume('login', 'a')->allowed);
    $rate->reset('login', 'a'); $rate->ban('login', 'a', 3); $clock->time += 3;
    Check::same(true, $rate->consume('login', 'a')->allowed);
    $clock->time += 10; Check::same(2, $rate->inspect('login', 'a')->remaining);
    Check::throws(InvalidArgumentException::class, function () { new Policy(0); });
    Check::throws(InvalidArgumentException::class, function () { new Policy(1, 20, [30], 10); });
};
$tests['store failures never allow sensitive operations'] = function () {
    $store = new class implements SoSecurity\Storage\AtomicStore {
        public function transact(string $key, callable $callback) { throw new StorageException('offline'); }
    };
    Check::throws(StorageException::class, function () use ($store) { (new RateLimiter($store))->consume('login', 'a'); });
    Check::throws(StorageException::class, function () use ($store) { (new CsrfTokens($store))->verify('form', 'a', str_repeat('a', 64)); });
    Check::throws(StorageException::class, function () use ($store) { (new Captcha($store))->verify('form', 'a', str_repeat('a', 32), '1'); });
};
$tests['malformed module records fail closed'] = function () {
    $store = new class implements SoSecurity\Storage\AtomicStore {
        public function transact(string $key, callable $callback) { return $callback(['unexpected' => '999999'])->result(); }
    };
    Check::throws(StorageException::class, function () use ($store) { (new CsrfTokens($store))->verify('form', 'a', str_repeat('a', 64)); });
    Check::throws(StorageException::class, function () use ($store) { (new CsrfTokens($store))->issue('form', 'a'); });
    Check::throws(StorageException::class, function () use ($store) { (new Captcha($store))->verify('form', 'a', str_repeat('a', 32), '1'); });
    Check::throws(StorageException::class, function () use ($store) { (new Captcha($store))->arithmetic('form', 'a'); });
    Check::throws(StorageException::class, function () use ($store) { (new RateLimiter($store))->consume('login', 'a'); });
};
$tests['password native hash, upgrades, legacy boundaries and byte limits'] = function () {
    $hasher = new PasswordHasher('bcrypt', ['cost' => 10]); $password = 'correct horse battery staple'; $hash = $hasher->hash($password);
    Check::same(true, $hasher->verify($password, $hash)); Check::same(false, $hasher->verify('wrong', $hash));
    Check::same(false, $hasher->needsRehash($hash)); Check::same(true, (new PasswordHasher())->needsRehash($hash));
    Check::same(false, $hasher->needsRehash(password_hash($password, PASSWORD_BCRYPT, ['cost' => 11])));
    Check::same(null, $hasher->verifyAndUpgrade($password, $hash)->replacementHash);
    $result = $hasher->verifyAndUpgrade('old password', md5('old password'), function ($password, $stored) {
        return hash_equals($stored, md5($password));
    });
    Check::same(true, $result->valid); Check::same(true, $hasher->verify('old password', $result->replacementHash));
    Check::same(false, $hasher->verifyAndUpgrade('wrong', $hash, function () { return true; })->valid);
    Check::same(false, $hasher->verifyAndUpgrade('wrong', 'legacy', function () { return 1; })->valid);
    Check::throws(InvalidArgumentException::class, function () use ($hasher) { $hasher->hash(str_repeat('x', 73)); });
    Check::throws(InvalidArgumentException::class, function () use ($hasher) { $hasher->hash("a\0b"); });
    Check::same(false, $hasher->verify(str_repeat('x', 73), $hasher->hash(str_repeat('x', 72))));
    Check::same(false, $hasher->verify('', $hash)); Check::same(false, $hasher->verify("a\0b", $hash));
    Check::same(false, $hasher->needsRehash('$argon2id$unavailable'));
    if (defined('PASSWORD_ARGON2ID')) {
        $argon = new PasswordHasher('argon2id'); $hash = $argon->hash($password);
        Check::same(true, $argon->verify($password, $hash)); Check::same(false, $hasher->needsRehash($hash));
        Check::same(null, $hasher->verifyAndUpgrade($password, $hash)->replacementHash);
    } else { Check::throws(InvalidArgumentException::class, function () { new PasswordHasher('argon2id'); }); }
    Check::throws(InvalidArgumentException::class, function () { new PasswordHasher('bcrypt', ['cost' => 1]); });
};
$tests['password policy Unicode, breach callback and reset tokens'] = function () {
    $policy = new PasswordPolicy();
    Check::same(['password.too_short'], $policy->errors('short'));
    Check::same([], $policy->errors(str_repeat('中', 15)));
    Check::same(['password.encoding'], $policy->errors("invalid\xff"));
    Check::same(['password.too_long'], $policy->errors(str_repeat('a', 73)));
    Check::same(['password.compromised'], $policy->errors(str_repeat('a', 15), function () { return true; }));
    Check::throws(RuntimeException::class, function () use ($policy) { $policy->errors(str_repeat('a', 15), function () { return null; }); });
    $clock = new TestClock(); $reset = new ResetTokens(new MemoryStore($clock), 30, $clock);
    $token = $reset->issue('account:version'); Check::same(false, $reset->consume('account:other-version', $token));
    Check::same(true, $reset->consume('account:version', $token)); Check::same(false, $reset->consume('account:version', $token));
    $token = $reset->issue('account:version'); $reset->revoke('account:version'); Check::same(false, $reset->consume('account:version', $token));
};
$tests['IPv4/IPv6 CIDR and trusted proxy anti-spoofing'] = function () {
    $rules = new IpRules(['10.0.0.0/8', '2001:db8::/32', '192.0.2.1']);
    foreach (['10.1.2.3', '2001:db8::123', '192.0.2.1'] as $ip) { Check::same(true, $rules->contains($ip)); }
    foreach (['11.1.2.3', '2001:db9::123', '192.0.2.2', 'bad'] as $ip) { Check::same(false, $rules->contains($ip)); }
    Check::same(true, (new IpRules(['0.0.0.0/0']))->contains('203.0.113.1'));
    Check::same(false, (new IpRules(['::/0']))->contains('127.0.0.1'));
    foreach (['bad', '10.0.0.0/33', '::/129', '10.0.0.0/-1', '10.0.0.0/8/x'] as $rule) {
        Check::throws(InvalidArgumentException::class, function () use ($rule) { new IpRules([$rule]); });
    }
    $resolver = new ClientIp(new IpRules(['10.0.0.0/8']));
    Check::same('203.0.113.1', $resolver->resolve(['REMOTE_ADDR' => '203.0.113.1', 'HTTP_X_FORWARDED_FOR' => '1.1.1.1']));
    Check::same('203.0.113.2', $resolver->resolve(['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '1.1.1.1, 203.0.113.2, 10.0.0.2']));
    Check::same('2001:db8::1', (new ClientIp())->resolve(['REMOTE_ADDR' => '2001:0db8:0:0::1']));
    Check::throws(InvalidArgumentException::class, function () use ($resolver) { $resolver->resolve(['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => 'bad']); });
    Check::throws(InvalidArgumentException::class, function () use ($resolver) { $resolver->resolve([]); });
};
$tests['safe output, cookies and opt-in headers'] = function () {
    Check::same('&lt;&quot;&#039;&amp;&gt;', Escaper::html('<"\'&>'));
    Check::same('&amp;lt;', Escaper::html('&lt;'));
    Check::same(false, strpos(Escaper::json('</script>'), '<'));
    Check::same('%2F%3F%26', Escaper::urlComponent('/?&'));
    Check::throws(InvalidArgumentException::class, function () { Escaper::json("\xff"); });
    $cookie = Cookie::header('__Host-session', "a\r\nb");
    Check::same(true, strpos($cookie, 'Secure') !== false); Check::same(true, strpos($cookie, 'HttpOnly') !== false);
    Check::same(false, strpos($cookie, "\r") !== false);
    Check::same(true, strpos(Cookie::header('session', '', '/', true, true, 'Lax', 0), 'Max-Age=0') !== false);
    Check::throws(InvalidArgumentException::class, function () { Cookie::header("bad\r\n", 'v'); });
    Check::throws(InvalidArgumentException::class, function () { Cookie::header('name', 'v', '/; Domain=evil'); });
    Check::throws(InvalidArgumentException::class, function () { Cookie::header('__Host-session', 'v', '/app'); });
    Check::throws(InvalidArgumentException::class, function () { Cookie::header('name', 'v', '/', false, true, 'None'); });
    $headers = SecurityHeaders::build(); Check::same(false, isset($headers['Strict-Transport-Security']));
    $headers = SecurityHeaders::build("default-src 'self'"); Check::same(true, isset($headers['Content-Security-Policy-Report-Only']));
    Check::same('max-age=300', SecurityHeaders::build(null, true, 300)['Strict-Transport-Security']);
    Check::throws(InvalidArgumentException::class, function () { SecurityHeaders::build("x\r\nInjected: 1"); });
};
$tests['audit drops secrets and rejects log injection'] = function () {
    $events = []; $logger = new AuditLogger(function ($event) use (&$events) { $events[] = $event; }, str_repeat('k', 32));
    $logger->record('login.failed', 'login', 'user@example.com', ['password' => 'SECRET', 'token' => 'TOKEN', 'allowed' => false, 'status' => 401]);
    Check::same(false, strpos(json_encode($events), 'SECRET') !== false);
    Check::same(false, strpos(json_encode($events), 'TOKEN') !== false);
    Check::same(false, strpos(json_encode($events), 'user@example.com') !== false);
    Check::same(['allowed' => false, 'status' => 401], $events[0]['context']);
    Check::throws(InvalidArgumentException::class, function () use ($logger) { $logger->record("login\nforged", 'login'); });
    Check::throws(InvalidArgumentException::class, function () use ($logger) { $logger->record('login.failed', "scope\r\n"); });
};

$failed = 0;
foreach ($tests as $name => $test) {
    try { $test(); echo "PASS $name\n"; }
    catch (Throwable $e) { ++$failed; fwrite(STDERR, "FAIL $name: " . $e->getMessage() . "\n" . $e->getTraceAsString() . "\n"); }
}
echo 'PHP ' . PHP_VERSION . ': ' . count($tests) . ' suites, ' . Check::$assertions . " assertions, $failed failures\n";
exit($failed ? 1 : 0);
