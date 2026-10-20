<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\IdentityState;
use SoSecurity\Auth\RememberCodec;
use SoSecurity\Auth\RememberedLogin;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;

// Authority is explicit test data; real native password/TOTP and browser adapters have separate tests.
$directory = privateDirectory();
$keys = new HmacKeys('old', ['old' => str_repeat('a', 32)]);
$nextKeys = new HmacKeys('next', ['old' => str_repeat('a', 32), 'next' => str_repeat('b', 32)]);
try {
    foreach (['memory', 'file'] as $backend) {
        $clock = new TestClock(); $store = $backend === 'memory' ? new MemoryStore($clock) : new FileStore($directory, 'remember', $clock);
        $account = new Account('tenant', 'subject', '1'); $offline = false; $guardAllowed = true; $guardCalls = [];
        $lookup = function (string $scope, string $subject) use (&$account, &$offline): ?Account {
            if ($offline) { throw new SecurityException('Test identity source unavailable.', 'auth.test_offline'); }
            return $scope === 'tenant' && $subject === 'subject' ? $account : null;
        };
        $provider = new CallbackIdentityProvider(function (string $scope, string $identifier, string $password) use ($lookup): ?Account {
            return $identifier === 'user' && $password === 'test-password' ? $lookup($scope, 'subject') : null;
        }, $lookup);
        $guard = function (string $phase, string $scope) use (&$guardAllowed, &$guardCalls): bool { $guardCalls[] = [$phase, $scope]; return $guardAllowed; };
        $sessions = new SessionRegistry($store, $provider, null, $clock, 10, 100, 4);
        $flow = new AuthenticationFlow($store, $provider, $sessions, $guard, null, $clock);
        $remember = new RememberedLogin($store, $provider, $sessions, $keys, $guard, null, $clock, 300, 2, 20, 5);
        $login = function () use ($flow) { return $flow->password('tenant', 'browser', 'user', 'test-password')->credential(); };
        $key = Guard::key('auth-sessions', 'tenant', 'subject');
        $first = $login(); $originalEpoch = $sessions->epoch('tenant', 'subject');
        $credential = $remember->issue('tenant', 'subject', $first->token(), 'Laptop');
        Check::same(100300, $credential->expiresAt()); Check::same(32, strlen($credential->id()));
        $header = $remember->cookieHeader($credential);
        foreach (['__Host-SoSecurityRemember=', 'Path=/', 'Secure', 'HttpOnly', 'SameSite=Lax', 'Max-Age=300'] as $part) { Check::same(true, strpos($header, $part) !== false); }
        Check::same(true, strpos($remember->clearCookieHeader(), 'Max-Age=0') !== false);
        Check::throws(ConfigurationException::class, function () use ($remember, $credential) { $remember->cookieHeader($credential, '__Host-Test', false); });
        Check::throws(ConfigurationException::class, function () use ($remember, $credential) { $remember->cookieHeader($credential, '__Host-Test', true, '/other'); });
        Check::same(true, strpos($remember->cookieHeader($credential, 'LocalOnly', false), 'Secure') === false);
        Check::throws(ConfigurationException::class, function () use ($credential) { serialize($credential); });
        Check::throws(ConfigurationException::class, function () use ($remember) { serialize($remember); });
        ob_start(); var_dump($credential); $dump = ob_get_clean(); Check::same(false, strpos($dump, $credential->token()) !== false);
        $raw = $store->transact($key, function ($state) { return new Change($state, 0, json_encode($state)); });
        Check::same(false, strpos($raw, $credential->token()) !== false);
        Check::same(false, isset($remember->all('tenant', 'subject')[0]['digest']));
        Check::same('Laptop', $remember->all('tenant', 'subject')[0]['label']);
        // Invalid MAC/scope/secret must not revoke an innocent user's valid grant.
        Check::same('invalid', $remember->resume('other', $credential->token())->status());
        Check::same('invalid', $remember->resume('tenant', substr($credential->token(), 0, -1) . 'Z')->status());
        foreach ([null, [], '', str_repeat('x', 211)] as $invalid) { Check::same('invalid', $remember->resume('tenant', $invalid)->status()); }
        $codec = new RememberCodec($keys);
        $wrongDigest = $codec->issue('tenant', $credential->id(), 0, str_repeat('c', 64));
        Check::same('invalid', $remember->resume('tenant', $wrongDigest)->status()); Check::same(1, count($remember->all('tenant', 'subject')));
        $guardAllowed = false;
        Check::throws(SecurityException::class, function () use ($remember, $credential) { $remember->resume('tenant', $credential->token()); });
        Check::throws(SecurityException::class, function () use ($remember, $first) { $remember->issue('tenant', 'subject', $first->token()); });
        Check::throws(SecurityException::class, function () use ($remember) { $remember->all('tenant', 'subject'); });
        Check::throws(SecurityException::class, function () use ($remember, $credential) { $remember->revoke('tenant', 'subject', $credential->id()); }); $guardAllowed = true;
        $offline = true; Check::throws(SecurityException::class, function () use ($remember, $credential) { $remember->resume('tenant', $credential->token()); }); $offline = false;
        $clock->time += 11; Check::same(null, $sessions->verify('tenant', 'subject', $first->token()));
        $restored = $remember->resume('tenant', $credential->token()); Check::same('authenticated', $restored->status());
        Check::same($first->id(), $restored->session()->id()); Check::same(100111, $restored->session()->expiresAt());
        Check::same($credential->expiresAt(), $restored->nextCredential()->expiresAt());
        Check::same(false, $credential->token() === $restored->nextCredential()->token());
        Check::same(null, $sessions->verify('tenant', 'subject', $first->token()));
        $verified = $sessions->verify('tenant', 'subject', $restored->session()->token());
        Check::same(true, $verified->resumed()); Check::same('password', $verified->method()); Check::same(100000, $verified->authenticatedAt());
        Check::same(false, $verified->recent(3600, $clock->time, 1));
        Check::same(null, $remember->issue('tenant', 'subject', $restored->session()->token()));
        Check::same('retry', $remember->resume('tenant', $credential->token())->status());
        Check::same(1, count($sessions->all('tenant', 'subject'))); Check::same($originalEpoch, $sessions->epoch('tenant', 'subject'));
        Check::throws(ConfigurationException::class, function () use ($restored) { serialize($restored); });
        // Genuine reauthentication changes only session freshness, retaining the absolute deadline.
        $fresh = $flow->password('tenant', 'browser', 'user', 'test-password', '', $restored->session()->token())->credential();
        Check::same($restored->session()->expiresAt(), $fresh->expiresAt());
        $verified = $sessions->verify('tenant', 'subject', $fresh->token()); Check::same(false, $verified->resumed()); Check::same(true, $verified->recent(20, $clock->time, 1));
        // Rotation under a new signing key accepts the retained old key; dropping it fails closed.
        $rotating = new RememberedLogin($store, $provider, $sessions, $nextKeys, $guard, null, $clock, 300, 2, 20, 5);
        $new = $rotating->resume('tenant', $restored->nextCredential()->token()); Check::same('authenticated', $new->status());
        Check::same(true, strpos($new->nextCredential()->token(), 'sorp1.next.') === 0);
        Check::same('invalid', $remember->resume('tenant', $new->nextCredential()->token())->status());
        // Expired grace detects a genuine old credential and revokes every device plus in-flight login epochs.
        $second = $login(); $secondGrant = $remember->issue('tenant', 'subject', $second->token());
        $clock->time += 5;
        Check::same('replayed', $remember->resume('tenant', $credential->token())->status());
        Check::same([], $sessions->all('tenant', 'subject')); Check::same([], $remember->all('tenant', 'subject'));
        Check::same('invalid', $remember->resume('tenant', $secondGrant->token())->status());
        Check::same(false, $originalEpoch === $sessions->epoch('tenant', 'subject'));
        Check::same(null, $sessions->register('tenant', 'subject', (new IdentityState($provider, null))->load('tenant', 'subject')['fingerprint'], $originalEpoch));
        // Replacement, per-device revoke, session revoke and global revoke cover both credential types.
        $first = $login(); $one = $remember->issue('tenant', 'subject', $first->token()); $two = $remember->issue('tenant', 'subject', $first->token());
        Check::same(1, count($remember->all('tenant', 'subject'))); Check::same('invalid', $remember->resume('tenant', $one->token())->status());
        Check::same(true, $remember->revoke('tenant', 'subject', $two->id())); Check::same(false, $remember->revoke('tenant', 'subject', $two->id()));
        Check::same(null, $sessions->verify('tenant', 'subject', $first->token()));
        $first = $login(); $one = $remember->issue('tenant', 'subject', $first->token()); $clock->time += 11;
        Check::same([], $sessions->all('tenant', 'subject')); Check::same(true, $sessions->revoke('tenant', 'subject', $first->id()));
        Check::same('invalid', $remember->resume('tenant', $one->token())->status());
        $first = $login(); $one = $remember->issue('tenant', 'subject', $first->token()); $sessions->revokeAll('tenant', 'subject');
        Check::same('invalid', $remember->resume('tenant', $one->token())->status());
        // Password, role, factor-policy and enabled-status authority changes invalidate old persistence.
        foreach ([new Account('tenant', 'subject', '2'), new Account('tenant', 'subject', '2', true, ['admin']), null] as $changed) {
            $first = $login(); $one = $remember->issue('tenant', 'subject', $first->token()); $before = $account; $account = $changed;
            Check::same('invalid', $remember->resume('tenant', $one->token())->status()); Check::same([], $remember->all('tenant', 'subject')); $account = $before;
        }
        // Capacity and recent-proof requirements, including strict boundary.
        $sessions->revokeAll('tenant', 'subject');
        $oneSession = $login(); $one = $remember->issue('tenant', 'subject', $oneSession->token());
        $twoSession = $login(); $two = $remember->issue('tenant', 'subject', $twoSession->token()); $threeSession = $login();
        Check::throws(SecurityException::class, function () use ($remember, $threeSession) { $remember->issue('tenant', 'subject', $threeSession->token()); });
        Check::same(2, count($remember->all('tenant', 'subject')));
        $clock->time += 20; Check::same(null, $remember->issue('tenant', 'subject', $threeSession->token()));
        // Fixed lifetime does not slide across repeated restoration; expiration removes dependent sessions.
        $last = $one;
        for ($i = 0; $i < 3; ++$i) { $clock->time += 80; $outcome = $remember->resume('tenant', $last->token()); Check::same('authenticated', $outcome->status()); $last = $outcome->nextCredential(); Check::same($one->expiresAt(), $last->expiresAt()); }
        $clock->time = $one->expiresAt() - 1; $outcome = $remember->resume('tenant', $last->token()); Check::same('authenticated', $outcome->status());
        Check::same($one->expiresAt(), $outcome->session()->expiresAt()); $clock->time++;
        Check::same('invalid', $remember->resume('tenant', $outcome->nextCredential()->token())->status()); Check::same([], $sessions->all('tenant', 'subject'));
        // A v1 ledger is strictly migrated in place. Unsupported/corrupt state is never silently reset.
        $legacySession = $login();
        $store->transact($key, function ($state) { $state['v'] = 1; unset($state['remember']); foreach ($state['sessions'] as &$row) { unset($row['resumed'], $row['grant']); } unset($row); return new Change($state, 0, null); });
        Check::same(false, $sessions->verify('tenant', 'subject', $legacySession->token())->resumed());
        Check::same(2, $store->transact($key, function ($state) { return new Change($state, 0, $state['v']); }));
        $store->transact($key, function ($state) { $state['unexpected'] = true; return new Change($state, 0, null); });
        Check::throws(StorageException::class, function () use ($sessions) { $sessions->all('tenant', 'subject'); });
        $store->transact($key, function () { return new Change(null, 0, null); });
        echo "PASS $backend persistent login: fixed lifetime, signed rotation/replay, grace, freshness, revocation, authority and v1 migration\n";
    }
} finally { cleanDirectory($directory); }

// Configuration/factory uses explicit shared storage, authority, request protection and separate HMAC keys.
$config = ['site' => 'remember-test', 'storage' => ['driver' => 'memory'],
    'authentication' => ['identity_provider' => 'identity', 'request_guard' => 'guard'], 'remember' => ['keys' => 'remember_keys']];
$security = SoSecurity\Security::fromArray($config, ['identity' => $provider, 'guard' => $guard, 'remember_keys' => $keys], $clock);
Check::throws(ConfigurationException::class, function () use ($security) { $security->rememberedLogin(); }); // Memory is intentionally not a shared deployment backend.
foreach ([['capacity' => 17], ['ttl' => 0], ['fresh_age' => 0], ['concurrency_grace' => 11], ['secure' => '1'], ['secure' => false], ['path' => '/nested'], ['unknown' => true]] as $bad) {
    Check::throws(ConfigurationException::class, function () use ($config, $bad) { $config['remember'] = $bad + $config['remember']; SoSecurity\Security::fromArray($config); });
}
Check::throws(ConfigurationException::class, function () { SoSecurity\Security::fromArray(['site' => 'x', 'remember' => ['keys' => 'k']]); });

// Retry the same callback before committing, then inject backend failure at the ledger write.
final class RememberRetryStore implements AtomicStore
{
    public $fail = false;
    public $skip = 0;
    public $calls = 0;
    private $inner;
    public function __construct(AtomicStore $inner) { $this->inner = $inner; }
    public function transact(string $key, callable $callback)
    {
        ++$this->calls;
        if ($this->fail && strpos($key, 'auth-sessions:') === 0 && $this->skip-- <= 0) { throw new StorageException('Test ledger fault.', 'storage.test_fault'); }
        return $this->inner->transact($key, static function ($state) use ($callback) {
            $first = $callback($state); $last = $callback($state);
            Check::same($first->value(), $last->value()); Check::same($first->expiresAt(), $last->expiresAt());
            Check::same(rememberComparableResult($first->result()), rememberComparableResult($last->result()));
            return $last;
        });
    }
}
function rememberComparableResult($result)
{
    if($result instanceof \SoSecurity\Auth\SessionCredential){return ['session',$result->token(),$result->id(),$result->expiresAt()];}
    if($result instanceof \SoSecurity\Auth\RememberCredential){return ['remember',$result->token(),$result->id(),$result->expiresAt()];}
    if($result instanceof \SoSecurity\Auth\RememberResult){return ['outcome',$result->status(),rememberComparableResult($result->session()),rememberComparableResult($result->nextCredential()),$result->account()];}
    return $result;
}
$clock = new TestClock(); $store = new RememberRetryStore(new MemoryStore($clock)); $account = new Account('tenant', 'subject', '1');
$provider = new CallbackIdentityProvider(function () use ($account) { return $account; }, function () use ($account) { return $account; });
$guard = static function (): bool { return true; };
$sessions = new SessionRegistry($store, $provider, null, $clock, 100, 1000);
$flow = new AuthenticationFlow($store, $provider, $sessions, $guard, null, $clock);
$remember = new RememberedLogin($store, $provider, $sessions, $keys, $guard, null, $clock, 300, 8, 20, 5);
$first = $flow->password('tenant', 'browser', 'user', 'test-password')->credential();
$store->fail = true; $store->skip = 1; // verify succeeds, locator allocated, ledger commit fails.
Check::throws(StorageException::class, function () use ($remember, $first) { $remember->issue('tenant', 'subject', $first->token()); });
$store->fail = false; Check::same([], $remember->all('tenant', 'subject'));
$one = $remember->issue('tenant', 'subject', $first->token());
$store->fail = true; $store->skip = 0;
Check::throws(StorageException::class, function () use ($remember, $one) { $remember->resume('tenant', $one->token()); });
$store->fail = false; $last = $remember->resume('tenant', $one->token()); Check::same('authenticated', $last->status());
// Many rotations keep both state and concurrent history bounded.
for ($i = 0; $i < 15; ++$i) { $last = $remember->resume('tenant', $last->nextCredential()->token()); Check::same('authenticated', $last->status()); }
Check::same(8, $store->transact(Guard::key('auth-sessions', 'tenant', 'subject'), function ($state) use ($one) { return new Change($state, 0, count($state['remember'][$one->id()]['recent'])); }));
Check::same(false, $remember->forget('tenant', str_repeat('bad', 30))); Check::same(true, $remember->forget('tenant', $one->token()));
Check::same([], $sessions->all('tenant', 'subject')); Check::same(false, $remember->forget('tenant', $one->token()));
// Tight grant expiry detaches an independently fresh session, but kills a dependent restored one.
$short = new RememberedLogin($store, $provider, $sessions, $keys, $guard, null, $clock, 10);
$first = $flow->password('tenant', 'browser', 'user', 'test-password')->credential(); $short->issue('tenant', 'subject', $first->token()); $clock->time += 10;
Check::same(false, $sessions->verify('tenant', 'subject', $first->token())->resumed()); Check::same([], $short->all('tenant', 'subject'));
$sessions->revokeAll('tenant', 'subject');
$first = $flow->password('tenant', 'browser', 'user', 'test-password')->credential(); $one = $remember->issue('tenant', 'subject', $first->token());
$raw = $store->transact(Guard::key('auth-sessions', 'tenant', 'subject'), function ($state) { return new Change($state, 0, $state); });
foreach (['generation' => -1, 'rotated' => $clock->time + 1, 'expires' => $clock->time, 'recent' => [['generation' => 0, 'until' => $clock->time + 6]], 'epoch' => str_repeat('f', 64)] as $field => $bad) {
    $store->transact(Guard::key('auth-sessions', 'tenant', 'subject'), function () use ($raw, $one, $field, $bad) { $state = $raw; $state['remember'][$one->id()][$field] = $bad; return new Change($state, 0, null); });
    Check::throws(StorageException::class, function () use ($remember) { $remember->all('tenant', 'subject'); });
}
$store->transact(Guard::key('auth-sessions', 'tenant', 'subject'), function () use ($raw) { return new Change($raw, 0, null); });
// Outdated clocks and corrupt locators refuse to reset authority.
$clock->time--;
Check::throws(SecurityException::class, function () use ($remember) { $remember->all('tenant', 'subject'); }); $clock->time++;
$store->transact(Guard::key('auth-remember-index', 'tenant', $one->id()), function ($state) { $state['subject'] = []; return new Change($state, $state['expires'], null); });
Check::throws(StorageException::class, function () use ($remember, $one) { $remember->resume('tenant', $one->token()); });

// Use the genuine encrypted factor authority, not a simulated proof, for persistent MFA provenance.
if (extension_loaded('sodium')) {
    $clock = new TestClock(); $store = new MemoryStore($clock);
    $account = new Account('tenant', 'subject', '1', true, [], true);
    $provider = new CallbackIdentityProvider(function () use ($account) { return $account; }, function () use ($account) { return $account; });
    $factors = new SoSecurity\Mfa\TotpFactors($store, new SoSecurity\Crypto\Cipher('test', ['test' => str_repeat('m', 32)], 'remember-tests'), 'Test', $clock);
    $pending = $factors->begin('tenant', 'subject', 'test@example.test'); parse_str(parse_url($pending->provisioningUri(), PHP_URL_QUERY), $uri);
    $codes = $factors->confirm('tenant', 'subject', $pending->id(), (new SoSecurity\Mfa\Totp())->codeAt($uri['secret'], $clock->time));
    $factor = new SoSecurity\Auth\TotpSecondFactor($factors); $sessions = new SessionRegistry($store, $provider, $factor, $clock);
    $flow = new AuthenticationFlow($store, $provider, $sessions, $guard, $factor, $clock);
    $remember = new RememberedLogin($store, $provider, $sessions, $keys, $guard, $factor, $clock);
    $pendingLogin = $flow->password('tenant', 'browser', 'user', 'test-password');
    $first = $flow->secondFactor('tenant', 'browser', $pendingLogin->challenge(), ['type' => 'recovery', 'code' => $codes[0]])->credential();
    $one = $remember->issue('tenant', 'subject', $first->token()); $restored = $remember->resume('tenant', $one->token());
    Check::same('authenticated', $restored->status()); $verified = $sessions->verify('tenant', 'subject', $restored->session()->token());
    Check::same('recovery', $verified->method()); Check::same(2, $verified->strength()); Check::same(false, $verified->recent(100, $clock->time));
    $factors->revoke('tenant', 'subject'); Check::same('invalid', $remember->resume('tenant', $restored->nextCredential()->token())->status());
} else {
    echo "NOT RUN encrypted persistent-MFA provenance: ext-sodium required\n";
    if (getenv('SOSECURITY_REQUIRE_CRYPTO') === '1') { throw new RuntimeException('Required sodium unavailable.'); }
}
$directory = privateDirectory();
try {
    $clock = new TestClock(); $factoryAccount = new Account('tenant', 'subject', '1');
    $factoryProvider = new CallbackIdentityProvider(function () use ($factoryAccount) { return $factoryAccount; }, function () use ($factoryAccount) { return $factoryAccount; });
    $config['storage'] = ['driver' => 'file', 'directory' => $directory];
    $security = SoSecurity\Security::fromArray($config, ['identity' => $factoryProvider, 'guard' => $guard, 'remember_keys' => $keys], $clock);
    $session = $security->authentication()->password('tenant', 'browser', 'user', 'test-password')->credential();
    $grant = $security->rememberedLogin()->issue('tenant', 'subject', $session->token());
    Check::same(true, strpos($security->rememberCookieHeader($grant), '__Host-SoSecurityRemember=') === 0);
    Check::same(true, strpos($security->clearRememberCookieHeader(), 'Max-Age=0') !== false);
    Check::same('authenticated', $security->rememberedLogin()->resume('tenant', $grant->token())->status());
    Check::same(1, count($security->sessions()->all('tenant', 'subject')));
    foreach (['remember_keys', 'guard', 'identity'] as $missing) {
        $services = ['identity' => $factoryProvider, 'guard' => $guard, 'remember_keys' => $keys]; unset($services[$missing]);
        Check::throws(ConfigurationException::class, function () use ($config, $services, $clock) { SoSecurity\Security::fromArray($config, $services, $clock)->rememberedLogin(); });
    }
} finally { cleanDirectory($directory); }
echo 'PASS persistent login: ' . Check::$assertions . ' assertions on PHP ' . PHP_VERSION . "\n";
