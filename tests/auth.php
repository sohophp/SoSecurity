<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\IdentityState;
use SoSecurity\Auth\PasswordIdentityProvider;
use SoSecurity\Auth\PasswordRecord;
use SoSecurity\Auth\SecondFactor;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;

// Explicit simulated second-factor authority: this checks flow semantics, not WebAuthn/TOTP implementation.
final class AuthTestFactor implements SecondFactor
{
    public $generation = 'generation-1';
    public $calls = 0;
    public $onVerify;
    public $fail = false;
    private $used = [];
    public function binding(string $scope, string $subject): ?string { return $this->generation; }
    public function verify(string $scope, string $subject, string $expectedBinding, $proof): ?string
    {
        ++$this->calls;
        if ($this->fail) { throw new SecurityException('Simulated verifier unavailable.', 'auth.test_factor'); }
        if ($expectedBinding !== $this->generation || !is_string($proof) || strpos($proof, 'proof-') !== 0 || isset($this->used[$proof])) { return null; }
        $this->used[$proof] = true;
        if ($this->onVerify !== null) { $callback = $this->onVerify; $this->onVerify = null; $callback(); }
        return 'totp';
    }
}

$hasher = new SoSecurity\Password\PasswordHasher('bcrypt', ['cost' => 10]);
$hash = $hasher->hash('Correct-test-password'); $dummy = $hasher->hash('Dummy-test-password');
Check::throws(ConfigurationException::class, function () { new Account('tenant', 'subject', '1', true, ['bad role']); });
Check::throws(ConfigurationException::class, function () use ($hash) { new PasswordRecord(new Account('tenant', 's', '1'), str_replace('$2y$10$', '$2y$17$', $hash)); });
Check::throws(ConfigurationException::class, function () use ($hasher) { new PasswordIdentityProvider(function () {}, function () {}, $hasher, 'invalid'); });
Check::same((new Account('tenant', 's', '1', true, ['b', 'a']))->fingerprint(), (new Account('tenant', 's', '1', true, ['a', 'b', 'a']))->fingerprint());
Check::same(null, SessionRegistry::reference(null)); Check::same(null, SessionRegistry::reference([]));

$directory = privateDirectory();
try {
    foreach (['memory', 'file'] as $backend) {
        $clock = new TestClock(); $store = $backend === 'memory' ? new MemoryStore($clock) : new FileStore($directory, 'auth-' . $backend, $clock);
        $records = ['user' => new PasswordRecord(new Account('tenant', 'subject', '1', true, ['member']), $hash)];
        $offline = false; $lookups = 0;
        $byIdentifier = function (string $scope, string $identifier) use (&$records, &$offline, &$lookups) {
            ++$lookups;
            if ($offline) { throw new SecurityException('Simulated private identity outage.', 'auth.test_identity'); }
            return $scope === 'tenant' ? ($records[$identifier] ?? null) : null;
        };
        $bySubject = function (string $scope, string $subject) use (&$records, &$offline) {
            if ($offline) { throw new SecurityException('Simulated private identity outage.', 'auth.test_identity'); }
            foreach ($records as $record) { if ($record->account()->scope() === $scope && $record->account()->subject() === $subject) { return $record; } }
            return null;
        };
        $provider = new PasswordIdentityProvider($byIdentifier, $bySubject, $hasher, $dummy);
        $guardAllowed = true; $guardCalls = [];
        $guard = function (string $phase, string $scope) use (&$guardAllowed, &$guardCalls) { $guardCalls[] = [$phase, $scope]; return $guardAllowed; };
        $sessions = new SessionRegistry($store, $provider, null, $clock, 10, 100, 3);
        $flow = new AuthenticationFlow($store, $provider, $sessions, $guard, null, $clock);
        Check::same('denied', $flow->password('tenant', 'browser', 'missing', 'wrong')->status());
        Check::same('denied', $flow->password('tenant', 'browser', 'user', 'wrong')->status());
        Check::same([], $sessions->all('tenant', 'subject'));
        $guardAllowed = false; $before = $lookups;
        Check::throws(SecurityException::class, function () use ($flow) { $flow->password('tenant', 'browser', 'user', 'Correct-test-password'); });
        Check::same($before, $lookups); $guardAllowed = true;
        Check::same('denied', $flow->password('tenant', 'browser', [], [])->status());
        Check::same($before, $lookups);
        $result = $flow->password('tenant', 'browser', 'user', 'Correct-test-password', 'Laptop'); Check::same('authenticated', $result->status());
        $first = $result->credential(); $verified = $sessions->verify('tenant', 'subject', $first->token());
        Check::same('subject', $verified->account()->subject()); Check::same(['member'], $verified->account()->roles());
        Check::throws(ConfigurationException::class, function () use ($verified) { serialize($verified); });
        Check::throws(ConfigurationException::class, function () use ($verified) { serialize($verified->account()); });
        Check::same(true, $verified->recent(20, $clock->time, 1)); Check::same(false, $verified->recent(20, $clock->time));
        Check::same(null, $sessions->verify('other-tenant', 'subject', $first->token()));
        Check::same(null, $sessions->verify('tenant', 'other-subject', $first->token()));
        Check::same(null, $sessions->verify('tenant', 'subject', 'old-native-session-id'));
        $key = Guard::key('auth-sessions', 'tenant', 'subject');
        $raw = $store->transact($key, function ($state) { return new Change($state, 0, json_encode($state)); });
        Check::same(false, strpos($raw, $first->token()) !== false); Check::same(false, strpos($raw, $hash) !== false);
        Check::same(false, isset($sessions->all('tenant', 'subject')[0]['digest']));
        Check::throws(ConfigurationException::class, function () use ($result) { serialize($result); });
        Check::throws(ConfigurationException::class, function () use ($first) { serialize($first); });
        ob_start(); var_dump($first); $dump = ob_get_clean(); Check::same(false, strpos($dump, $first->token()) !== false);
        $clock->time += 5;
        $refreshed = $flow->password('tenant', 'browser', 'user', 'Correct-test-password', '', $first->token())->credential();
        Check::same($first->id(), $refreshed->id()); Check::same($first->expiresAt(), $refreshed->expiresAt());
        Check::same(false, $first->token() === $refreshed->token()); Check::same(null, $sessions->verify('tenant', 'subject', $first->token()));
        Check::same($clock->time, $sessions->verify('tenant', 'subject', $refreshed->token())->authenticatedAt());
        $second = $flow->password('tenant', 'other-browser', 'user', 'Correct-test-password')->credential();
        Check::same(2, count($sessions->all('tenant', 'subject')));
        Check::same(false, $sessions->revoke('other-tenant', 'subject', $second->id()));
        Check::same(true, $sessions->revoke('tenant', 'subject', $refreshed->id()));
        Check::same(null, $sessions->verify('tenant', 'subject', $refreshed->token()));
        Check::same('subject', $sessions->verify('tenant', 'subject', $second->token())->account()->subject());
        $epoch = $sessions->epoch('tenant', 'subject'); $snapshot = (new IdentityState($provider, null))->load('tenant', 'subject');
        $sessions->revokeAll('tenant', 'subject');
        Check::same(null, $sessions->verify('tenant', 'subject', $second->token()));
        Check::same(null, $sessions->register('tenant', 'subject', $snapshot['fingerprint'], $epoch));
        $credential = $flow->password('tenant', 'browser', 'user', 'Correct-test-password')->credential();
        $clock->time += 9; Check::same('subject', $sessions->verify('tenant', 'subject', $credential->token())->account()->subject());
        $clock->time += 10; Check::same(null, $sessions->verify('tenant', 'subject', $credential->token()));
        $credential = $flow->password('tenant', 'browser', 'user', 'Correct-test-password')->credential();
        $newHash = $hasher->hash('Changed-test-password');
        $records['user'] = new PasswordRecord(new Account('tenant', 'subject', '1', true, ['member']), $newHash);
        Check::same(null, $sessions->verify('tenant', 'subject', $credential->token())); // hash changed without bumping host version
        Check::same('denied', $flow->password('tenant', 'browser', 'user', 'Correct-test-password')->status());
        $credential = $flow->password('tenant', 'browser', 'user', 'Changed-test-password')->credential();
        $records['user'] = new PasswordRecord(new Account('tenant', 'subject', '1', true, ['reader']), $newHash);
        Check::same(null, $sessions->verify('tenant', 'subject', $credential->token()));
        $credential = $flow->password('tenant', 'browser', 'user', 'Changed-test-password')->credential();
        $offline = true;
        Check::throws(SecurityException::class, function () use ($sessions, $credential) { $sessions->verify('tenant', 'subject', $credential->token()); });
        Check::throws(SecurityException::class, function () use ($flow) { $flow->password('tenant', 'browser', 'user', 'Changed-test-password'); });
        $offline = false;
        $records['user'] = new PasswordRecord(new Account('tenant', 'subject', '1', false, ['reader']), $newHash);
        Check::same(null, $sessions->verify('tenant', 'subject', $credential->token()));
        Check::same('denied', $flow->password('tenant', 'browser', 'user', 'Changed-test-password')->status());
        $records['user'] = new PasswordRecord(new Account('tenant', 'subject', '2', true, ['reader']), $newHash);
        Check::same(null, $sessions->verify('tenant', 'subject', $credential->token()));
        $sessions->revokeAll('tenant', 'subject');

        $records['cap'] = new PasswordRecord(new Account('tenant', 'capacity', '1'), $newHash);
        $cap = [];
        for ($i = 0; $i < 3; ++$i) { $cap[] = $flow->password('tenant', 'cap-' . $i, 'cap', 'Changed-test-password')->credential(); }
        Check::throws(SecurityException::class, function () use ($flow) { $flow->password('tenant', 'cap-excess', 'cap', 'Changed-test-password'); });
        Check::same(3, count($sessions->all('tenant', 'capacity'))); $sessions->revoke('tenant', 'capacity', $cap[0]->id());
        Check::same('authenticated', $flow->password('tenant', 'cap-new', 'cap', 'Changed-test-password')->status());
        $sessions->revokeAll('tenant', 'capacity');
        $longSessions = new SessionRegistry($store, $provider, null, $clock, 60, 100);
        $longFlow = new AuthenticationFlow($store, $provider, $longSessions, $guard, null, $clock);
        $credential = $longFlow->password('tenant', 'long', 'user', 'Changed-test-password')->credential();
        $clock->time += 50;
        $renewed = $longFlow->password('tenant', 'long', 'user', 'Changed-test-password', '', $credential->token())->credential();
        Check::same($credential->expiresAt(), $renewed->expiresAt());
        $clock->time += 49; Check::same(true, $longSessions->verify('tenant', 'subject', $renewed->token()) !== null);
        ++$clock->time; Check::same(null, $longSessions->verify('tenant', 'subject', $renewed->token()));
        $credential = $longFlow->password('tenant', 'tight', 'user', 'Changed-test-password')->credential();
        $tight = new SessionRegistry($store, $provider, null, $clock, 5, 50);
        Check::same(true, $tight->verify('tenant', 'subject', $credential->token()) !== null);
        $clock->time += 5; Check::same(null, $tight->verify('tenant', 'subject', $credential->token()));
        Check::same(null, $longSessions->verify('tenant', 'subject', $credential->token()));
        $sessions->revokeAll('tenant', 'subject');

        // Flow protocol with a simulated factor: no partial identity becomes a registry credential.
        $factor = new AuthTestFactor(); $sessions = new SessionRegistry($store, $provider, $factor, $clock, 100, 500, 8);
        $flow = new AuthenticationFlow($store, $provider, $sessions, $guard, $factor, $clock, 60, 10, 3);
        $pending = $flow->password('tenant', 'browser', 'user', 'Changed-test-password');
        Check::same('mfa_required', $pending->status()); Check::same(null, $pending->credential()); Check::same([], $sessions->all('tenant', 'subject'));
        Check::same('denied', $flow->secondFactor('tenant', 'other-browser', $pending->challenge(), 'proof-cross')->status());
        Check::same('denied', $flow->secondFactor('other-tenant', 'browser', $pending->challenge(), 'proof-cross')->status());
        Check::same(0, $factor->calls);
        Check::same('denied', $flow->secondFactor('tenant', 'browser', $pending->challenge(), 'wrong')->status());
        $done = $flow->secondFactor('tenant', 'browser', $pending->challenge(), 'proof-valid'); Check::same('authenticated', $done->status());
        Check::same(2, $sessions->verify('tenant', 'subject', $done->credential()->token())->strength());
        Check::same('denied', $flow->secondFactor('tenant', 'browser', $pending->challenge(), 'proof-replay')->status());
        $reauth = $flow->password('tenant', 'browser', 'user', 'Changed-test-password', '', $done->credential()->token());
        $clock->time += 1;
        $replaced = $flow->secondFactor('tenant', 'browser', $reauth->challenge(), 'proof-reauth')->credential();
        Check::same($done->credential()->id(), $replaced->id()); Check::same($done->credential()->expiresAt(), $replaced->expiresAt());
        Check::same(null, $sessions->verify('tenant', 'subject', $done->credential()->token()));
        Check::same(true, $sessions->verify('tenant', 'subject', $replaced->token())->recent(10, $clock->time));

        $pending = $flow->password('tenant', 'browser', 'user', 'Changed-test-password'); $sessions->revokeAll('tenant', 'subject'); $before = $factor->calls;
        Check::same('denied', $flow->secondFactor('tenant', 'browser', $pending->challenge(), 'proof-revoked')->status()); Check::same($before, $factor->calls);
        $pending = $flow->password('tenant', 'browser', 'user', 'Changed-test-password');
        $factor->onVerify = function () use ($sessions) { $sessions->revokeAll('tenant', 'subject'); };
        Check::same('denied', $flow->secondFactor('tenant', 'browser', $pending->challenge(), 'proof-race-revoke')->status()); Check::same([], $sessions->all('tenant', 'subject'));
        $pending = $flow->password('tenant', 'browser', 'user', 'Changed-test-password');
        $factor->onVerify = function () use ($factor) { $factor->generation = 'generation-2'; };
        Check::same('denied', $flow->secondFactor('tenant', 'browser', $pending->challenge(), 'proof-factor-replaced')->status()); Check::same([], $sessions->all('tenant', 'subject'));

        $oneAttempt = new AuthenticationFlow($store, $provider, $sessions, $guard, $factor, $clock, 60, 10, 1);
        $pending = $oneAttempt->password('tenant', 'browser', 'user', 'Changed-test-password'); $factor->fail = true;
        Check::throws(SecurityException::class, function () use ($oneAttempt, $pending) { $oneAttempt->secondFactor('tenant', 'browser', $pending->challenge(), 'proof-service'); });
        $factor->fail = false;
        Check::same('authenticated', $oneAttempt->secondFactor('tenant', 'browser', $pending->challenge(), 'proof-service')->status());
        $sessions->revokeAll('tenant', 'subject');
        $pending = $flow->password('tenant', 'browser', 'user', 'Changed-test-password');
        $factor->onVerify = function () use ($flow, $clock, $pending) {
            $clock->time += 11;
            Check::same('authenticated', $flow->secondFactor('tenant', 'browser', $pending->challenge(), 'proof-new-claim')->status());
        };
        Check::same('denied', $flow->secondFactor('tenant', 'browser', $pending->challenge(), 'proof-stale-claim')->status());
        Check::same(1, count($sessions->all('tenant', 'subject'))); $sessions->revokeAll('tenant', 'subject');
        $pending = $flow->password('tenant', 'browser', 'user', 'Changed-test-password');
        $clock->time += 60;
        Check::same('denied', $flow->secondFactor('tenant', 'browser', $pending->challenge(), 'proof-expired')->status());
        Check::same([], $sessions->all('tenant', 'subject'));
        $pending = $flow->password('tenant', 'browser', 'user', 'Changed-test-password'); $flow->cancel('tenant', 'browser');
        Check::same('denied', $flow->secondFactor('tenant', 'browser', $pending->challenge(), 'proof-cancelled')->status());

        $key = Guard::key('auth-pending', 'tenant', 'corrupt');
        $store->transact($key, function () { return new Change(['v' => 1], 0, null); });
        Check::throws(StorageException::class, function () use ($flow) { $flow->secondFactor('tenant', 'corrupt', str_repeat('a', 64), 'proof-corrupt'); });
        $clock->time += 1; $pending = $flow->password('tenant', 'clock', 'user', 'Changed-test-password'); --$clock->time;
        Check::throws(SecurityException::class, function () use ($flow, $pending) { $flow->secondFactor('tenant', 'clock', $pending->challenge(), 'proof-clock'); }); ++$clock->time;
        $registryKey = Guard::key('auth-sessions', 'tenant', 'corrupt-registry');
        $store->transact($registryKey, function () { return new Change(['v' => 2], 0, null); });
        Check::throws(StorageException::class, function () use ($sessions) { $sessions->all('tenant', 'corrupt-registry'); });
        echo 'PASS ' . $backend . ' authentication/registry: password/version/role/disable checks, scoped credentials, MFA pending/leases, epoch revocation and reauthentication' . "\n";
    }

    $badProvider = new CallbackIdentityProvider(function () { return false; }, function () { return false; });
    Check::throws(SecurityException::class, function () use ($badProvider) { $badProvider->find('tenant', 'subject'); });
    $badProvider = new CallbackIdentityProvider(function () { return new Account('other', 'subject', '1'); }, function () { return new Account('other', 'subject', '1'); });
    Check::throws(SecurityException::class, function () use ($badProvider) { $badProvider->authenticate('tenant', 'subject', 'pw'); });
    Check::throws(SecurityException::class, function () use ($badProvider) { $badProvider->find('tenant', 'subject'); });
    $offlineStore = new class implements AtomicStore { public function transact(string $key, callable $callback) { throw new StorageException('Simulated store outage.'); } };
    $provider = new CallbackIdentityProvider(function () { return new Account('tenant', 'subject', '1'); }, function () { return new Account('tenant', 'subject', '1'); });
    $sessions = new SessionRegistry($offlineStore, $provider);
    Check::throws(StorageException::class, function () use ($sessions) { $sessions->epoch('tenant', 'subject'); });
    $required = new CallbackIdentityProvider(function () { return new Account('tenant', 'subject', '1', true, [], true); }, function () { return new Account('tenant', 'subject', '1', true, [], true); });
    $memory = new MemoryStore(); $sessions = new SessionRegistry($memory, $required);
    Check::throws(ConfigurationException::class, function () use ($sessions) { $sessions->epoch('tenant', 'subject'); });
    $emptyFactor = new AuthTestFactor(); $emptyFactor->generation = null;
    $sessions = new SessionRegistry($memory, $required, $emptyFactor);
    $flow = new AuthenticationFlow($memory, $required, $sessions, function () { return true; }, $emptyFactor);
    Check::same('enrollment_required', $flow->password('tenant', 'browser', 'subject', 'pw')->status());

    $clock = new TestClock(); $config = ['site' => 'auth-factory', 'storage' => ['driver' => 'file', 'directory' => $directory],
        'authentication' => ['identity_provider' => 'identity', 'request_guard' => 'guard']];
    $factory = SoSecurity\Security::fromArray($config, ['identity' => $provider, 'guard' => function () { return true; }], $clock);
    $result = $factory->authentication()->password('tenant', 'browser', 'subject', 'pw'); Check::same('authenticated', $result->status());
    Check::same('subject', $factory->sessions()->verify('tenant', 'subject', $result->credential()->token())->account()->subject());
    $bad = SoSecurity\Security::fromArray($config, ['identity' => $provider], $clock);
    Check::throws(ConfigurationException::class, function () use ($bad) { $bad->authentication(); });
    $config['storage'] = ['driver' => 'memory'];
    $bad = SoSecurity\Security::fromArray($config, ['identity' => $provider, 'guard' => function () { return true; }], $clock);
    Check::throws(ConfigurationException::class, function () use ($bad) { $bad->sessions(); });

    if (extension_loaded('sodium')) {
        $clock = new TestClock(); $store = new MemoryStore($clock);
        $cipher = new SoSecurity\Crypto\Cipher('test', ['test' => str_repeat('k', 32)], 'auth-totp-test');
        $mfa = new SoSecurity\Mfa\TotpFactors($store, $cipher, 'Test', $clock);
        $pending = $mfa->begin('tenant', 'subject', 'test@example.test');
        parse_str(parse_url($pending->provisioningUri(), PHP_URL_QUERY), $setup);
        $totp = new SoSecurity\Mfa\Totp(); $proof = $totp->codeAt($setup['secret'], $clock->time);
        $codes = $mfa->confirm('tenant', 'subject', $pending->id(), $proof);
        $factor = new SoSecurity\Auth\TotpSecondFactor($mfa);
        $sessions = new SessionRegistry($store, $required, $factor, $clock);
        $flow = new AuthenticationFlow($store, $required, $sessions, function () { return true; }, $factor, $clock);
        $login = $flow->password('tenant', 'browser', 'subject', 'pw'); Check::same('mfa_required', $login->status());
        Check::same(null, $login->account());
        Check::same('denied', $flow->secondFactor('tenant', 'browser', $login->challenge(), ['type' => 'totp', 'code' => $proof])->status());
        $clock->time += 30;
        $login = $flow->secondFactor('tenant', 'browser', $login->challenge(), ['type' => 'totp', 'code' => $totp->codeAt($setup['secret'], $clock->time)]);
        Check::same('authenticated', $login->status()); Check::same('totp', $sessions->verify('tenant', 'subject', $login->credential()->token())->method());
        $reauth = $flow->password('tenant', 'browser', 'subject', 'pw', '', $login->credential()->token());
        $renewed = $flow->secondFactor('tenant', 'browser', $reauth->challenge(), ['type' => 'recovery', 'code' => $codes[0]]);
        Check::same('authenticated', $renewed->status()); Check::same('recovery', $sessions->verify('tenant', 'subject', $renewed->credential()->token())->method());
        Check::same(null, $sessions->verify('tenant', 'subject', $login->credential()->token()));
        $waiting = $flow->password('tenant', 'browser', 'subject', 'pw'); $oldId = $factor->binding('tenant', 'subject');
        $pending = $mfa->begin('tenant', 'subject', 'replace@example.test');
        parse_str(parse_url($pending->provisioningUri(), PHP_URL_QUERY), $newSetup);
        $newCodes = $mfa->confirm('tenant', 'subject', $pending->id(), $totp->codeAt($newSetup['secret'], $clock->time));
        Check::same(false, $mfa->verifyBound('tenant', 'subject', $oldId, $newCodes[0], true));
        Check::same(true, $mfa->verifyRecovery('tenant', 'subject', $newCodes[0])); // rejected old binding did not consume the new proof
        Check::same('denied', $flow->secondFactor('tenant', 'browser', $waiting->challenge(), ['type' => 'recovery', 'code' => $newCodes[1]])->status());
        Check::same(null, $sessions->verify('tenant', 'subject', $renewed->credential()->token()));
        $mfa->revoke('tenant', 'subject');
        Check::same('enrollment_required', $flow->password('tenant', 'browser', 'subject', 'pw')->status());
        echo 'PASS real TOTP authentication integration: factor generation, pending identity, recovery reauthentication and replacement invalidation' . "\n";
    } else {
        echo 'NOT RUN encrypted TOTP authentication integration: ext-sodium required' . "\n";
        if (getenv('SOSECURITY_REQUIRE_CRYPTO') === '1') { throw new RuntimeException('Required ext-sodium missing.'); }
    }
} finally { cleanDirectory($directory); }
echo 'PASS authentication: ' . Check::$assertions . ' assertions on PHP ' . PHP_VERSION . "\n";
