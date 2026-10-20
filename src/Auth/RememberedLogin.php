<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Http\Cookie;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SystemClock;

/** Explicit opt-in persistent authorization. Rotation and session/grant revocation share one atomic ledger. */
final class RememberedLogin
{
    private $store;
    private $sessions;
    private $identities;
    private $codec;
    private $guard;
    private $clock;
    private $ttl;
    private $capacity;
    private $fresh;
    private $grace;
    private $policy;
    private $riskGuard;

    public function __construct(AtomicStore $store, IdentityProvider $provider, SessionRegistry $sessions, HmacKeys $keys,
        callable $requestGuard, ?SecondFactor $factor = null, ?Clock $clock = null, int $ttl = 2592000,
        int $capacity = 8, int $freshAge = 300, int $concurrencyGrace = 5, ?callable $riskGuard = null)
    {
        Guard::duration($ttl);
        if ($capacity < 1 || $capacity > 16 || $freshAge < 1 || $freshAge > 3600 || $concurrencyGrace < 0 || $concurrencyGrace > 10) {
            throw new ConfigurationException('Invalid persistent-login limits.', 'configuration.remember');
        }
        $this->store = $store; $this->sessions = $sessions; $this->identities = new IdentityState($provider, $factor);
        $this->codec = new RememberCodec($keys); $this->guard = $requestGuard; $this->clock = $clock ?? new SystemClock();
        $this->ttl = $ttl; $this->capacity = $capacity; $this->fresh = $freshAge; $this->grace = $concurrencyGrace; $this->policy = $sessions->policy();
        $this->riskGuard = $riskGuard;
    }

    /** Caller obtains explicit user consent first. Only a recent, non-restored full login can create a grant. */
    public function issue(string $scope, string $subject, $sessionToken, string $label = ''): ?RememberCredential
    {
        $key = Guard::key('auth-sessions', $scope, $subject); $this->guard('remember_issue', $scope);
        if (strlen($label) > 128 || !preg_match('//u', $label) || preg_match('/[\x00-\x1f\x7f]/', $label)) { throw new ConfigurationException('Invalid persistent device label.', 'configuration.remember'); }
        $verified = $this->sessions->verify($scope, $subject, $sessionToken); $now = $this->now();
        if ($verified === null || !$verified->recent($this->fresh, $now, 1)) { return null; }
        $identity = $this->identities->load($scope, $subject);
        if ($identity === null || !hash_equals($identity['account']->fingerprint(), $verified->account()->fingerprint())) { return null; }
        $reference = SessionRegistry::reference($sessionToken); $expires = $verified->authenticatedAt() + $this->ttl;
        if ($reference === null) { return null; }
        if ($expires <= $now) { return null; }
        $selector = bin2hex(random_bytes(16)); $token = $this->codec->issue($scope, $selector, 0, bin2hex(random_bytes(32)));
        $locatorKey = Guard::key('auth-remember-index', $scope, $selector);
        $locator = ['v' => 1, 'subject' => $subject, 'created' => $now, 'expires' => $expires];
        $allocated = $this->store->transact($locatorKey, static function ($old) use ($locator) {
            if ($old !== null) { throw new SecurityException('Persistent selector allocation collided.', 'auth.remember_collision'); }
            return new Change($locator, $locator['expires'], true);
        });
        if (!$allocated) { return null; }
        try {
            $result = $this->store->transact($key, function ($state) use ($reference, $identity, $verified, $now, $selector, $token, $expires, $label) {
                $state = $this->state($state, $now);
                if ($state === null || !isset($state['sessions'][$reference['id']])) { return RegistryState::change($state, $now, null); }
                $record = $state['sessions'][$reference['id']];
                if (!hash_equals($record['digest'], $reference['digest']) || !hash_equals($record['fingerprint'], $identity['fingerprint'])
                    || $record['resumed'] || $record['authenticated'] !== $verified->authenticatedAt() || $now - $record['authenticated'] >= $this->fresh) {
                    return RegistryState::change($state, $now, null);
                }
                if ($record['grant'] !== null) {
                    // Replace this device's previous grant, preserving the independently verified current session.
                    unset($state['remember'][$record['grant']]);
                }
                $state = RegistryState::forIdentity($state, $identity['fingerprint']);
                if (count($state['remember']) >= $this->capacity) { throw new SecurityException('Persistent device capacity reached.', 'auth.remember_capacity'); }
                $state['remember'][$selector] = ['fingerprint' => $record['fingerprint'], 'epoch' => $state['epoch'], 'digest' => hash('sha256', $token),
                    'generation' => 0, 'created' => $now, 'authenticated' => $record['authenticated'], 'expires' => $expires, 'method' => $record['method'],
                    'session_id' => $reference['id'], 'label' => $label, 'rotated' => $now, 'recent' => []];
                $record['grant'] = $selector; $state['sessions'][$reference['id']] = $record;
                return RegistryState::change($state, $now, new RememberCredential($token, $selector, $expires));
            });
        } catch (\Throwable $e) { $this->discardLocator($locatorKey, $locator); throw $e; }
        if ($result === null) { $this->discardLocator($locatorKey, $locator); }
        return $result;
    }

    /** POST/CSRF-protected restoration; a retry outcome must not overwrite/delete the winner's cookies. */
    public function resume(string $scope, $token): RememberResult
    {
        Guard::label($scope); $this->guard('remember_resume', $scope);
        $parts = $this->codec->parse($scope, $token);
        if ($parts === null) { return new RememberResult('invalid'); }
        $locator = $this->locator($scope, $parts['id']);
        if ($locator === null) { return new RememberResult('invalid'); }
        $subject = $locator['subject']; $key = Guard::key('auth-sessions', $scope, $subject); $identity = $this->identities->load($scope, $subject);
        // Evaluate outside the retryable storage callback; the callback must not perform I/O or mutate host state.
        $risk = $this->riskGuard === null ? new DeviceRiskDecision('allow', 'none') : ($this->riskGuard)($scope, $subject, $parts['id']);
        if (!$risk instanceof DeviceRiskDecision) {
            throw new SecurityException('Trusted-device risk assessment was not confirmed.', 'auth.device_risk_denied');
        }
        $now = $this->now(); $secret = bin2hex(random_bytes(32)); $sessionSecret = bin2hex(random_bytes(32)); $nextEpoch = bin2hex(random_bytes(32));
        $result = $this->store->transact($key, function ($state) use ($scope, $parts, $identity, $risk, $now, $secret, $sessionSecret, $nextEpoch) {
            $state = $this->state($state, $now);
            if ($state === null || !isset($state['remember'][$parts['id']])) { return RegistryState::change($state, $now, new RememberResult('invalid')); }
            $grant = $state['remember'][$parts['id']];
            if ($parts['generation'] !== $grant['generation']) {
                if ($parts['generation'] < $grant['generation']) {
                    foreach ($grant['recent'] as $entry) {
                        if ($entry['generation'] === $parts['generation'] && $entry['until'] > $now) {
                            return RegistryState::change($state, $now, new RememberResult('retry'));
                        }
                    }
                }
                // Authenticated old/future generation: revoke every subject session/grant and fence pending logins atomically.
                return RegistryState::change(RegistryState::empty($nextEpoch, $now), $now, new RememberResult('replayed'));
            }
            if (!hash_equals($grant['digest'], $parts['digest'])) { return RegistryState::change($state, $now, new RememberResult('invalid')); }
            if ($identity === null || !hash_equals($grant['fingerprint'], $identity['fingerprint'])
                || ($identity['mfa_required'] && (SessionRegistry::strength($grant['method']) < 2 || $identity['factor'] === null))) {
                $state = RegistryState::removeGrant($state, $parts['id']);
                return RegistryState::change($state, $now, new RememberResult('invalid'));
            }
            if ($risk->action() === 'deny') {
                return RegistryState::change(RegistryState::removeGrant($state, $parts['id']), $now,
                    new RememberResult('blocked', null, null, null, $risk->reason()));
            }
            if ($risk->action() === 'step_up') {
                // A later change in ambient signals must not turn this same persistent token back into login authority.
                return RegistryState::change(RegistryState::removeGrant($state, $parts['id']), $now,
                    new RememberResult('step_up', null, null, null, $risk->reason()));
            }
            if (!isset($state['sessions'][$grant['session_id']]) && count($state['sessions']) >= $this->policy['capacity']) {
                throw new SecurityException('Session capacity reached; revoke an existing session first.', 'auth.session_capacity');
            }
            if ($grant['generation'] >= 2147483647) { throw new SecurityException('Persistent rotation counter exhausted.', 'auth.remember_generation'); }
            $grant['recent'] = array_values(array_filter($grant['recent'], static function (array $entry) use ($now): bool { return $entry['until'] > $now; }));
            if ($this->grace > 0) { $grant['recent'][] = ['generation' => $grant['generation'], 'until' => min($grant['expires'], $now + $this->grace)]; }
            while (count($grant['recent']) > 8) { array_shift($grant['recent']); }
            ++$grant['generation']; $grant['rotated'] = $now;
            $next = $this->codec->issue($scope, $parts['id'], $grant['generation'], $secret); $grant['digest'] = hash('sha256', $next);
            $state['remember'][$parts['id']] = $grant;
            $sessionToken = 'soss_' . $grant['session_id'] . '.' . $sessionSecret; $expires = min($grant['expires'], $now + $this->policy['absolute']);
            $state['sessions'][$grant['session_id']] = ['digest' => hash('sha256', $sessionToken), 'fingerprint' => $grant['fingerprint'], 'method' => $grant['method'],
                'created' => $now, 'seen' => $now, 'expires' => $expires, 'authenticated' => $grant['authenticated'], 'idle' => $this->policy['idle'],
                'label' => $grant['label'], 'resumed' => true, 'grant' => $parts['id']];
            return RegistryState::change($state, $now, new RememberResult('authenticated', new SessionCredential($sessionToken, $grant['session_id'], $expires),
                new RememberCredential($next, $parts['id'], $grant['expires']), $identity['account']));
        });
        if ($result->status() === 'authenticated') {
            // A replay/disable/version change that committed while the result was being returned must not be ignored.
            if ($this->sessions->verify($scope, $subject, $result->session()->token()) === null) { return new RememberResult('invalid'); }
        }
        return $result;
    }

    /** Host authorizes the trusted subject/selector management target; removes its linked sessions too. */
    public function revoke(string $scope, string $subject, string $selector): bool
    {
        $key = Guard::key('auth-sessions', $scope, $subject); $this->guard('remember_revoke', $scope); $now = $this->now();
        if (!preg_match('/\A[a-f0-9]{32}\z/D', $selector)) { return false; }
        return $this->store->transact($key, function ($state) use ($now, $selector) {
            $state = $this->state($state, $now); $exists = $state !== null && isset($state['remember'][$selector]);
            if ($exists) { $state = RegistryState::removeGrant($state, $selector); }
            return RegistryState::change($state, $now, $exists);
        });
    }
    /** Explicit sign-out without an active host session; possession of the signed credential only permits revocation. */
    public function forget(string $scope, $token): bool
    {
        Guard::label($scope); $this->guard('remember_forget', $scope); $parts = $this->codec->parse($scope, $token);
        if ($parts === null) { return false; }
        $locator = $this->locator($scope, $parts['id']); if ($locator === null) { return false; }
        $now = $this->now();
        return $this->store->transact(Guard::key('auth-sessions', $scope, $locator['subject']), function ($state) use ($parts, $now) {
            $state = $this->state($state, $now); $grant = $state === null ? null : ($state['remember'][$parts['id']] ?? null);
            $valid = $grant !== null && $parts['generation'] <= $grant['generation']
                && ($parts['generation'] !== $grant['generation'] || hash_equals($grant['digest'], $parts['digest']));
            if ($valid) { $state = RegistryState::removeGrant($state, $parts['id']); }
            return RegistryState::change($state, $now, $valid);
        });
    }
    public function all(string $scope, string $subject): array
    {
        $key = Guard::key('auth-sessions', $scope, $subject); $this->guard('remember_list', $scope); $now = $this->now();
        return $this->store->transact($key, function ($state) use ($now) {
            $state = $this->state($state, $now); $rows = [];
            foreach ($state === null ? [] : $state['remember'] as $id => $grant) {
                $rows[] = ['id' => $id, 'session_id' => $grant['session_id'], 'created' => $grant['created'], 'expires' => $grant['expires'],
                    'authenticated' => $grant['authenticated'], 'last_used' => $grant['rotated'], 'label' => $grant['label']];
            }
            return RegistryState::change($state, $now, $rows);
        });
    }
    public function cookieHeader(RememberCredential $credential, string $name = '__Host-SoSecurityRemember', bool $secure = true, string $path = '/'): string
    {
        return Cookie::header($name, $credential->token(), $path, $secure, true, 'Lax', max(0, $credential->expiresAt() - $this->now()));
    }
    public function clearCookieHeader(string $name = '__Host-SoSecurityRemember', bool $secure = true, string $path = '/'): string
    {
        return Cookie::header($name, '', $path, $secure, true, 'Lax', 0);
    }
    private function locator(string $scope, string $selector): ?array
    {
        return $this->store->transact(Guard::key('auth-remember-index', $scope, $selector), static function ($index) {
            if ($index === null) { return new Change(null, 0, null); }
            $fields = is_array($index) ? array_keys($index) : []; sort($fields);
            if ($fields !== ['created', 'expires', 'subject', 'v'] || $index['v'] !== 1 || !is_string($index['subject']) || $index['subject'] === ''
                || strlen($index['subject']) > 256 || !preg_match('//u', $index['subject']) || preg_match('/[\x00-\x1f\x7f]/', $index['subject'])
                || !is_int($index['created']) || !is_int($index['expires']) || $index['created'] < 0 || $index['expires'] <= $index['created']
                || $index['expires'] - $index['created'] > 31536000) { throw new StorageException('Corrupt persistent identity locator.', 'storage.corrupt'); }
            return new Change($index, $index['expires'], $index);
        });
    }
    private function discardLocator(string $key, array $expected): void
    {
        $this->store->transact($key, static function ($old) use ($expected) {
            return $old === $expected ? new Change(null, 0, null) : new Change($old, $old === null ? 0 : ($old['expires'] ?? 0), null);
        });
    }
    private function state($state, int $now): ?array { return RegistryState::read($state, $now, $this->policy['idle'], $this->policy['absolute']); }
    private function guard(string $phase, string $scope): void
    {
        if (($this->guard)($phase, $scope) !== true) { throw new SecurityException('Host persistent-login request protection was not confirmed.', 'auth.request_denied'); }
    }
    private function now(): int
    {
        $now = $this->clock->now();
        if ($now < 0 || $now > PHP_INT_MAX - 31536000) { throw new ConfigurationException('Authentication clock out of range.', 'configuration.clock'); }
        return $now;
    }
    public function __debugInfo(): array { return ['persistent_login' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Do not serialize persistent-login services.', 'configuration.keys_serialization'); }
}
