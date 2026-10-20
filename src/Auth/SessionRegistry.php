<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Shared revocable sessions. Host authorizes management calls; register/replace require fresh server-side proof. */
final class SessionRegistry
{
    private $store;
    private $identities;
    private $clock;
    private $idle;
    private $absolute;
    private $capacity;

    public function __construct(AtomicStore $store, IdentityProvider $provider, ?SecondFactor $factor = null,
        ?Clock $clock = null, int $idle = 1800, int $absolute = 28800, int $capacity = 16)
    {
        Guard::duration($idle); Guard::duration($absolute);
        if ($idle > $absolute || $capacity < 1 || $capacity > 32) { throw new ConfigurationException('Invalid session limits.', 'configuration.auth_sessions'); }
        $this->store = $store; $this->identities = new IdentityState($provider, $factor); $this->clock = $clock ?? new SystemClock();
        $this->idle = $idle; $this->absolute = $absolute; $this->capacity = $capacity;
    }

    /** Capture after successful first-factor verification, before an optional second-factor challenge. */
    public function epoch(string $scope, string $subject): ?string
    {
        $key = Guard::key('auth-sessions', $scope, $subject); $identity = $this->identities->load($scope, $subject);
        if ($identity === null) { return null; }
        $now = $this->now(); $epoch = bin2hex(random_bytes(32));
        return $this->store->transact($key, function ($state) use ($epoch, $now) {
            $state = $this->state($state, $now) ?? RegistryState::empty($epoch, $now);
            return $this->change($state, $now, $state['epoch']);
        });
    }

    /** Only call after verified credentials. Fingerprint and epoch MUST come from trusted pre-proof snapshots. */
    public function register(string $scope, string $subject, string $expectedFingerprint, string $expectedEpoch,
        string $method = 'password', string $label = ''): ?SessionCredential
    {
        return $this->issue($scope, $subject, $expectedFingerprint, $expectedEpoch, $method, $label, null);
    }

    /** Rotates the original secret while preserving its ID and absolute expiry. Used by AuthenticationFlow. */
    public function replace(string $scope, string $subject, string $expectedFingerprint, string $expectedEpoch,
        string $method, string $id, string $expectedDigest): ?SessionCredential
    {
        if (!preg_match('/\A[a-f0-9]{32}\z/D', $id) || !preg_match('/\A[a-f0-9]{64}\z/D', $expectedDigest)) {
            throw new ConfigurationException('Invalid reauthentication reference.', 'configuration.authentication');
        }
        return $this->issue($scope, $subject, $expectedFingerprint, $expectedEpoch, $method, '', ['id' => $id, 'digest' => $expectedDigest]);
    }

    public function verify(string $scope, string $subject, $token, int $minimumStrength = 0): ?VerifiedSession
    {
        $key = Guard::key('auth-sessions', $scope, $subject);
        if ($minimumStrength < 0 || $minimumStrength > 2) { throw new ConfigurationException('Invalid authentication strength.', 'configuration.authentication'); }
        $parts = self::reference($token); if ($parts === null) { return null; }
        $identity = $this->identities->load($scope, $subject);
        $now = $this->now();
        if ($identity === null || ($identity['mfa_required'] && $identity['factor'] === null)) {
            $epoch = bin2hex(random_bytes(32));
            $this->store->transact($key, function ($state) use ($parts, $now, $epoch) {
                $state = $this->state($state, $now);
                if ($state !== null && isset($state['sessions'][$parts['id']]) && hash_equals($state['sessions'][$parts['id']]['digest'], $parts['digest'])) {
                    // A definitive loss of authority observed with a valid token revokes the entire subject.
                    // Provider outages throw before this point and must not be mistaken for account removal.
                    $state['epoch'] = $epoch; $state['sessions'] = []; $state['remember'] = [];
                }
                return $this->change($state, $now, null);
            });
            return null;
        }
        $record = $this->store->transact($key, function ($state) use ($parts, $identity, $now, $minimumStrength) {
            $state = $this->state($state, $now);
            if ($state === null || !isset($state['sessions'][$parts['id']])) { return $this->change($state, $now, null); }
            $record = $state['sessions'][$parts['id']];
            if (!hash_equals($record['digest'], $parts['digest'])) { return $this->change($state, $now, null); }
            if (!hash_equals($record['fingerprint'], $identity['fingerprint'])) {
                if ($record['grant'] !== null) { $state = RegistryState::removeGrant($state, $record['grant']); }
                unset($state['sessions'][$parts['id']]); return $this->change($state, $now, null);
            }
            if (self::strength($record['method']) < max($minimumStrength, $identity['mfa_required'] ? 2 : 0)) { return $this->change($state, $now, null); }
            $record['seen'] = $now; $record['idle'] = min($record['idle'], $this->idle);
            $record['expires'] = min($record['expires'], $record['created'] + $this->absolute);
            $state['sessions'][$parts['id']] = $record;
            return $this->change($state, $now, $record);
        });
        if ($record === null || $record['expires'] <= $this->now()) { return null; }
        return new VerifiedSession($identity['account'], $parts['id'], $record['method'], $record['created'], $record['authenticated'], $record['expires'], $record['resumed']);
    }

    /** Management ID only; knowing it grants no authentication capability. Never accept an untrusted subject. */
    public function revoke(string $scope, string $subject, string $id): bool
    {
        if (!preg_match('/\A[a-f0-9]{32}\z/D', $id)) { return false; }
        $key = Guard::key('auth-sessions', $scope, $subject); $now = $this->now();
        return $this->store->transact($key, function ($state) use ($id, $now) {
            $state = $this->state($state, $now); $exists = $state !== null && isset($state['sessions'][$id]);
            foreach ($state === null ? [] : $state['remember'] as $grantId => $grant) {
                if ($grant['session_id'] === $id) { $state = RegistryState::removeGrant($state, $grantId); $exists = true; }
            }
            if ($exists) {
                unset($state['sessions'][$id]);
            }
            return $this->change($state, $now, $exists);
        });
    }

    /** Also invalidates first-factor snapshots captured before this call, including in-flight MFA logins. */
    public function revokeAll(string $scope, string $subject): void
    {
        $key = Guard::key('auth-sessions', $scope, $subject); $now = $this->now(); $epoch = bin2hex(random_bytes(32));
        $this->store->transact($key, function ($state) use ($now, $epoch) {
            $this->state($state, $now);
            return $this->change(RegistryState::empty($epoch, $now), $now, null);
        });
    }

    /** Stored live records only, not proof of a browser being online; host authorizes this query. */
    public function all(string $scope, string $subject): array
    {
        $key = Guard::key('auth-sessions', $scope, $subject); $now = $this->now();
        return $this->store->transact($key, function ($state) use ($now) {
            $state = $this->state($state, $now); $result = [];
            foreach ($state === null ? [] : $state['sessions'] as $id => $record) {
                unset($record['digest'], $record['fingerprint'], $record['idle']); $result[] = ['id' => $id] + $record;
            }
            return $this->change($state, $now, $result);
        });
    }

    public static function reference($token): ?array
    {
        if (!is_string($token) || strlen($token) !== 102 || !preg_match('/\Asoss_([a-f0-9]{32})\.[a-f0-9]{64}\z/D', $token, $parts)) { return null; }
        return ['id' => $parts[1], 'digest' => hash('sha256', $token)];
    }
    public function policy(): array { return ['idle' => $this->idle, 'absolute' => $this->absolute, 'capacity' => $this->capacity]; }
    public static function strength(string $method): int
    {
        $methods = ['remembered' => 0, 'password' => 1, 'totp' => 2, 'recovery' => 2, 'webauthn' => 2];
        if (!isset($methods[$method])) { throw new ConfigurationException('Unknown authentication method.', 'configuration.authentication'); }
        return $methods[$method];
    }

    private function issue(string $scope, string $subject, string $fingerprint, string $epoch, string $method, string $label, ?array $replacement): ?SessionCredential
    {
        $key = Guard::key('auth-sessions', $scope, $subject); $strength = self::strength($method);
        if (!preg_match('/\A[a-f0-9]{64}\z/D', $fingerprint) || !preg_match('/\A[a-f0-9]{64}\z/D', $epoch)
            || strlen($label) > 128 || !preg_match('//u', $label) || preg_match('/[\x00-\x1f\x7f]/', $label)) {
            throw new ConfigurationException('Invalid session proof metadata.', 'configuration.auth_sessions');
        }
        $identity = $this->identities->load($scope, $subject);
        if ($identity === null || !hash_equals($identity['fingerprint'], $fingerprint)
            || ($identity['mfa_required'] && ($strength < 2 || $identity['factor'] === null))) { return null; }
        $now = $this->now(); $id = $replacement === null ? bin2hex(random_bytes(16)) : $replacement['id'];
        $token = 'soss_' . $id . '.' . bin2hex(random_bytes(32)); $digest = hash('sha256', $token);
        return $this->store->transact($key, function ($state) use ($fingerprint, $epoch, $method, $label, $replacement, $now, $id, $token, $digest) {
            $state = $this->state($state, $now);
            if ($state === null || !hash_equals($state['epoch'], $epoch)) { return $this->change($state, $now, null); }
            $state = RegistryState::forIdentity($state, $fingerprint);
            if ($replacement === null) {
                if (count($state['sessions']) >= $this->capacity) { throw new SecurityException('Session capacity reached; revoke an existing session first.', 'auth.session_capacity'); }
                if (isset($state['sessions'][$id])) { throw new SecurityException('Session ID allocation collided.', 'auth.session_collision'); }
                $record = ['digest' => $digest, 'fingerprint' => $fingerprint, 'method' => $method, 'created' => $now, 'seen' => $now,
                    'expires' => $now + $this->absolute, 'authenticated' => $method === 'remembered' ? 0 : $now, 'idle' => $this->idle, 'label' => $label,
                    'resumed' => false, 'grant' => null];
            } else {
                if (!isset($state['sessions'][$id]) || !hash_equals($state['sessions'][$id]['digest'], $replacement['digest'])
                    || !hash_equals($state['sessions'][$id]['fingerprint'], $fingerprint)) { return $this->change($state, $now, null); }
                $record = $state['sessions'][$id]; $record['digest'] = $digest; $record['method'] = $method;
                $record['seen'] = $now; $record['authenticated'] = $method === 'remembered' ? 0 : $now;
                $record['resumed'] = false;
            }
            $state['sessions'][$id] = $record;
            return $this->change($state, $now, new SessionCredential($token, $id, $record['expires']));
        });
    }

    private function state($state, int $now): ?array { return RegistryState::read($state, $now, $this->idle, $this->absolute); }
    private function change(?array $state, int $now, $result): Change { return RegistryState::change($state, $now, $result); }
    private function now(): int
    {
        $now = $this->clock->now();
        if ($now < 0 || $now > PHP_INT_MAX - 31536000) { throw new ConfigurationException('Authentication clock out of range.', 'configuration.clock'); }
        return $now;
    }
}
