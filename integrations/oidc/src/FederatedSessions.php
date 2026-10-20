<?php
declare(strict_types=1);

namespace SoSecurity\Oidc;

use SoSecurity\Auth\Account;
use SoSecurity\Auth\IdentityProvider;
use SoSecurity\Auth\IdentityState;
use SoSecurity\Auth\SecondFactor;
use SoSecurity\Auth\SessionCredential;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Separate OIDC session authority; never writes a local password/MFA SessionRegistry record. */
final class FederatedSessions
{
    private $store;
    private $identity;
    private $links;
    private $fence;
    private $guard;
    private $clock;
    private $idle;
    private $absolute;
    private $capacity;

    public function __construct(AtomicStore $store, IdentityProvider $provider, LinkRegistry $links,
        LogoutFence $fence, callable $requestGuard, ?SecondFactor $factor = null, ?Clock $clock = null,
        int $idle = 1800, int $absolute = 28800, int $capacity = 16)
    {
        Guard::duration($idle); Guard::duration($absolute);
        if ($idle > $absolute || $capacity < 1 || $capacity > 32) {
            throw new ConfigurationException('Invalid federated session limits.', 'configuration.federation');
        }
        $this->store = $store; $this->identity = new IdentityState($provider, $factor);
        $this->links = $links; $this->fence = $fence; $this->guard = $requestGuard;
        $this->clock = $clock ?? new SystemClock(); $this->idle = $idle;
        $this->absolute = $absolute; $this->capacity = $capacity;
    }

    public function issue(string $scope, VerifiedSubject $remote, string $label = ''): ?SessionCredential
    {
        Guard::label($scope);
        if (($this->guard)('federation_login', $scope) !== true) {
            throw new SecurityException('Federated login request was not protected.', 'federation.request_denied');
        }
        if (strlen($label) > 128 || !preg_match('//u', $label) || preg_match('/[\x00-\x1f\x7f]/', $label)) {
            throw new ConfigurationException('Invalid federated session label.', 'configuration.federation');
        }
        $account = $this->links->resolve($scope, $remote);
        if ($account === null) { return null; }
        $identity = $this->identity->load($scope, $account->subject());
        if (!$this->matches($identity, $account) || $identity['mfa_required']) { return null; }
        $now = $this->now();
        if (!$this->fence->allowsSession($scope, $remote->issuer(), $remote->subject(),
            $remote->providerSessionId(), $remote->issuedAt(), $now)) { return null; }
        $id = bin2hex(random_bytes(16));
        $token = 'sofs_' . $id . '.' . bin2hex(random_bytes(32));
        $digest = hash('sha256', $token);
        $expires = $now + $this->absolute;
        $record = ['digest' => $digest, 'fingerprint' => $identity['fingerprint'],
            'issuer' => $remote->issuer(), 'remote' => $remote->subject(),
            'sid' => $remote->providerSessionId(), 'iat' => $remote->issuedAt(),
            'created' => $now, 'seen' => $now, 'expires' => $expires, 'label' => $label];
        $key = $this->key($scope, $account->subject());
        $this->store->transact($key, function ($old) use ($now, $id, $record) {
            $state = $this->read($old, $now);
            if ($state === null) { $state = ['v' => 1, 'sessions' => [], 'updated' => $now]; }
            if (count($state['sessions']) >= $this->capacity) {
                throw new SecurityException('Federated session capacity reached.', 'federation.session_capacity');
            }
            if (isset($state['sessions'][$id])) { throw new SecurityException('Federated session ID collision.', 'federation.session_collision'); }
            $state['sessions'][$id] = $record;
            return $this->change($state, $now, null);
        });
        $latest = $this->identity->load($scope, $account->subject());
        if (!$this->fence->allowsSession($scope, $record['issuer'], $record['remote'], $record['sid'], $record['iat'], $now)
            || !$this->links->matchesCurrentLink($scope, $record['issuer'], $record['remote'], $account)
            || !$this->matches($latest, $account) || $latest['mfa_required']
            || !hash_equals($identity['fingerprint'], $latest['fingerprint'])) {
            $this->revoke($scope, $account->subject(), $id);
            return null;
        }
        if ($this->verify($scope, $account->subject(), $token) === null) { return null; }
        return new SessionCredential($token, $id, $expires);
    }

    public function verify(string $scope, string $subject, $token): ?FederatedSession
    {
        $key = $this->key($scope, $subject);
        $reference = self::reference($token);
        if ($reference === null) { return null; }
        $now = $this->now();
        $record = $this->store->transact($key, function ($old) use ($reference, $now) {
            $state = $this->read($old, $now);
            $record = $state['sessions'][$reference['id']] ?? null;
            return $this->change($state, $now, $record !== null && hash_equals($record['digest'], $reference['digest']) ? $record : null);
        });
        if ($record === null) { return null; }
        $identity = $this->identity->load($scope, $subject);
        $account = $identity['account'] ?? null;
        if (!$this->validAuthority($scope, $record, $identity, $account)) {
            $this->revoke($scope, $subject, $reference['id']); return null;
        }
        $touched = $this->store->transact($key, function ($old) use ($reference, $record, $now) {
            $state = $this->read($old, $now);
            $current = $state['sessions'][$reference['id']] ?? null;
            if ($current === null || $current !== $record || !hash_equals($current['digest'], $reference['digest'])) {
                return $this->change($state, $now, false);
            }
            $current['seen'] = $now;
            $state['sessions'][$reference['id']] = $current;
            return $this->change($state, $now, true);
        });
        $latest = $this->identity->load($scope, $subject);
        $currentAccount = $latest['account'] ?? null;
        if (!$touched || !$currentAccount instanceof Account
            || !$this->validAuthority($scope, $record, $latest, $currentAccount)) { return null; }
        return new FederatedSession($currentAccount, $reference['id'], $record['created'], $record['expires']);
    }

    public function revoke(string $scope, string $subject, string $id): bool
    {
        $key = $this->key($scope, $subject);
        if (!self::hex($id, 32)) { return false; }
        $now = $this->now();
        return $this->store->transact($key, function ($old) use ($id, $now) {
            $state = $this->read($old, $now);
            $exists = $state !== null && isset($state['sessions'][$id]);
            if ($exists) { unset($state['sessions'][$id]); }
            return $this->change($state, $now, $exists);
        });
    }

    public function revokeAll(string $scope, string $subject): void
    {
        $key = $this->key($scope, $subject);
        $now = $this->now();
        $this->store->transact($key, function ($old) use ($now) {
            $this->read($old, $now);
            return new Change(null, 0, null);
        });
    }

    /** Idempotent LogoutProcessor callback: durable fence makes matching tokens fail every later verify. */
    public function revokeFromProvider(VerifiedLogout $logout, string $scope): bool
    {
        $this->fence->record($scope, $logout);
        return true;
    }

    public static function reference($token): ?array
    {
        if (!is_string($token) || strlen($token) !== 102
            || !preg_match('/\Asofs_([a-f0-9]{32})\.[a-f0-9]{64}\z/D', $token, $parts)) { return null; }
        return ['id' => $parts[1], 'digest' => hash('sha256', $token)];
    }

    private function validAuthority(string $scope, array $record, ?array $identity, $account): bool
    {
        return $account instanceof Account && $this->matches($identity, $account) && !$identity['mfa_required']
            && hash_equals($record['fingerprint'], $identity['fingerprint'])
            && $this->links->matchesCurrentLink($scope, $record['issuer'], $record['remote'], $account)
            && $this->fence->allowsSession($scope, $record['issuer'], $record['remote'], $record['sid'],
                $record['iat'], $record['created']);
    }

    private function matches(?array $identity, Account $account): bool
    {
        return $identity !== null && $identity['account']->scope() === $account->scope()
            && $identity['account']->subject() === $account->subject()
            && hash_equals($identity['account']->fingerprint(), $account->fingerprint());
    }

    private function read($old, int $now): ?array
    {
        if ($old === null) { return null; }
        if (!is_array($old)) { throw new StorageException('Corrupt federated sessions.', 'storage.corrupt'); }
        $keys = array_keys($old); sort($keys);
        if ($keys !== ['sessions', 'updated', 'v'] || $old['v'] !== 1 || !is_array($old['sessions'])
            || count($old['sessions']) > 32 || !is_int($old['updated']) || $old['updated'] < 0) {
            throw new StorageException('Corrupt federated sessions.', 'storage.corrupt');
        }
        if ($old['updated'] > $now) { throw new SecurityException('Federated session clock moved backwards.', 'federation.clock'); }
        foreach ($old['sessions'] as $id => $record) {
            if (!self::hex($id, 32) || !is_array($record)) { throw new StorageException('Corrupt federated session.', 'storage.corrupt'); }
            $fields = array_keys($record); sort($fields);
            if ($fields !== ['created', 'digest', 'expires', 'fingerprint', 'iat', 'issuer', 'label', 'remote', 'seen', 'sid']
                || !self::hex($record['digest'], 64) || !self::hex($record['fingerprint'], 64)
                || !is_string($record['issuer']) || strlen($record['issuer']) > 2048
                || preg_match('/\Ahttps:\/\/[^\x00-\x20\x7f]+\z/D', $record['issuer']) !== 1
                || !self::ascii($record['remote'], 255)
                || ($record['sid'] !== null && !self::ascii($record['sid'], 255))
                || !is_string($record['label']) || strlen($record['label']) > 128
                || !preg_match('//u', $record['label']) || preg_match('/[\x00-\x1f\x7f]/', $record['label'])
                || !is_int($record['iat']) || $record['iat'] < 0
                || !is_int($record['created']) || $record['created'] < 0
                || !is_int($record['seen']) || $record['seen'] < $record['created'] || $record['seen'] > $now
                || !is_int($record['expires']) || $record['expires'] <= $record['seen']
                || $record['expires'] - $record['created'] > 31536000) {
                throw new StorageException('Corrupt federated session.', 'storage.corrupt');
            }
            if ($record['expires'] <= $now || $now - $record['seen'] >= $this->idle
                || $now - $record['created'] >= $this->absolute) { unset($old['sessions'][$id]); }
        }
        return $old;
    }

    private function change(?array $state, int $now, $result): Change
    {
        if ($state !== null) {
            if ($state['sessions'] === []) { $state = null; }
            else { $state['updated'] = $now; }
        }
        return new Change($state, 0, $result);
    }

    private function key(string $scope, string $subject): string { return Guard::key('oidc-sessions', $scope, Guard::label($subject)); }
    private static function hex($value, int $size): bool { return is_string($value) && preg_match('/\A[a-f0-9]{' . $size . '}\z/D', $value) === 1; }
    private static function ascii($value, int $limit): bool
    {
        return is_string($value) && $value !== '' && strlen($value) <= $limit
            && preg_match('/\A[\x21-\x7e]+\z/D', $value) === 1;
    }
    private function now(): int
    {
        $now = $this->clock->now();
        if ($now < 0 || $now > PHP_INT_MAX - 31536000) {
            throw new SecurityException('Federated session clock out of range.', 'federation.clock');
        }
        return $now;
    }
}
