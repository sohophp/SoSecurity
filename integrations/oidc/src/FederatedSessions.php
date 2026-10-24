<?php
declare(strict_types=1);

namespace SoSecurity\Oidc;

use SoSecurity\Auth\Account;
use SoSecurity\Auth\IdentityProvider;
use SoSecurity\Auth\IdentityState;
use SoSecurity\Auth\LoginResult;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Exception\DependencyException;
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
    private $factor;

    public function __construct(AtomicStore $store, IdentityProvider $provider, LinkRegistry $links,
        LogoutFence $fence, callable $requestGuard, ?SecondFactor $factor = null, ?Clock $clock = null,
        int $idle = 1800, int $absolute = 28800, int $capacity = 16)
    {
        Guard::duration($idle); Guard::duration($absolute);
        if ($idle > $absolute || $capacity < 1 || $capacity > 32) {
            throw new ConfigurationException('Invalid federated session limits.', 'configuration.federation');
        }
        $this->factor = $factor; $this->store = $store; $this->identity = new IdentityState($provider, $factor);
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
        $binding = $this->links->currentBinding($scope, $remote->issuer(), $remote->subject(), $account);
        if ($binding === null) { return null; }
        return $this->create($scope, $account, $identity, self::remoteData($remote), $binding, null, $label);
    }

    private function create(string $scope, Account $account, array $identity, array $remote,
        string $binding, ?string $method, string $label): ?SessionCredential
    {
        $now = $this->now();
        if ($remote['iat'] < max(0, $now - 86400)) { return null; }
        if (!$this->fence->allowsSession($scope, $remote['issuer'], $remote['remote'],
            $remote['sid'], $remote['iat'], $now)) { return null; }
        $id = bin2hex(random_bytes(16));
        $token = 'sofs_' . $id . '.' . bin2hex(random_bytes(32));
        $digest = hash('sha256', $token);
        $expires = $now + $this->absolute;
        $record = ['digest' => $digest, 'fingerprint' => $identity['fingerprint'], 'link' => $binding, 'mfa' => $method,
            'issuer' => $remote['issuer'], 'remote' => $remote['remote'],
            'sid' => $remote['sid'], 'iat' => $remote['iat'],
            'created' => $now, 'seen' => $now, 'expires' => $expires, 'label' => $label];
        $key = $this->key($scope, $account->subject());
        $this->store->transact($key, function ($old) use ($now, $id, $record) {
            $state = $this->read($old, $now);
            if ($state === null) { $state = ['v' => 2, 'sessions' => [], 'updated' => $now]; }
            if (count($state['sessions']) >= $this->capacity) {
                throw new SecurityException('Federated session capacity reached.', 'federation.session_capacity');
            }
            if (isset($state['sessions'][$id])) { throw new SecurityException('Federated session ID collision.', 'federation.session_collision'); }
            $state['sessions'][$id] = $record;
            return $this->change($state, $now, null);
        });
        $latest = $this->identity->load($scope, $account->subject());
        if (!$this->fence->allowsSession($scope, $record['issuer'], $record['remote'], $record['sid'], $record['iat'], $now)
            || $this->links->currentBinding($scope, $record['issuer'], $record['remote'], $account) !== $record['link']
            || !$this->matches($latest, $account) || ($latest['mfa_required'] && $method === null)
            || !hash_equals($identity['fingerprint'], $latest['fingerprint'])) {
            $this->revoke($scope, $account->subject(), $id);
            return null;
        }
        if ($this->verify($scope, $account->subject(), $token) === null) { return null; }
        return new SessionCredential($token, $id, $expires);
    }

    /** Begin a login bound to an unpredictable server-owned browser binding. Never accept a client-selected binding. */
    public function begin(string $scope, string $browserBinding, VerifiedSubject $remote, string $label = ''): LoginResult
    {
        $key = Guard::key('oidc-pending', $scope, $browserBinding);
        $this->request('federation_login', $scope);
        if (strlen($label) > 128 || !preg_match('//u', $label) || preg_match('/[\x00-\x1f\x7f]/', $label)) {
            throw new ConfigurationException('Invalid federated session label.', 'configuration.federation');
        }
        $account = $this->links->resolve($scope, $remote);
        if ($account === null) { return new LoginResult('denied'); }
        $identity = $this->identity->load($scope, $account->subject());
        if (!$this->matches($identity, $account)) { return new LoginResult('denied'); }
        $binding = $this->links->currentBinding($scope, $remote->issuer(), $remote->subject(), $account);
        if ($binding === null) { return new LoginResult('denied'); }
        if (!$identity['mfa_required']) {
            $now = $this->now();
            $this->store->transact($key, function ($old) use ($now) {
                $this->pending($old, $now); return new Change(null, 0, null);
            });
            $credential = $this->create($scope, $account, $identity, self::remoteData($remote), $binding, null, $label);
            return $credential === null ? new LoginResult('denied') : new LoginResult('authenticated', null, null, $credential, $account);
        }
        if ($identity['factor'] === null) { return new LoginResult('enrollment_required'); }
        $now = $this->now(); $token = bin2hex(random_bytes(32));
        $pending = ['v' => 1, 'digest' => hash('sha256', $token), 'subject' => $account->subject(),
            'fingerprint' => $identity['fingerprint'], 'factor' => $identity['factor'], 'link' => $binding,
            'remote' => self::remoteData($remote), 'issued' => $now, 'expires' => $now + 300, 'updated' => $now,
            'attempts' => 0, 'claim' => null, 'claim_until' => 0, 'label' => $label];
        $this->store->transact($key, function ($old) use ($pending, $now) {
            $this->pending($old, $now);
            return new Change($pending, $pending['expires'], null);
        });
        return new LoginResult('mfa_required', $token, $pending['expires']);
    }

    /** Complete one bounded challenge using the configured current local factor; never creates a local password session. */
    public function secondFactor(string $scope, string $browserBinding, $challenge, $proof): LoginResult
    {
        $key = Guard::key('oidc-pending', $scope, $browserBinding);
        $this->request('federation_second_factor', $scope);
        if (!self::hex($challenge, 64)) { return new LoginResult('denied'); }
        if ($this->factor === null) { throw new ConfigurationException('No local second factor is configured.', 'configuration.second_factor'); }
        $now = $this->now(); $digest = hash('sha256', $challenge); $claim = bin2hex(random_bytes(16));
        $pending = $this->store->transact($key, function ($old) use ($now, $digest, $claim) {
            $state = $this->pending($old, $now);
            if ($state === null || !hash_equals($state['digest'], $digest) || $state['attempts'] >= 5 || $state['claim_until'] > $now) {
                return $this->pendingChange($state, $now, null);
            }
            ++$state['attempts']; $state['claim'] = $claim; $state['claim_until'] = min($state['expires'], $now + 10);
            $state['updated'] = $now;
            return $this->pendingChange($state, $now, $state);
        });
        if ($pending === null) { return new LoginResult('denied'); }
        try {
            $identity = $this->pendingAuthority($scope, $pending);
            if ($identity === null) { $this->releasePending($key, $claim); return new LoginResult('denied'); }
            // The proof is consumed only by the adapter, outside any retryable storage callback.
            $method = $this->factor->verify($scope, $pending['subject'], $pending['factor'], $proof);
            if ($method === null) { $this->releasePending($key, $claim); return new LoginResult('denied'); }
            if (!in_array($method, ['totp', 'recovery', 'webauthn'], true) || SessionRegistry::strength($method) < 2) {
                throw new SecurityException('Local factor returned insufficient authority.', 'federation.factor_contract');
            }
            $identity = $this->pendingAuthority($scope, $pending);
            if ($identity === null) { $this->releasePending($key, $claim); return new LoginResult('denied'); }
            $this->request('federation_second_factor_current', $scope);
            $finished = $this->now();
            $consumed = $this->store->transact($key, function ($old) use ($finished, $digest, $claim) {
                $state = $this->pending($old, $finished);
                if ($state === null || $state['claim'] !== $claim || !hash_equals($state['digest'], $digest)
                    || $state['claim_until'] <= $finished) { return $this->pendingChange($state, $finished, false); }
                return new Change(null, 0, true);
            });
            if (!$consumed) { return new LoginResult('denied'); }
            $credential = $this->create($scope, $identity['account'], $identity, $pending['remote'], $pending['link'], $method, $pending['label']);
            return $credential === null ? new LoginResult('denied') : new LoginResult('authenticated', null, null, $credential, $identity['account']);
        } catch (\Throwable $error) {
            $this->releasePending($key, $claim);
            // Do not expose adapter messages or repeat a proof whose consumption may already have happened.
            throw new DependencyException('Federated second-factor service unavailable.', 'federation.factor_unavailable');
        }
    }

    public function cancel(string $scope, string $browserBinding): void
    {
        $key = Guard::key('oidc-pending', $scope, $browserBinding);
        $this->request('federation_cancel', $scope); $now = $this->now();
        $this->store->transact($key, function ($old) use ($now) {
            $this->pending($old, $now); return new Change(null, 0, null);
        });
    }

    private static function remoteData(VerifiedSubject $remote): array
    {
        return ['issuer' => $remote->issuer(), 'remote' => $remote->subject(), 'sid' => $remote->providerSessionId(), 'iat' => $remote->issuedAt()];
    }

    private function request(string $phase, string $scope): void
    {
        if (($this->guard)($phase, $scope) !== true) { throw new SecurityException('Federation request was not protected.', 'federation.request_denied'); }
    }

    private function pendingAuthority(string $scope, array $pending): ?array
    {
        $identity = $this->identity->load($scope, $pending['subject']); $now = $this->now();
        if ($now < $pending['updated']) { throw new SecurityException('Federated login clock moved backwards.', 'federation.clock'); }
        if ($identity === null || $identity['factor'] !== $pending['factor'] || !hash_equals($identity['fingerprint'], $pending['fingerprint'])
            || $now >= $pending['expires'] || $now >= $pending['claim_until'] || $pending['remote']['iat'] < max(0, $now - 86400)
            || $this->links->currentBinding($scope, $pending['remote']['issuer'], $pending['remote']['remote'], $identity['account']) !== $pending['link']
            || !$this->fence->allowsSession($scope, $pending['remote']['issuer'], $pending['remote']['remote'], $pending['remote']['sid'], $pending['remote']['iat'], $pending['issued'])) {
            return null;
        }
        $finished = $this->now();
        if ($finished < $now) { throw new SecurityException('Federated login clock moved backwards.', 'federation.clock'); }
        return $finished >= $pending['expires'] || $finished >= $pending['claim_until'] ? null : $identity;
    }

    private function releasePending(string $key, string $claim): void
    {
        $now = $this->now();
        $this->store->transact($key, function ($old) use ($now, $claim) {
            $state = $this->pending($old, $now);
            if ($state !== null && $state['claim'] === $claim) {
                $state['claim'] = null; $state['claim_until'] = 0;
                if ($state['attempts'] >= 5) { $state = null; }
            }
            return $this->pendingChange($state, $now, null);
        });
    }

    private function pendingChange(?array $state, int $now, $result): Change
    {
        if ($state !== null) { $state['updated'] = $now; }
        return new Change($state, $state === null ? 0 : $state['expires'], $result);
    }

    private function pending($state, int $now): ?array
    {
        if ($state === null) { return null; }
        $fields = ['v', 'digest', 'subject', 'fingerprint', 'factor', 'link', 'remote', 'issued', 'expires', 'updated', 'attempts', 'claim', 'claim_until', 'label'];
        if (!is_array($state) || count($state) !== count($fields) || array_diff(array_keys($state), $fields) || $state['v'] !== 1) {
            throw new StorageException('Corrupt pending federated login.', 'storage.corrupt');
        }
        foreach (['digest', 'fingerprint', 'link'] as $field) {
            if (!self::hex($state[$field], 64)) { throw new StorageException('Corrupt federated login binding.', 'storage.corrupt'); }
        }
        foreach (['subject', 'factor'] as $field) {
            if (!is_string($state[$field]) || $state[$field] === '' || strlen($state[$field]) > 256
                || !preg_match('//u', $state[$field]) || preg_match('/[\x00-\x1f\x7f]/', $state[$field])) {
                throw new StorageException('Corrupt federated login identity.', 'storage.corrupt');
            }
        }
        foreach (['issued', 'expires', 'updated', 'attempts', 'claim_until'] as $field) {
            if (!is_int($state[$field]) || $state[$field] < 0) { throw new StorageException('Corrupt federated login budget.', 'storage.corrupt'); }
        }
        $remote = $state['remote'];
        if (!is_array($remote) || count($remote) !== 4 || array_diff(array_keys($remote), ['issuer', 'remote', 'sid', 'iat'])
            || !is_string($remote['issuer']) || strlen($remote['issuer']) > 2048 || !preg_match('/\Ahttps:\/\/[^\x00-\x20\x7f]+\z/D', $remote['issuer'])
            || !self::ascii($remote['remote'], 255) || ($remote['sid'] !== null && !self::ascii($remote['sid'], 255))
            || !is_int($remote['iat']) || $remote['iat'] < 0
            || !is_string($state['label']) || strlen($state['label']) > 128 || !preg_match('//u', $state['label']) || preg_match('/[\x00-\x1f\x7f]/', $state['label'])
            || $state['expires'] <= $state['issued'] || $state['expires'] - $state['issued'] > 300
            || $state['updated'] < $state['issued'] || $state['attempts'] > 5
            || ($state['claim'] !== null && !self::hex($state['claim'], 32))
            || ($state['claim'] === null && $state['claim_until'] !== 0)
            || ($state['claim'] !== null && ($state['claim_until'] <= $state['issued'] || $state['attempts'] === 0))
            || $state['claim_until'] > $state['expires'] || $state['claim_until'] > $state['updated'] + 10) {
            throw new StorageException('Corrupt pending federated login fields.', 'storage.corrupt');
        }
        if ($state['updated'] > $now) { throw new SecurityException('Federated login clock moved backwards.', 'federation.clock'); }
        return $state['expires'] <= $now ? null : $state;
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
        $checkedAt = $this->now();
        if ($checkedAt < $now) { throw new SecurityException('Federated session clock moved backwards.', 'federation.clock'); }
        if (!$this->liveAt($record, $checkedAt)) { return null; }
        $now = $checkedAt;
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
        $finishedAt = $this->now();
        if ($finishedAt < $now) { throw new SecurityException('Federated session clock moved backwards.', 'federation.clock'); }
        $record['seen'] = $now;
        if (!$this->liveAt($record, $finishedAt)) { return null; }
        return new FederatedSession($currentAccount, $reference['id'], $record['created'], $record['expires'], $record['mfa']);
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
        return $account instanceof Account && $this->matches($identity, $account) && (!$identity['mfa_required'] || $record['mfa'] !== null)
            && hash_equals($record['fingerprint'], $identity['fingerprint'])
            && $this->links->currentBinding($scope, $record['issuer'], $record['remote'], $account) === $record['link']
            && $this->fence->allowsSession($scope, $record['issuer'], $record['remote'], $record['sid'],
                $record['iat'], $record['created']);
    }

    private function matches(?array $identity, Account $account): bool
    {
        return $identity !== null && $identity['account']->scope() === $account->scope()
            && $identity['account']->subject() === $account->subject()
            && hash_equals($identity['account']->fingerprint(), $account->fingerprint());
    }

    private function liveAt(array $record, int $now): bool
    {
        return $now < $record['expires'] && $now - $record['seen'] < $this->idle
            && $now - $record['created'] < $this->absolute;
    }

    private function read($old, int $now): ?array
    {
        if ($old === null) { return null; }
        if (!is_array($old) || count($old) !== 3) { throw new StorageException('Corrupt federated sessions.', 'storage.corrupt'); }
        $keys = array_keys($old); sort($keys);
        if ($keys !== ['sessions', 'updated', 'v'] || !in_array($old['v'], [1, 2], true) || !is_array($old['sessions'])
            || count($old['sessions']) > 32 || !is_int($old['updated']) || $old['updated'] < 0) {
            throw new StorageException('Corrupt federated sessions.', 'storage.corrupt');
        }
        if ($old['updated'] > $now) { throw new SecurityException('Federated session clock moved backwards.', 'federation.clock'); }
        foreach ($old['sessions'] as $id => $record) {
            if (!self::hex($id, 32) || !is_array($record) || count($record) !== ($old['v'] === 1 ? 10 : 12)) { throw new StorageException('Corrupt federated session.', 'storage.corrupt'); }
            $fields = array_keys($record); sort($fields);
            $expected = ['created', 'digest', 'expires', 'fingerprint', 'iat', 'issuer', 'label', 'remote', 'seen', 'sid'];
            if ($old['v'] === 2) { $expected[] = 'link'; $expected[] = 'mfa'; sort($expected); }
            if ($fields !== $expected || ($old['v'] === 2 && (!self::hex($record['link'], 64) || !in_array($record['mfa'], [null, 'totp', 'recovery', 'webauthn'], true)))
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
        // A legacy session never recorded its link generation; attaching today's link would revive old authority.
        return $old['v'] === 1 ? null : $old;
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
    public function __debugInfo(): array { return ['federated_sessions' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Rebuild federated session services.', 'configuration.federation_serialization'); }
    public function __wakeup(): void { throw new ConfigurationException('Rebuild federated session services.', 'configuration.federation_serialization'); }
}
