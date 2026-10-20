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

/** Explicit request-driven authentication. Guard must confirm host CSRF, transport and request budgets. */
final class AuthenticationFlow
{
    private $store;
    private $provider;
    private $sessions;
    private $guard;
    private $factor;
    private $identities;
    private $clock;
    private $ttl;
    private $lease;
    private $attempts;

    public function __construct(AtomicStore $store, IdentityProvider $provider, SessionRegistry $sessions, callable $requestGuard,
        ?SecondFactor $factor = null, ?Clock $clock = null, int $challengeTtl = 300, int $claimSeconds = 10, int $attempts = 5)
    {
        if ($challengeTtl < 30 || $challengeTtl > 600 || $claimSeconds < 1 || $claimSeconds > 30
            || $attempts < 1 || $attempts > 10) { throw new ConfigurationException('Invalid authentication challenge budget.', 'configuration.authentication'); }
        $this->store = $store; $this->provider = $provider; $this->sessions = $sessions; $this->guard = $requestGuard;
        $this->factor = $factor; $this->identities = new IdentityState($provider, $factor); $this->clock = $clock ?? new SystemClock();
        $this->ttl = $challengeTtl; $this->lease = $claimSeconds; $this->attempts = $attempts;
    }

    /** Optional currentToken requests reauthentication of exactly that session, not a second independent login. */
    public function password(string $scope, string $binding, $identifier, $password, string $label = '', $currentToken = null): LoginResult
    {
        $key = Guard::key('auth-pending', $scope, $binding); $this->guard('password', $scope);
        if (!is_string($identifier) || $identifier === '' || strlen($identifier) > 256 || !preg_match('//u', $identifier)
            || preg_match('/[\x00-\x1f\x7f]/', $identifier) || !is_string($password) || $password === ''
            || strlen($password) > 4096 || strpos($password, "\0") !== false) { return new LoginResult('denied'); }
        if (strlen($label) > 128 || !preg_match('//u', $label) || preg_match('/[\x00-\x1f\x7f]/', $label)) {
            throw new ConfigurationException('Invalid device label.', 'configuration.auth_sessions');
        }
        $account = $this->provider->authenticate($scope, $identifier, $password);
        if ($account === null || !$account->enabled()) { return new LoginResult('denied'); }
        if ($account->scope() !== $scope) { throw new SecurityException('Authentication returned a cross-scope identity.', 'auth.provider'); }
        $identity = $this->identities->load($scope, $account->subject());
        if ($identity === null || !hash_equals($account->fingerprint(), $identity['account']->fingerprint())) { return new LoginResult('denied'); }
        $replacement = null;
        if ($currentToken !== null) {
            if ($this->sessions->verify($scope, $account->subject(), $currentToken) === null) { return new LoginResult('denied'); }
            $replacement = SessionRegistry::reference($currentToken);
        }
        $epoch = $this->sessions->epoch($scope, $account->subject());
        if ($epoch === null) { return new LoginResult('denied'); }
        if (!$identity['mfa_required']) {
            return $this->finish($scope, $account->subject(), $identity['fingerprint'], $epoch, 'password', $label, $replacement);
        }
        if ($identity['factor'] === null) { return new LoginResult('enrollment_required'); }
        $now = $this->now(); $token = bin2hex(random_bytes(32));
        $pending = ['v' => 1, 'token_digest' => hash('sha256', $token), 'subject' => $account->subject(), 'fingerprint' => $identity['fingerprint'],
            'factor' => $identity['factor'], 'epoch' => $epoch, 'issued' => $now, 'expires' => $now + $this->ttl, 'attempts' => 0,
            'claim' => null, 'claim_until' => 0, 'label' => $label, 'replacement' => $replacement, 'updated' => $now];
        $this->store->transact($key, function ($old) use ($pending, $now) { $this->state($old, $now); return new Change($pending, $pending['expires'], null); });
        return new LoginResult('mfa_required', $token, $pending['expires']);
    }

    public function secondFactor(string $scope, string $binding, $challenge, $proof): LoginResult
    {
        $key = Guard::key('auth-pending', $scope, $binding); $this->guard('second_factor', $scope);
        if (!is_string($challenge) || !preg_match('/\A[a-f0-9]{64}\z/D', $challenge)) { return new LoginResult('denied'); }
        if ($this->factor === null) { throw new ConfigurationException('No second-factor adapter is configured.', 'configuration.second_factor'); }
        $now = $this->now(); $claim = bin2hex(random_bytes(16)); $digest = hash('sha256', $challenge);
        $pending = $this->store->transact($key, function ($state) use ($now, $claim, $digest) {
            $state = $this->state($state, $now);
            if ($state === null || !hash_equals($state['token_digest'], $digest) || $state['attempts'] >= $this->attempts || $state['claim_until'] > $now) {
                return $this->change($state, null, $now);
            }
            $state['claim'] = $claim; $state['claim_until'] = min($state['expires'], $now + $this->lease); ++$state['attempts'];
            return $this->change($state, $state, $now);
        });
        if ($pending === null) { return new LoginResult('denied'); }
        try {
            $identity = $this->identities->load($scope, $pending['subject']);
            if (!$this->matches($identity, $pending) || $this->sessions->epoch($scope, $pending['subject']) !== $pending['epoch']) {
                $this->release($key, $claim, false); return new LoginResult('denied');
            }
            $method = $this->factor->verify($scope, $pending['subject'], $pending['factor'], $proof);
            if ($method === null) { $this->release($key, $claim, false); return new LoginResult('denied'); }
            if (SessionRegistry::strength($method) < 2) { throw new SecurityException('Second-factor adapter returned an insufficient proof.', 'auth.factor_contract'); }
            if (!$this->matches($this->identities->load($scope, $pending['subject']), $pending)) {
                $this->release($key, $claim, false); return new LoginResult('denied');
            }
            $finished = $this->now();
            $consumed = $this->store->transact($key, function ($state) use ($claim, $digest, $finished) {
                $state = $this->state($state, $finished);
                if ($state === null || $state['claim'] !== $claim || !hash_equals($state['token_digest'], $digest)
                    || $state['claim_until'] <= $finished) { return $this->change($state, false, $finished); }
                return new Change(null, 0, true);
            });
            if (!$consumed) { return new LoginResult('denied'); }
            return $this->finish($scope, $pending['subject'], $pending['fingerprint'], $pending['epoch'], $method, $pending['label'], $pending['replacement']);
        } catch (\Throwable $e) {
            // Service failures refund the flow attempt without extending its lifetime. Proofs already consumed stay consumed.
            $this->release($key, $claim, true); throw $e;
        }
    }

    public function cancel(string $scope, string $binding): void
    {
        $key = Guard::key('auth-pending', $scope, $binding); $this->guard('cancel', $scope); $now = $this->now();
        $this->store->transact($key, function ($state) use ($now) { $this->state($state, $now); return new Change(null, 0, null); });
    }

    private function finish(string $scope, string $subject, string $fingerprint, string $epoch, string $method, string $label, ?array $replacement): LoginResult
    {
        $credential = $replacement === null ? $this->sessions->register($scope, $subject, $fingerprint, $epoch, $method, $label)
            : $this->sessions->replace($scope, $subject, $fingerprint, $epoch, $method, $replacement['id'], $replacement['digest']);
        if ($credential === null) { return new LoginResult('denied'); }
        $verified = $this->sessions->verify($scope, $subject, $credential->token());
        return $verified === null ? new LoginResult('denied') : new LoginResult('authenticated', null, null, $credential, $verified->account());
    }
    private function matches(?array $identity, array $pending): bool
    {
        return $identity !== null && hash_equals($identity['fingerprint'], $pending['fingerprint']) && $identity['factor'] === $pending['factor'];
    }
    private function release(string $key, string $claim, bool $refund): void
    {
        $now = $this->now();
        $this->store->transact($key, function ($state) use ($now, $claim, $refund) {
            $state = $this->state($state, $now);
            if ($state !== null && $state['claim'] === $claim) {
                $state['claim'] = null; $state['claim_until'] = 0;
                if ($refund) { $state['attempts'] = max(0, $state['attempts'] - 1); }
                if ($state['attempts'] >= $this->attempts) { $state = null; }
            }
            return $this->change($state, null, $now);
        });
    }
    private function guard(string $phase, string $scope): void
    {
        if (($this->guard)($phase, $scope) !== true) { throw new SecurityException('Host request protection was not confirmed.', 'auth.request_denied'); }
    }
    private function state($state, int $now): ?array
    {
        if ($state === null) { return null; }
        $fields = ['v', 'token_digest', 'subject', 'fingerprint', 'factor', 'epoch', 'issued', 'expires', 'attempts', 'claim', 'claim_until', 'label', 'replacement', 'updated'];
        if (!is_array($state) || !$this->fields($state, $fields) || $state['v'] !== 1) { throw new StorageException('Corrupt pending login.', 'storage.corrupt'); }
        foreach (['token_digest', 'fingerprint', 'epoch'] as $field) {
            if (!is_string($state[$field]) || !preg_match('/\A[a-f0-9]{64}\z/D', $state[$field])) { throw new StorageException('Corrupt pending login binding.', 'storage.corrupt'); }
        }
        foreach (['issued', 'expires', 'attempts', 'claim_until', 'updated'] as $field) {
            if (!is_int($state[$field]) || $state[$field] < 0) { throw new StorageException('Corrupt pending login budget.', 'storage.corrupt'); }
        }
        if (!is_string($state['subject']) || $state['subject'] === '' || strlen($state['subject']) > 256 || !preg_match('//u', $state['subject']) || preg_match('/[\x00-\x1f\x7f]/', $state['subject'])
            || !is_string($state['factor']) || $state['factor'] === '' || strlen($state['factor']) > 256 || !preg_match('//u', $state['factor']) || preg_match('/[\x00-\x1f\x7f]/', $state['factor'])
            || !is_string($state['label']) || strlen($state['label']) > 128 || !preg_match('//u', $state['label']) || preg_match('/[\x00-\x1f\x7f]/', $state['label'])
            || $state['expires'] <= $state['issued'] || $state['expires'] - $state['issued'] > 600 || $state['attempts'] > 10
            || ($state['claim'] !== null && (!is_string($state['claim']) || !preg_match('/\A[a-f0-9]{32}\z/D', $state['claim'])))
            || ($state['claim'] === null && $state['claim_until'] !== 0) || $state['claim_until'] > $state['expires']
            || ($state['claim'] !== null && ($state['claim_until'] <= $state['issued'] || $state['attempts'] === 0))
            || $state['updated'] < $state['issued']) {
            throw new StorageException('Corrupt pending login fields.', 'storage.corrupt');
        }
        if ($state['replacement'] !== null && (!is_array($state['replacement']) || !$this->fields($state['replacement'], ['id', 'digest'])
            || !is_string($state['replacement']['id']) || !preg_match('/\A[a-f0-9]{32}\z/D', $state['replacement']['id'])
            || !is_string($state['replacement']['digest']) || !preg_match('/\A[a-f0-9]{64}\z/D', $state['replacement']['digest']))) {
            throw new StorageException('Corrupt reauthentication binding.', 'storage.corrupt');
        }
        if ($state['updated'] > $now) { throw new SecurityException('Authentication clock moved backwards.', 'auth.clock'); }
        return $state['expires'] <= $now ? null : $state;
    }
    private function change(?array $state, $result, int $now): Change
    {
        if ($state !== null) { $state['updated'] = $now; }
        return new Change($state, $state === null ? 0 : $state['expires'], $result);
    }
    private function fields(array $value, array $fields): bool { $keys = array_keys($value); sort($keys); sort($fields); return $keys === $fields; }
    private function now(): int
    {
        $now = $this->clock->now();
        if ($now < 0 || $now > PHP_INT_MAX - 31536000) { throw new ConfigurationException('Authentication clock out of range.', 'configuration.clock'); }
        return $now;
    }
    public function __debugInfo(): array { return ['authentication' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Do not serialize authentication flows.', 'configuration.identity_serialization'); }
}
