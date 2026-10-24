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
    private $boundary;

    public function __construct(AtomicStore $store, IdentityProvider $provider, ?SecondFactor $factor = null,
        ?Clock $clock = null, int $idle = 1800, int $absolute = 28800, int $capacity = 16, ?\SoSecurity\Account\StateBoundary $boundary = null)
    {
        if($boundary===null&&($store instanceof \SoSecurity\Account\WitnessedStore||\SoSecurity\Storage\FileStateBoundary::protects($store))){throw new ConfigurationException('Protected sessions require their exact state authority.','configuration.state_boundary');}
        if($boundary!==null&&!$boundary->semanticAuthority()){throw new ConfigurationException('Protected authentication requires persisted operation descriptions.','configuration.state_boundary');}
        Guard::duration($idle); Guard::duration($absolute);
        if ($idle > $absolute || $capacity < 1 || $capacity > 32) { throw new ConfigurationException('Invalid session limits.', 'configuration.auth_sessions'); }
        $this->boundary = $boundary; $this->store = $boundary === null ? $store : $boundary->protect($store); $this->identities = new IdentityState($provider, $factor); $this->clock = $clock ?? new SystemClock();
        $this->idle = $idle; $this->absolute = $absolute; $this->capacity = $capacity;
    }

    public function boundTo(\SoSecurity\Account\StateBoundary $boundary): bool { return $this->boundary === $boundary; }
    public function requiresStateBoundary(): bool { return $this->boundary !== null; }
    public function statePolicy(\SoSecurity\Storage\FileStore $store,\SoSecurity\Account\ManagedSecondFactor $factor,\SoSecurity\Account\LocalStateWitness $witness):?array{if($this->boundary===null||!$this->boundary->boundTo($witness)||!$this->store instanceof \SoSecurity\Account\WitnessedStore||!$this->store->protects($store)||!$this->identities->matchesStatePolicy($factor)){return null;}return ['idle'=>$this->idle,'absolute'=>$this->absolute,'clock'=>$this->clock];}
    /** Pure exact physical binding; no grant, registry read, or authority reset. */
    public function credentialInstallationContext(\SoSecurity\Storage\FileStore $store,\SoSecurity\Account\FactorRegistry $registry,\SoSecurity\Account\LocalStateWitness $witness,string $scope,string $subject):?array
    {
        $key=Guard::key('auth-sessions',$scope,$subject);
        if($this->boundary===null||!$this->boundary->recoveryAuthority($witness)||!$witness->allowsScope($scope)||!$this->store instanceof \SoSecurity\Account\WitnessedStore||!$this->store->protects($store)||!$this->identities->matchesRecoveryRegistry($registry)){return null;}
        return ['key'=>$key,'reference'=>$store->snapshotReference($key),'policy'=>hash('sha256',json_encode([$this->idle,$this->absolute,$this->capacity])),'clock'=>$this->clock];
    }
    public function credentialRegistryContext(IdentityProvider $provider,?SecondFactor $factor,Clock $clock,\SoSecurity\Account\StateBoundary $boundary):bool{return $this->boundary===$boundary&&$this->clock===$clock&&$provider instanceof PasswordIdentityProvider&&$factor instanceof \SoSecurity\Account\ManagedSecondFactor&&$this->identities->matchesProviders($provider,$factor);}
    /** Pure matching identity/policy extraction; no session lookup or permission is granted. */
    public function operationRolePolicy(\SoSecurity\Authorization\Authorizer $authorizer):?\SoSecurity\Authorization\RolePolicy{return $this->boundary===null?null:$this->identities->operationRolePolicy($authorizer);}
    /** Pure configuration agreement only; no session lookup, evaluator call or permission is granted. */
    public function operationSnapshotPolicy(\SoSecurity\Authorization\Authorizer $authorizer,\SoSecurity\Account\StateAccountPolicy $state):?\SoSecurity\Authorization\SnapshotPolicy
    {
        if($this->boundary===null||!$state->credentialContext($this->store,$this,$this->clock,$this->boundary)){return null;}
        return $this->identities->operationSnapshotPolicy($authorizer,$state);
    }
    private function within(string $action,string $scope,callable $operation) { if($this->boundary===null){return $operation();}$this->boundary->assertScope($scope);return $this->boundary->run('sessions.'.$action,$operation); }
    private function inputIssue(string $scope,string $subject,string $fingerprint,string $epoch,string $method,string $label): void
    {
        Guard::key('auth-sessions',$scope,$subject);self::strength($method);
        if(!preg_match('/\A[a-f0-9]{64}\z/D',$fingerprint)||!preg_match('/\A[a-f0-9]{64}\z/D',$epoch)||strlen($label)>128||!preg_match('//u',$label)||preg_match('/[\x00-\x1f\x7f]/',$label)){throw new ConfigurationException('Invalid session proof metadata.','configuration.auth_sessions');}
    }
    public function epoch(string $scope,string $subject): ?string
    {
        if($this->boundary!==null){Guard::key('auth-sessions',$scope,$subject);}
        return $this->within('epoch',$scope,function()use($scope,$subject){return $this->epochInternal($scope,$subject);});
    }
    public function register(string $scope,string $subject,string $expectedFingerprint,string $expectedEpoch,string $method='password',string $label=''): ?SessionCredential
    {
        if($this->boundary!==null){$this->inputIssue($scope,$subject,$expectedFingerprint,$expectedEpoch,$method,$label);}
        return $this->within('register',$scope,function()use($scope,$subject,$expectedFingerprint,$expectedEpoch,$method,$label){return $this->registerInternal($scope,$subject,$expectedFingerprint,$expectedEpoch,$method,$label);});
    }
    public function replace(string $scope,string $subject,string $expectedFingerprint,string $expectedEpoch,string $method,string $id,string $expectedDigest): ?SessionCredential
    {
        if($this->boundary!==null){if(!preg_match('/\A[a-f0-9]{32}\z/D',$id)||!preg_match('/\A[a-f0-9]{64}\z/D',$expectedDigest)){throw new ConfigurationException('Invalid reauthentication reference.','configuration.authentication');}$this->inputIssue($scope,$subject,$expectedFingerprint,$expectedEpoch,$method,'');}
        return $this->within('replace',$scope,function()use($scope,$subject,$expectedFingerprint,$expectedEpoch,$method,$id,$expectedDigest){return $this->replaceInternal($scope,$subject,$expectedFingerprint,$expectedEpoch,$method,$id,$expectedDigest);});
    }
    public function verify(string $scope,string $subject,$token,int $minimumStrength=0): ?VerifiedSession
    {
        if($this->boundary!==null){Guard::key('auth-sessions',$scope,$subject);if($minimumStrength<0||$minimumStrength>2){throw new ConfigurationException('Invalid authentication strength.','configuration.authentication');}if(self::reference($token)===null){return null;}}
        return $this->within('verify',$scope,function()use($scope,$subject,$token,$minimumStrength){return $this->verifyInternal($scope,$subject,$token,$minimumStrength);});
    }
    public function revoke(string $scope,string $subject,string $id): bool
    {
        if($this->boundary!==null){if(!preg_match('/\A[a-f0-9]{32}\z/D',$id)){return false;}Guard::key('auth-sessions',$scope,$subject);}
        return $this->within('revoke',$scope,function()use($scope,$subject,$id){return $this->revokeInternal($scope,$subject,$id);});
    }
    public function revokeAll(string $scope,string $subject): void
    {
        if($this->boundary!==null){Guard::key('auth-sessions',$scope,$subject);}
        $this->within('revoke_all',$scope,function()use($scope,$subject):void{$this->revokeAllInternal($scope,$subject);});
    }
    public function all(string $scope,string $subject): array
    {
        if($this->boundary!==null){Guard::key('auth-sessions',$scope,$subject);}
        return $this->within('all',$scope,function()use($scope,$subject){return $this->allInternal($scope,$subject);});
    }

    /** Capture after successful first-factor verification, before an optional second-factor challenge. */
    private function epochInternal(string $scope, string $subject): ?string
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
    private function registerInternal(string $scope, string $subject, string $expectedFingerprint, string $expectedEpoch,
        string $method = 'password', string $label = ''): ?SessionCredential
    {
        return $this->issue($scope, $subject, $expectedFingerprint, $expectedEpoch, $method, $label, null);
    }

    /** Rotates the original secret while preserving its ID and absolute expiry. Used by AuthenticationFlow. */
    private function replaceInternal(string $scope, string $subject, string $expectedFingerprint, string $expectedEpoch,
        string $method, string $id, string $expectedDigest): ?SessionCredential
    {
        if (!preg_match('/\A[a-f0-9]{32}\z/D', $id) || !preg_match('/\A[a-f0-9]{64}\z/D', $expectedDigest)) {
            throw new ConfigurationException('Invalid reauthentication reference.', 'configuration.authentication');
        }
        return $this->issue($scope, $subject, $expectedFingerprint, $expectedEpoch, $method, '', ['id' => $id, 'digest' => $expectedDigest]);
    }

    private function verifyInternal(string $scope, string $subject, $token, int $minimumStrength = 0): ?VerifiedSession
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
        // Storage I/O can outlive the authority observed before it. Do not return that stale identity.
        $current = $this->identities->load($scope, $subject);
        $end = $this->now();
        if ($end < $now || $record['expires'] <= $end || $end - $record['seen'] >= $record['idle'] || $current === null
            || !hash_equals($identity['fingerprint'], $current['fingerprint'])) { return null; }
        return new VerifiedSession($current['account'], $parts['id'], $record['method'], $record['created'], $record['authenticated'], $record['expires'], $record['resumed']);
    }

    /** Management ID only; knowing it grants no authentication capability. Never accept an untrusted subject. */
    private function revokeInternal(string $scope, string $subject, string $id): bool
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
    private function revokeAllInternal(string $scope, string $subject): void
    {
        $key = Guard::key('auth-sessions', $scope, $subject); $now = $this->now(); $epoch = bin2hex(random_bytes(32));
        $this->store->transact($key, function ($state) use ($now, $epoch) {
            $this->state($state, $now);
            return $this->change(RegistryState::empty($epoch, $now), $now, null);
        });
    }

    /** Stored live records only, not proof of a browser being online; host authorizes this query. */
    private function allInternal(string $scope, string $subject): array
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
