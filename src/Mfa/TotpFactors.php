<?php
declare(strict_types=1);

namespace SoSecurity\Mfa;

use SoSecurity\Crypto\Cipher;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** One encrypted TOTP factor per trusted scope/subject. Host authorizes every management call first. */
final class TotpFactors
{
    private $store;
    private $cipher;
    private $issuer;
    private $clock;
    private $ttl;
    private $attempts;
    private $cooldown;
    private $totp;
    private $authority;
    private $migrationSource;

    public function __construct(AtomicStore $store, Cipher $cipher, string $issuer, ?Clock $clock = null,
        int $enrollmentTtl = 300, int $attempts = 5, int $cooldown = 60, ?Totp $totp = null)
    {
        Guard::label($issuer);
        if (strpos($issuer, ':') !== false || $enrollmentTtl < 30 || $enrollmentTtl > 900
            || $attempts < 1 || $attempts > 10 || $cooldown < 1 || $cooldown > 3600) {
            throw new ConfigurationException('Invalid MFA issuer, enrollment TTL or attempt budget.', 'configuration.mfa');
        }
        $this->store = $store; $this->cipher = $cipher; $this->issuer = $issuer; $this->clock = $clock ?? new SystemClock();
        $this->ttl = $enrollmentTtl; $this->attempts = $attempts; $this->cooldown = $cooldown; $this->totp = $totp ?? new Totp();
    }

    /** SQL-registered mode retains the typed provider and its explicit SQL I/O budget. No automatic provisioning. */
    public function managedRegistered(string $site,string $scope,string $epoch,\SoSecurity\Support\HmacKeys $keys,\SoSecurity\Account\LocalEpochFence $fence,\SoSecurity\Account\FactorWorkerAuthority $authority):self
    {
        return $this->managed($site,$scope,$epoch,$keys,$fence,$authority,$authority->ioMilliseconds());
    }
    /** Explicit managed mode. This does not migrate any slot or authorize a caller by itself. */
    public function managed(string $site,string $scope,string $epoch,\SoSecurity\Support\HmacKeys $keys,\SoSecurity\Account\LocalEpochFence $fence,callable $guard,int $milliseconds=1000):self
    {
        Guard::label($site);Guard::label($scope);
        if($this->authority!==null||$this->store instanceof ManagedFactorStore||preg_match('//u',$site)!==1||preg_match('//u',$scope)!==1||!$fence->matches($site,$scope,$epoch)){throw new ConfigurationException('Use a matching fresh managed factor context.','configuration.mfa_managed');}
        $this->validateConfiguration(null,true);$authority=new FactorAuthority($fence,$guard,$this->clock,$milliseconds);
        $context=hash('sha256',json_encode(['SoSecurity.Mfa.ManagedContext.1',$site,$scope,$epoch],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        $managed=new self(new ManagedFactorStore($this->store,$context,$keys,$authority),$this->cipher,$this->issuer,$this->clock,$this->ttl,$this->attempts,$this->cooldown,$this->totp);$managed->authority=$authority;$managed->migrationSource=$this;return $managed;
    }
    public function migratesFrom(self $source):bool {return $this->authority!==null&&$this->migrationSource===$source;}
    /** Fingerprint the exact, unnormalized legacy payload. This is metadata, never a factor proof. */
    private function migrationData($raw,string $key,int $now):array
    {
        $this->state($raw,$now);
        if($raw!==null&&($raw['pending']!==null||$raw['enabled']===null)){throw new SecurityException('Resolve all pending legacy state explicitly before migration.','mfa.migration_pending');}
        if($raw!==null){$secret=$this->cipher->decrypt($raw['enabled']['secret'],$key.':'.$raw['enabled']['id']);$this->profile($raw['enabled']['profile'])->codeAt($secret,$now);}
        $encoded=json_encode($raw,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);if(!is_string($encoded)||strlen($encoded)>12000){throw new StorageException('Legacy migration state exceeds its encoding bound.','mfa.migration_corrupt');}
        return ['factor_id'=>$raw===null?null:$raw['enabled']['id'],'digest'=>hash('sha256','SoSecurity.Mfa.LegacyMigration.1.'.$key.':'.$encoded)];
    }
    public function legacyMigrationSnapshot(string $scope,string $subject):array
    {
        if($this->authority!==null){throw new ConfigurationException('Use the original unmanaged source for legacy review.','configuration.mfa_migration');}
        $key=Guard::key('mfa-totp',$scope,$subject);$now=$this->now();return $this->store->transact($key,function($raw)use($key,$now):Change{return new Change($raw,0,$this->migrationData($raw,$key,$now));});
    }
    public function migrationSnapshot(string $scope,string $subject):array
    {
        if($this->authority===null||!$this->store instanceof ManagedFactorStore){throw new ConfigurationException('Use an explicitly managed migration inspector.','configuration.mfa_migration');}
        return $this->access('migrationInspect',$scope,$subject,[],function()use($scope,$subject):array{$key=Guard::key('mfa-totp',$scope,$subject);$now=$this->now();return $this->store->migrationInspect($key,function($raw)use($key,$now):array{return $this->migrationData($raw,$key,$now);});});
    }
    /** Metadata only, borrowed exclusively from the matching active closed EX drain. */
    public function migrationSnapshotClosed(\SoSecurity\Account\LocalEpochFence $fence,string $scope,string $subject):array
    {
        if($this->authority===null||!$this->store instanceof ManagedFactorStore){throw new ConfigurationException('Use explicit managed migration state.','configuration.mfa_migration');}
        return $this->authority->inspectClosed($fence,$scope,$subject,function()use($scope,$subject):array{$key=Guard::key('mfa-totp',$scope,$subject);$now=$this->now();return $this->store->migrationInspect($key,function($raw)use($key,$now):array{return $this->migrationData($raw,$key,$now);});});
    }
    public function adoptManagedExact(string $scope,string $subject,?string $factorId,string $digest,string $operation,callable $validate):array {return $this->migrateExact($scope,$subject,$factorId,$digest,$operation,$validate,false);}
    public function completeManagedMigration(string $scope,string $subject,?string $factorId,string $digest,string $operation,callable $validate):array {return $this->migrateExact($scope,$subject,$factorId,$digest,$operation,$validate,true);}
    private function migrateExact(string $scope,string $subject,?string $factorId,string $digest,string $operation,callable $validate,bool $commit):array
    {
        if($this->authority===null||!$this->store instanceof ManagedFactorStore){throw new ConfigurationException('Use explicit managed migration state.','configuration.mfa_migration');}
        $action=$commit?'completeManagedMigration':'adoptManagedExact';return $this->access($action,$scope,$subject,['factor_id'=>$factorId,'state_digest'=>$digest,'migration_id'=>$operation],function()use($scope,$subject,$commit,$validate):array{
            if($validate()!==true){throw new SecurityException('A current committed SQL migration intent is required.','mfa.migration_denied');}
            $key=Guard::key('mfa-totp',$scope,$subject);$now=$this->now();return $this->store->migrate($key,function($raw)use($key,$now):array{return $this->migrationData($raw,$key,$now);},$commit);
        });
    }
    /** Exact inactive-generation retirement only, within the matching active closed drain. */
    public function revokeGenerationClosed(\SoSecurity\Account\LocalEpochFence $fence,string $scope,string $subject,string $generation,callable $validate):bool
    {
        if($this->authority===null||!$this->store instanceof ManagedFactorStore){throw new ConfigurationException('Closed retirement requires managed factors.','configuration.mfa_closed');}
        return $this->authority->retireClosed($fence,$scope,$subject,$generation,function()use($scope,$subject,$generation,$validate):bool{
            $key=Guard::key('mfa-totp',$scope,$subject);$now=$this->now();if($validate()!==true){throw new SecurityException('Current inactive-slot validation required.','mfa.closed_denied');}return $this->store->transact($key,function($raw)use($generation,$now):Change{
                $this->state($raw,$now);if($raw!==null){foreach(['enabled','pending'] as $field){if($raw[$field]!==null&&$raw[$field]['id']!==$generation){return $this->keep($raw,false);}}}
                return new Change(null,0,true);
            });
        });
    }
    public function isManaged():bool {return $this->authority!==null;}
    /** Internal directory lock ordering; authorization still runs for every physical method. */
    /** Pure capability check; no root initialization, SQL or authority callbacks. */
    public function registeredWith(\PDO $connection):bool {return $this->authority!==null&&$this->authority->registeredWith($connection);}
    public function enlistWorkers(\PDO $connection):void {if($this->authority!==null){$this->authority->enlistWorkers($connection);}}
    public function boundTo(\SoSecurity\Account\LocalEpochFence $fence):bool {return $this->authority!==null&&$this->authority->boundTo($fence);}
    private function access(string $action,string $scope,string $subject,array $metadata,callable $operation)
    {
        return $this->authority===null?$operation():$this->authority->work($action,$scope,$subject,$metadata,$operation);
    }
    /** Explicit migration of an empty or exact active legacy slot; never use as an authentication fallback. */
    public function adoptManaged(string $scope,string $subject,?string $expectedFactorId):array
    {
        if($this->authority===null||!$this->store instanceof ManagedFactorStore||($expectedFactorId!==null&&!preg_match('/\A[a-f0-9]{32}\z/D',$expectedFactorId))){throw new ConfigurationException('Use an exact explicitly managed adoption.','configuration.mfa_managed');}
        return $this->access('adoptManaged',$scope,$subject,['factor_id'=>$expectedFactorId],function()use($scope,$subject,$expectedFactorId):array{
            $key=Guard::key('mfa-totp',$scope,$subject);$now=$this->now();return $this->store->adopt($key,function($state)use($now,$expectedFactorId):Change{
                $state=$this->state($state,$now);$id=$state===null||$state['enabled']===null?null:$state['enabled']['id'];
                if($id!==$expectedFactorId||($state!==null&&$state['pending']!==null)){throw new SecurityException('Legacy factor changed or has unresolved enrollment.','mfa.adoption_changed');}
                return $this->change($state,$now,$this->statusOf($state,$now));
            });
        });
    }
    private function statusOf(?array $state,int $now):array
    {
        return ['enabled'=>$state!==null&&$state['enabled']!==null,'factor_id'=>$state===null||$state['enabled']===null?null:$state['enabled']['id'],'pending'=>$state!==null&&$state['pending']!==null,'recovery_remaining'=>$state===null?0:count($state['recovery']),'retry_after'=>$state===null?0:max(0,$state['blocked_until']-$now)];
    }
    public function begin(string $scope, string $subject, string $accountLabel): Enrollment
    {
        return $this->access('begin',$scope,$subject,[],function()use($scope,$subject,$accountLabel): Enrollment{return $this->beginRaw($scope,$subject,$accountLabel);});
    }
    public function confirm(string $scope, string $subject, string $enrollmentId, $code): ?array
    {
        return $this->access('confirm',$scope,$subject,['factor_id'=>$enrollmentId],function()use($scope,$subject,$enrollmentId,$code): ?array{return $this->confirmRaw($scope,$subject,$enrollmentId,$code);});
    }
    public function verify(string $scope, string $subject, $code): bool
    {
        return $this->access('verify',$scope,$subject,[],function()use($scope,$subject,$code): bool{return $this->verifyRaw($scope,$subject,$code);});
    }
    public function verifyRecovery(string $scope, string $subject, $code): bool
    {
        return $this->access('verifyRecovery',$scope,$subject,[],function()use($scope,$subject,$code): bool{return $this->verifyRecoveryRaw($scope,$subject,$code);});
    }
    public function verifyBound(string $scope, string $subject, string $expectedFactorId, $code, bool $recovery = false): bool
    {
        return $this->access('verifyBound',$scope,$subject,['factor_id'=>$expectedFactorId,'recovery'=>$recovery],function()use($scope,$subject,$expectedFactorId,$code,$recovery): bool{return $this->verifyBoundRaw($scope,$subject,$expectedFactorId,$code,$recovery);});
    }
    public function regenerateRecoveryCodes(string $scope, string $subject, $code): ?array
    {
        return $this->access('regenerateRecoveryCodes',$scope,$subject,[],function()use($scope,$subject,$code): ?array{return $this->regenerateRecoveryCodesRaw($scope,$subject,$code);});
    }
    public function regenerateRecoveryCodesBound(string $scope,string $subject,string $expectedFactorId,$code):?array
    {
        return $this->access('regenerateRecoveryCodesBound',$scope,$subject,['factor_id'=>$expectedFactorId],function()use($scope,$subject,$expectedFactorId,$code):?array{return $this->regenerateRecoveryCodesBoundRaw($scope,$subject,$expectedFactorId,$code);});
    }
    public function disableBound(string $scope,string $subject,string $expectedFactorId,$code,bool $recovery=false):bool
    {
        return $this->access('disableBound',$scope,$subject,['factor_id'=>$expectedFactorId,'recovery'=>$recovery],function()use($scope,$subject,$expectedFactorId,$code,$recovery):bool{return $this->disableBoundRaw($scope,$subject,$expectedFactorId,$code,$recovery);});
    }
    public function disable(string $scope, string $subject, $code, bool $recovery = false): bool
    {
        return $this->access('disable',$scope,$subject,['recovery'=>$recovery],function()use($scope,$subject,$code,$recovery): bool{return $this->disableRaw($scope,$subject,$code,$recovery);});
    }
    public function prepare(string $scope,string $subject,string $generation,string $accountLabel):Enrollment
    {
        return $this->access('prepare',$scope,$subject,['factor_id'=>$generation],function()use($scope,$subject,$generation,$accountLabel):Enrollment{return $this->prepareRaw($scope,$subject,$generation,$accountLabel);});
    }
    public function revokeGeneration(string $scope,string $subject,string $expectedGeneration):bool
    {
        return $this->access('revokeGeneration',$scope,$subject,['factor_id'=>$expectedGeneration],function()use($scope,$subject,$expectedGeneration):bool{return $this->revokeGenerationRaw($scope,$subject,$expectedGeneration);});
    }
    public function revoke(string $scope, string $subject): void
    {
        $this->access('revoke',$scope,$subject,[],function()use($scope,$subject): void{$this->revokeRaw($scope,$subject);});
    }
    public function status(string $scope, string $subject): array
    {
        return $this->access('status',$scope,$subject,[],function()use($scope,$subject): array{return $this->statusRaw($scope,$subject);});
    }
    public function reencrypt(string $scope, string $subject): bool
    {
        return $this->access('reencrypt',$scope,$subject,[],function()use($scope,$subject): bool{return $this->reencryptRaw($scope,$subject);});
    }
    public function reencryptBound(string $scope,string $subject,string $expectedFactorId):bool
    {
        return $this->access('reencryptBound',$scope,$subject,['factor_id'=>$expectedFactorId],function()use($scope,$subject,$expectedFactorId):bool{return $this->reencryptBoundRaw($scope,$subject,$expectedFactorId);});
    }

    /** Pure dependency validation; custom store persistence remains a host contract. */
    public function validateConfiguration(?Clock $clock=null,bool $requireShared=false):void
    {
        if($clock!==null&&$this->clock!==$clock&&!($clock instanceof SystemClock&&$this->clock instanceof SystemClock)){throw new ConfigurationException('Use the same factor and account clock.','configuration.mfa_clock');}
        if($requireShared){$store=$this->store;$depth=0;while($store instanceof \SoSecurity\Storage\NamespacedStore){if(++$depth>8){throw new ConfigurationException('Factor storage nesting exceeds its bound.','configuration.mfa_store');}$store=$store->underlying();}if($store instanceof \SoSecurity\Storage\MemoryStore||$store instanceof \SoSecurity\Storage\SessionStore){throw new ConfigurationException('Managed factor recovery requires shared atomic factor storage.','configuration.mfa_store');}}
    }

    /** Existing active factor remains valid until confirmation. Replacing it requires host step-up authorization. */
    private function beginRaw(string $scope, string $subject, string $accountLabel): Enrollment
    {
        $key = Guard::key('mfa-totp', $scope, $subject); $now = $this->now();
        $secret = $this->totp->generateSecret(); $id = bin2hex(random_bytes(16));
        $uri = $this->totp->provisioningUri($secret, $this->issuer, $accountLabel);
        $pending = ['id' => $id, 'secret' => $this->cipher->encrypt($secret, $key . ':' . $id), 'profile' => $this->totp->profile(),
            'last_step' => -1, 'expires' => $now + $this->ttl];
        $this->store->transact($key, function ($state) use ($pending, $now) {
            $state = $this->state($state, $now);
            if ($state === null) { $state = ['v' => 1, 'enabled' => null, 'pending' => null, 'recovery' => [], 'failures' => 0, 'blocked_until' => 0, 'updated' => $now]; }
            if ($state['blocked_until'] > $now) { throw new SecurityException('MFA is cooling down.', 'mfa.throttled'); }
            $state['pending'] = $pending;
            return $this->change($state, $now, null);
        });
        return new Enrollment($id, $uri, $pending['expires']);
    }

    /** Returns newly generated recovery codes once, only after the pending factor proves possession. */
    private function confirmRaw(string $scope, string $subject, string $enrollmentId, $code): ?array
    {
        $key = Guard::key('mfa-totp', $scope, $subject); $now = $this->now(); $codes = $this->codes();
        return $this->store->transact($key, function ($state) use ($key, $now, $enrollmentId, $code, $codes) {
            $state = $this->state($state, $now);
            if ($state === null || $state['pending'] === null || $state['pending']['id'] !== $enrollmentId || $state['blocked_until'] > $now) {
                return $this->change($state, $now, null);
            }
            $factor = $state['pending']; $step = $this->step($factor, $key, $code, $now);
            if ($step === null) { return $this->change($this->failed($state, $now), $now, null); }
            unset($factor['expires']); $factor['last_step'] = $step;
            $state['enabled'] = $factor; $state['pending'] = null; $state['recovery'] = $this->digests($codes);
            $state['failures'] = 0; $state['blocked_until'] = 0;
            return $this->change($state, $now, $codes);
        });
    }

    private function verifyRaw(string $scope, string $subject, $code): bool { return $this->authenticate($scope, $subject, $code, false); }
    private function verifyRecoveryRaw(string $scope, string $subject, $code): bool { return $this->authenticate($scope, $subject, $code, true); }
    /** Bind an in-progress authentication to the exact factor that existed after password verification. */
    private function verifyBoundRaw(string $scope, string $subject, string $expectedFactorId, $code, bool $recovery = false): bool
    {
        if (!preg_match('/\A[a-f0-9]{32}\z/D', $expectedFactorId)) { return false; }
        return $this->authenticate($scope, $subject, $code, $recovery, 'verify', [], $expectedFactorId);
    }

    /** A fresh TOTP atomically authorizes recovery-code rotation. Host also checks current account ownership. */
    private function regenerateRecoveryCodesRaw(string $scope, string $subject, $code): ?array
    {
        return $this->authenticate($scope, $subject, $code, false, 'regenerate', $this->codes());
    }

    /** Fresh proof and recovery replacement are one atomic operation on an exact current generation. */
    private function regenerateRecoveryCodesBoundRaw(string $scope,string $subject,string $expectedFactorId,$code):?array
    {
        if(!preg_match('/\A[a-f0-9]{32}\z/D',$expectedFactorId)){return null;}
        return $this->authenticate($scope,$subject,$code,false,'regenerate',$this->codes(),$expectedFactorId);
    }
    /** Exact-generation counterpart; an old request cannot disable a replacement factor. */
    private function disableBoundRaw(string $scope,string $subject,string $expectedFactorId,$code,bool $recovery=false):bool
    {
        if(!preg_match('/\A[a-f0-9]{32}\z/D',$expectedFactorId)){return false;}
        return $this->authenticate($scope,$subject,$code,$recovery,'disable',[],$expectedFactorId);
    }

    /** A fresh factor/recovery proof plus host authorization is required; removal invalidates all MFA state. */
    private function disableRaw(string $scope, string $subject, $code, bool $recovery = false): bool
    {
        return $this->authenticate($scope, $subject, $code, $recovery, 'disable');
    }

    /** Create an isolated slot with a generation reserved durably by the caller. Never replace existing state. */
    private function prepareRaw(string $scope,string $subject,string $generation,string $accountLabel):Enrollment
    {
        if(!preg_match('/\A[a-f0-9]{32}\z/D',$generation)){throw new ConfigurationException('Use a pre-reserved factor generation.','configuration.mfa');}
        $key=Guard::key('mfa-totp',$scope,$subject);$now=$this->now();$secret=$this->totp->generateSecret();$uri=$this->totp->provisioningUri($secret,$this->issuer,$accountLabel);
        $pending=['id'=>$generation,'secret'=>$this->cipher->encrypt($secret,$key.':'.$generation),'profile'=>$this->totp->profile(),'last_step'=>-1,'expires'=>$now+$this->ttl];
        $this->store->transact($key,function($state)use($pending,$now):Change{
            if($this->state($state,$now)!==null){throw new SecurityException('A prepared factor slot cannot be reused.','mfa.occupied');}
            return $this->change(['v'=>1,'enabled'=>null,'pending'=>$pending,'recovery'=>[],'failures'=>0,'blocked_until'=>0,'updated'=>$now],$now,null);
        });return new Enrollment($generation,$uri,$pending['expires']);
    }
    /** Privileged compare-and-delete only. Caller must fence the workflow and prove the whole slot is inactive. */
    private function revokeGenerationRaw(string $scope,string $subject,string $expectedGeneration):bool
    {
        if(!preg_match('/\A[a-f0-9]{32}\z/D',$expectedGeneration)){throw new ConfigurationException('Use an exact factor retirement generation.','configuration.mfa');}
        $key=Guard::key('mfa-totp',$scope,$subject);$now=$this->now();
        return $this->store->transact($key,function($state)use($expectedGeneration,$now):Change{
            $state=$this->state($state,$now);if($state===null){return new Change(null,0,true);}
            foreach(['enabled','pending'] as $field){if($state[$field]!==null&&!hash_equals($state[$field]['id'],$expectedGeneration)){return $this->change($state,$now,false);}}
            return new Change(null,0,true);
        });
    }

    /** Privileged account-recovery hook. Host MUST authorize, notify, and invalidate affected sessions. */
    private function revokeRaw(string $scope, string $subject): void
    {
        $key = Guard::key('mfa-totp', $scope, $subject); $now = $this->now();
        $this->store->transact($key, function ($state) use ($now) { $this->state($state, $now); return new Change(null, 0, null); });
    }

    private function statusRaw(string $scope, string $subject): array
    {
        $key = Guard::key('mfa-totp', $scope, $subject); $now = $this->now();
        return $this->store->transact($key, function ($state) use ($now) {
            $state = $this->state($state, $now);
            $result = ['enabled' => $state !== null && $state['enabled'] !== null,
                'factor_id' => $state === null || $state['enabled'] === null ? null : $state['enabled']['id'],
                'pending' => $state !== null && $state['pending'] !== null,
                'recovery_remaining' => $state === null ? 0 : count($state['recovery']),
                'retry_after' => $state === null ? 0 : max(0, $state['blocked_until'] - $now)];
            return $this->change($state, $now, $result);
        });
    }

    /** Re-encrypt both active and pending factors in the same record transaction; no secret leaves this method. */
    private function reencryptRaw(string $scope, string $subject): bool {return $this->reencryptFactor($scope,$subject,null);}
    /** Re-encrypt only a current managed generation, refusing a foreign pending replacement. */
    private function reencryptBoundRaw(string $scope,string $subject,string $expectedFactorId):bool
    {
        if(!preg_match('/\A[a-f0-9]{32}\z/D',$expectedFactorId)){return false;}
        return $this->reencryptFactor($scope,$subject,$expectedFactorId);
    }
    private function reencryptFactor(string $scope,string $subject,?string $expectedFactorId):bool
    {
        $key = Guard::key('mfa-totp', $scope, $subject); $now = $this->now();
        // Nonces are generated outside the retryable callback. Encrypting inside would violate that contract.
        $snapshot = $this->store->transact($key, function ($state) use ($now,$expectedFactorId) {
            $state = $this->state($state, $now);
            if($expectedFactorId!==null&&($state===null||$state['enabled']===null||$state['enabled']['id']!==$expectedFactorId||$state['pending']!==null)){return $this->keep($state,null);}
            if ($state !== null) { $state['updated'] = $now; }
            return $this->change($state, $now, $state);
        });
        if ($snapshot === null) { return false; }
        $replacement = $snapshot;
        foreach (['enabled', 'pending'] as $field) {
            if ($replacement[$field] !== null) {
                $replacement[$field]['secret'] = $this->cipher->reencrypt($replacement[$field]['secret'], $key . ':' . $replacement[$field]['id']);
            }
        }
        return $this->store->transact($key, function ($state) use ($snapshot, $replacement, $now) {
            $current=$this->now();if($current<$now){throw new SecurityException('MFA clock moved backwards.','mfa.clock');}
            $state = $this->state($state, $current);
            return $state === $snapshot ? $this->change($replacement, $current, true) : $this->keep($state,false);
        });
    }

    private function authenticate(string $scope, string $subject, $code, bool $recovery, string $operation = 'verify', array $codes = [], ?string $expectedFactorId = null)
    {
        $key = Guard::key('mfa-totp', $scope, $subject); $now = $this->now(); $failure = $operation === 'regenerate' ? null : false;
        return $this->store->transact($key, function ($state) use ($key, $now, $code, $recovery, $operation, $codes, $failure, $expectedFactorId) {
            $state = $this->state($state, $now);
            if ($state === null || $state['enabled'] === null || $state['blocked_until'] > $now) { return $this->change($state, $now, $failure); }
            if ($expectedFactorId !== null && !hash_equals($state['enabled']['id'], $expectedFactorId)) { return $this->keep($state,$failure); }
            $valid = false;
            if ($recovery) {
                $match = null;
                if (is_string($code) && preg_match('/\A[a-f0-9]{8}(?:-[a-f0-9]{8}){3}\z/D', $code)) {
                    $digest = hash('sha256', $code);
                    foreach ($state['recovery'] as $index => $stored) { if (hash_equals($stored, $digest)) { $match = $index; } }
                }
                if ($match !== null) { unset($state['recovery'][$match]); $state['recovery'] = array_values($state['recovery']); $valid = true; }
            } else {
                $step = $this->step($state['enabled'], $key, $code, $now);
                if ($step !== null && $step > $state['enabled']['last_step']) { $state['enabled']['last_step'] = $step; $valid = true; }
            }
            if (!$valid) { return $this->change($this->failed($state, $now), $now, $failure); }
            $state['failures'] = 0; $state['blocked_until'] = 0;
            if ($operation === 'disable') { return new Change(null, 0, true); }
            if ($operation === 'regenerate') { $state['recovery'] = $this->digests($codes); }
            return $this->change($state, $now, $operation === 'regenerate' ? $codes : true);
        });
    }

    private function step(array $factor, string $key, $code, int $now): ?int
    {
        try {
            $secret = $this->cipher->decrypt($factor['secret'], $key . ':' . $factor['id']);
            return $this->profile($factor['profile'])->matchingStep($secret, $code, $now);
        } catch (\SoSecurity\Exception\ValidationException $e) {
            throw new StorageException('MFA secret cannot be authenticated.', 'mfa.secret_unavailable', $e);
        } catch (ConfigurationException $e) {
            throw new StorageException('MFA secret or profile is corrupt.', 'storage.corrupt', $e);
        }
    }

    private function failed(array $state, int $now): array
    {
        $state['failures'] = min(10, $state['failures'] + 1);
        if ($state['failures'] >= $this->attempts) { $state['blocked_until'] = $now + $this->cooldown; }
        return $state;
    }

    private function keep(?array $state,$result):Change
    {
        if($state===null||($state['enabled']===null&&$state['pending']===null)){return new Change(null,0,$result);}
        return new Change($state,$state['enabled']===null?max($state['pending']['expires'],$state['blocked_until']):0,$result);
    }

    private function change(?array $state, int $now, $result): Change
    {
        if ($state === null || ($state['enabled'] === null && $state['pending'] === null)) { return new Change(null, 0, $result); }
        $state['updated'] = $now;
        return new Change($state, $state['enabled'] === null ? max($state['pending']['expires'], $state['blocked_until']) : 0, $result);
    }

    private function state($state, int $now): ?array
    {
        if ($state === null) { return null; }
        if (!is_array($state) || !$this->fields($state, ['v', 'enabled', 'pending', 'recovery', 'failures', 'blocked_until', 'updated'])
            || $state['v'] !== 1 || !is_array($state['recovery']) || count($state['recovery']) > 10
            || !is_int($state['failures']) || $state['failures'] < 0 || $state['failures'] > 10
            || !is_int($state['blocked_until']) || $state['blocked_until'] < 0 || !is_int($state['updated']) || $state['updated'] < 0) {
            throw new StorageException('Corrupt MFA state.', 'storage.corrupt');
        }
        if ($state['updated'] > $now) { throw new SecurityException('MFA clock moved backwards.', 'mfa.clock'); }
        foreach ($state['recovery'] as $digest) {
            if (!is_string($digest) || !preg_match('/\A[a-f0-9]{64}\z/D', $digest)) { throw new StorageException('Corrupt recovery codes.', 'storage.corrupt'); }
        }
        if (array_values($state['recovery']) !== $state['recovery'] || count(array_unique($state['recovery'])) !== count($state['recovery'])
            || ($state['enabled'] === null && $state['recovery'] !== [])) { throw new StorageException('Corrupt recovery state.', 'storage.corrupt'); }
        foreach (['enabled', 'pending'] as $field) {
            $factor = $state[$field];
            if ($factor === null) { continue; }
            $fields = ['id', 'secret', 'profile', 'last_step']; if ($field === 'pending') { $fields[] = 'expires'; }
            if (!is_array($factor) || !$this->fields($factor, $fields) || !is_string($factor['id']) || !preg_match('/\A[a-f0-9]{32}\z/D', $factor['id'])
                || !is_string($factor['secret']) || strlen($factor['secret']) < 60 || strlen($factor['secret']) > 2048
                || !is_int($factor['last_step']) || $factor['last_step'] < -1 || !is_array($factor['profile'])
                || ($field === 'pending' && (!is_int($factor['expires']) || $factor['expires'] < 0))) {
                throw new StorageException('Corrupt MFA factor.', 'storage.corrupt');
            }
            $this->profile($factor['profile']);
        }
        if ($state['pending'] !== null && $state['pending']['expires'] <= $now) { $state['pending'] = null; }
        if ($state['blocked_until'] !== 0 && $state['blocked_until'] <= $now) { $state['failures'] = 0; $state['blocked_until'] = 0; }
        return $state;
    }

    private function profile(array $profile): Totp
    {
        if (!$this->fields($profile, ['algorithm', 'digits', 'period']) || !is_string($profile['algorithm']) || !is_int($profile['digits']) || !is_int($profile['period'])) {
            throw new StorageException('Corrupt MFA profile.', 'storage.corrupt');
        }
        try { return new Totp($profile['algorithm'], $profile['digits'], $profile['period']); }
        catch (ConfigurationException $e) { throw new StorageException('Corrupt MFA profile.', 'storage.corrupt', $e); }
    }

    private function fields(array $record, array $fields): bool { $keys = array_keys($record); sort($keys); sort($fields); return $keys === $fields; }
    private function codes(): array
    {
        $codes = [];
        for ($i = 0; $i < 10; ++$i) { $codes[] = implode('-', str_split(bin2hex(random_bytes(16)), 8)); }
        return $codes;
    }
    private function digests(array $codes): array { return array_map(static function (string $code): string { return hash('sha256', $code); }, $codes); }
    private function now(): int
    {
        $now = $this->clock->now();
        if ($now < 0 || $now > PHP_INT_MAX - 86400) { throw new ConfigurationException('MFA clock is out of range.', 'configuration.clock'); }
        return $now;
    }
}
