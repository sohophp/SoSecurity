<?php
declare(strict_types=1);
namespace SoSecurity\Concurrency;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;

/** Cooperative leases on one authoritative atomic ledger. Host-enforced fences protect separate business writes. */
final class LeaseManager
{
    private $store;
    private $policy;
    private $clock;
    private $state;
    public function __construct(AtomicStore $store, ?LeasePolicy $policy = null, ?Clock $clock = null, ?\SoSecurity\Account\StateLeaseConnection $state = null) { $this->store = $store; $this->policy = $policy ?? new LeasePolicy(); $this->clock = $clock ?? new SystemClock(); $this->state=$state; if($state!==null){$state->validate($store,$this->clock);} }
    public function policy(): LeasePolicy { return $this->policy; }
    /** Authorized provisioning only. Normal acquisition never creates a missing ledger. Pin this epoch in the business resource. */
    public function initialize(string $scope, string $resource): string
    {
        $now = $this->now(); $key = LeaseState::context($scope, $resource, $now); $epoch = bin2hex(random_bytes(16));
        $result = $this->transact('initialize',$scope,$resource,null,$key,$now,false,function ($state,int $now) use ($epoch) {
            $state = LeaseState::read($state, $this->policy, $now);
            if ($state === null) { $state = ['v' => 1, 'epoch' => $epoch, 'policy' => $this->policy->fingerprint(), 'sequence' => 0, 'seen' => $now, 'holders' => []]; }
            $state = LeaseState::prune($state, $now);
            return new Change($state, 0, $state['epoch']);
        });
        return $result;
    }
    public function acquire(string $scope, string $resource, string $owner): ?Lease
    {
        $now = $this->now(); $key = LeaseState::context($scope, $resource, $now, $owner); $binding = LeaseState::owner($scope, $resource, $owner);
        $id = bin2hex(random_bytes(16)); $secret = bin2hex(random_bytes(32));
        $result = $this->transact('acquire',$scope,$resource,$owner,$key,$now,true,function ($state,int $now) use ($binding, $id, $secret) {
            $state = $this->required($state, $now); $state = LeaseState::prune($state, $now);
            foreach ($state['holders'] as $holder) { if (hash_equals($holder['owner'], $binding)) { return new Change($state, 0, null); } }
            if (count($state['holders']) >= $this->policy->maximum()) { return new Change($state, 0, null); }
            if ($state['sequence'] === PHP_INT_MAX || isset($state['holders'][$id])) { throw new StorageException('Lease sequence/candidate exhausted.', 'lease.capacity'); }
            ++$state['sequence']; $token = 'l1.' . $state['epoch'] . '.' . $id . '.' . $secret; $expires = $now + $this->policy->ttl(); $absolute = $now + $this->policy->maximumLifetime();
            $state['holders'][$id] = ['digest' => hash('sha256', $token), 'owner' => $binding, 'fence' => $state['sequence'], 'issued' => $now, 'expires' => $expires, 'absolute' => $absolute];
            return new Change($state, 0, new Lease($token, $state['sequence'], $expires, $absolute));
        });
        return $result;
    }
    public function renew(string $scope, string $resource, string $owner, string $token): ?Lease { return $this->credential($scope, $resource, $owner, $token, 'renew'); }
    public function verify(string $scope, string $resource, string $owner, string $token): ?Lease { return $this->credential($scope, $resource, $owner, $token, 'verify'); }
    public function release(string $scope, string $resource, string $owner, string $token): bool { return $this->credential($scope, $resource, $owner, $token, 'release'); }
    private function credential(string $scope, string $resource, string $owner, string $token, string $operation)
    {
        $now = $this->now(); $key = LeaseState::context($scope, $resource, $now, $owner); $reference = LeaseState::token($token);
        if ($reference === null) { return $operation === 'release' ? false : null; }
        $binding = LeaseState::owner($scope, $resource, $owner);
        $result = $this->transact($operation,$scope,$resource,$owner,$key,$now,true,function ($state,int $now) use ($reference, $binding, $token, $operation) {
            $state = $this->required($state, $now); $state = LeaseState::prune($state, $now); $holder = LeaseState::holder($state, $reference, $binding);
            $result = $operation === 'release' ? false : null;
            if ($holder !== null) {
                if ($operation === 'release') { unset($state['holders'][$reference['id']]); $result = true; }
                else {
                    if ($operation === 'renew') { $holder['expires'] = min($now + $this->policy->ttl(), $holder['absolute']); $state['holders'][$reference['id']] = $holder; }
                    $result = new Lease($token, $holder['fence'], $holder['expires'], $holder['absolute']);
                }
            }
            return new Change($state, 0, $result);
        });
        return $result;
    }
    public function inspect(string $scope, string $resource): LeaseStatus
    {
        $now = $this->now(); $key = LeaseState::context($scope, $resource, $now);
        $result = $this->transact('inspect',$scope,$resource,null,$key,$now,false,function ($state,int $now) {
            $state = LeaseState::read($state, $this->policy, $now);
            if ($state !== null) { $state = LeaseState::prune($state, $now); }
            $active = $state['holders'] ?? []; $retry = 0;
            if (count($active) >= $this->policy->maximum()) { $retry = min(array_column($active, 'expires')) - $now; }
            return new Change($state, 0, new LeaseStatus($state['epoch'] ?? null, count($active), $this->policy->maximum(), $state['sequence'] ?? 0, $retry));
        });
        return $result;
    }
    /** Authorized cleanup after draining/retiring the host resource. Epoch prevents deleting a replacement ledger. */
    public function remove(string $scope, string $resource, string $epoch): bool
    {
        $now = $this->now(); $key = LeaseState::context($scope, $resource, $now);
        if (!LeaseState::hex($epoch, 32)) { throw new ConfigurationException('Expected the pinned lease epoch.', 'configuration.lease'); }
        $result = $this->transact('remove',$scope,$resource,null,$key,$now,false,function ($state,int $now) use ($epoch) {
            $state = LeaseState::read($state, $this->policy, $now); $remove = false;
            if ($state !== null) { $state = LeaseState::prune($state, $now); $remove = hash_equals($state['epoch'], $epoch) && !$state['holders']; }
            return new Change($remove ? null : $state, 0, $remove);
        });
        return $result;
    }
    private function now():int
    {
        if($this->state===null){return $this->clock->now();}
        try{return $this->clock->now();}catch(\Throwable $error){throw new StorageException('Lease clock unavailable.','lease.clock');}
    }
    private function transact(string $action,string $scope,string $resource,?string $owner,string $key,int $started,bool $credential,callable $prepare)
    {
        $finish=function($result)use($key,$started,$credential):void{
            if($credential){$this->finishCredential($key,$started,$result instanceof Lease?$result:null);}
            else{LeaseState::finish($started,$this->now());}
        };
        if($this->state!==null){return $this->state->transact($action,$scope,$resource,$owner,$this->policy,$prepare,$finish);}
        $result=$this->store->transact($key,static function($old)use($prepare,$started):Change{return $prepare($old,$started);});$finish($result);return $result;
    }
    private function required($state, int $now): array
    {
        $state = LeaseState::read($state, $this->policy, $now);
        if ($state === null) { throw new StorageException('Lease ledger missing; authorized provisioning/recovery is required.', 'lease.uninitialized'); }
        return $state;
    }
    private function finishCredential(string $key, int $started, ?Lease $lease): void
    {
        $finished = $this->now();
        if ($lease !== null && ($finished < $started || $lease->expiresAt() <= $finished)) {
            $floor = max($started, $finished); $reference = LeaseState::token($lease->token());
            // A late/invalid observed credential must not revive after a later clock correction.
            // Cleanup is exact-token only and cannot delete a concurrently replaced holder/epoch.
            $this->store->transact($key, function ($state) use ($floor, $reference) {
                $state = LeaseState::read($state, $this->policy, $floor);
                if ($state === null) { return new Change(null, 0, null); }
                $state = LeaseState::prune($state, $floor);
                $holder = $state['holders'][$reference['id']] ?? null;
                if (hash_equals($state['epoch'], $reference['epoch']) && $holder !== null && hash_equals($holder['digest'], $reference['digest'])) { unset($state['holders'][$reference['id']]); }
                return new Change($state, 0, null);
            });
        }
        LeaseState::finish($started, $finished, $lease);
    }
    public function __sleep(): array { throw new ConfigurationException('Do not serialize lease managers or backend connections.', 'configuration.lease_serialization'); }
    public function __debugInfo(): array { return ['maximum' => $this->policy->maximum(), 'ttl' => $this->policy->ttl()]; }
}
