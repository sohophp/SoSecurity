<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Concurrency\LeaseManager;
use SoSecurity\Concurrency\LeasePolicy;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Support\Guard;

final class LeaseTestStore implements AtomicStore
{
    public $states = [];
    public $expires = [];
    public $before;
    public $after;
    public $retry = true;
    public function transact(string $key, callable $callback)
    {
        if ($this->before !== null) { ($this->before)(); }
        $state = $this->states[$key] ?? null; $change = $callback($state);
        if ($this->retry) { $again = $callback($state); Check::same($change->value(), $again->value()); Check::same($change->expiresAt(), $again->expiresAt()); if($change->result() instanceof \SoSecurity\Concurrency\Lease){Check::same(leaseComparableResult($change->result()),leaseComparableResult($again->result()));}else{Check::same(true,$change->result()==$again->result());} }
        $this->states[$key] = $change->value(); $this->expires[$key] = $change->expiresAt();
        if ($this->after !== null) { ($this->after)(); }
        return $change->result();
    }
}
function leaseComparableResult($result)
{
    if($result instanceof \SoSecurity\Concurrency\Lease){return ['lease',$result->token(),$result->epoch(),$result->fence(),$result->expiresAt(),$result->absoluteExpiresAt()];}
    return $result;
}
function leaseReason(string $expected, callable $operation): void
{
    try { $operation(); throw new LogicException('Expected lease storage rejection.'); }
    catch (StorageException $e) { Check::same($expected, $e->reason()); }
}
$clock = new TestClock(); $store = new LeaseTestStore(); $manager = new LeaseManager($store, new LeasePolicy(2, 10, 25), $clock);
Check::same(false, $manager->inspect('jobs', 'a')->initialized()); Check::same(0, $manager->inspect('jobs', 'a')->available());
leaseReason('lease.uninitialized', function () use ($manager) { $manager->acquire('jobs', 'a', 'worker-a'); });
$epoch = $manager->initialize('jobs', 'a'); Check::same($epoch, $manager->initialize('jobs', 'a')); Check::same(32, strlen($epoch));
$first = $manager->acquire('jobs', 'a', 'worker-a'); Check::same(1, $first->fence()); Check::same($epoch, $first->epoch()); Check::same(100010, $first->expiresAt()); Check::same(100025, $first->absoluteExpiresAt());
Check::same(133, strlen($first->token())); Check::same(null, $manager->acquire('jobs', 'a', 'worker-a'));
$second = $manager->acquire('jobs', 'a', 'worker-b'); Check::same(2, $second->fence()); Check::same(null, $manager->acquire('jobs', 'a', 'worker-c'));
$status = $manager->inspect('jobs', 'a'); Check::same(2, $status->active()); Check::same(0, $status->available()); Check::same(10, $status->retryAfter()); Check::same(2, $status->sequence());
$key = Guard::key('leases', 'jobs', 'a'); Check::same(0, $store->expires[$key]);
$encoded = json_encode($store->states); Check::same(false, strpos($encoded, $first->token()) !== false); Check::same(false, strpos($encoded, 'worker-a') !== false);
ob_start(); var_dump($first, $manager); $debug = ob_get_clean(); Check::same(false, strpos($debug, $first->token()) !== false); Check::same('{}', json_encode($first));
foreach ([$first, $manager, $status] as $value) { Check::throws(ConfigurationException::class, function () use ($value) { serialize($value); }); }
Check::throws(ConfigurationException::class, function () use ($first) { $first->expiresAt = PHP_INT_MAX; });
foreach (['', str_repeat('x', 10000), strtoupper($first->token()), substr($first->token(), 0, -1), $first->token() . '\n'] as $bad) {
    Check::same(null, $manager->verify('jobs', 'a', 'worker-a', $bad)); Check::same(false, $manager->release('jobs', 'a', 'worker-a', $bad));
}
Check::same(null, $manager->verify('jobs', 'a', 'worker-b', $first->token())); Check::same(false, $manager->release('jobs', 'a', 'worker-b', $first->token()));
$manager->initialize('other', 'a'); $manager->initialize('jobs', 'b');
Check::same(null, $manager->verify('other', 'a', 'worker-a', $first->token())); Check::same(null, $manager->verify('jobs', 'b', 'worker-a', $first->token()));
$original = $store->states; $clock->time += 5; Check::same($first->expiresAt(), $manager->verify('jobs', 'a', 'worker-a', $first->token())->expiresAt()); Check::same($original[$key]['holders'], $store->states[$key]['holders']); Check::same($clock->time, $store->states[$key]['seen']);
$renewed = $manager->renew('jobs', 'a', 'worker-a', $first->token()); Check::same(100015, $renewed->expiresAt()); Check::same(1, $renewed->fence()); Check::same($first->token(), $renewed->token());
$clock->time = 100010; Check::same(null, $manager->verify('jobs', 'a', 'worker-b', $second->token())); Check::same(null, $manager->renew('jobs', 'a', 'worker-b', $second->token()));
$third = $manager->acquire('jobs', 'a', 'worker-c'); Check::same(3, $third->fence()); Check::same(false, $manager->release('jobs', 'a', 'worker-b', $second->token()));
Check::same(2, $manager->inspect('jobs', 'a')->active()); Check::same(false, $manager->remove('jobs', 'a', $epoch));
$clock->time = 100014; Check::same(100024, $manager->renew('jobs', 'a', 'worker-a', $first->token())->expiresAt());
$clock->time = 100023; Check::same(100025, $manager->renew('jobs', 'a', 'worker-a', $first->token())->expiresAt());
$clock->time = 100025; Check::same(null, $manager->renew('jobs', 'a', 'worker-a', $first->token())); Check::same(false, $manager->release('jobs', 'a', 'worker-a', $first->token()));
$new = $manager->acquire('jobs', 'a', 'worker-a'); Check::same(4, $new->fence()); Check::same(false, $first->token() === $new->token());
Check::same(false, $manager->release('jobs', 'a', 'worker-a', $first->token())); Check::same(true, $manager->release('jobs', 'a', 'worker-a', $new->token())); Check::same(false, $manager->release('jobs', 'a', 'worker-a', $new->token()));
Check::same(false, $manager->remove('jobs', 'a', str_repeat('0', 32))); Check::same(true, $manager->remove('jobs', 'a', $epoch));
leaseReason('lease.uninitialized', function () use ($manager, $new) { $manager->verify('jobs', 'a', 'worker-a', $new->token()); });
$replacementEpoch = $manager->initialize('jobs', 'a'); Check::same(false, $epoch === $replacementEpoch); Check::same(false, $manager->remove('jobs', 'a', $epoch));
Check::same(null, $manager->verify('jobs', 'a', 'worker-a', $new->token()));
$live = $manager->acquire('jobs', 'a', 'worker-a');
$clock->time -= 1; leaseReason('lease.clock', function () use ($manager) { $manager->inspect('jobs', 'a'); }); ++$clock->time;
leaseReason('lease.policy_changed', function () use ($store, $clock) { (new LeaseManager($store, new LeasePolicy(1, 10, 25), $clock))->inspect('jobs', 'a'); });
$valid = $store->states[$key];
foreach ([['v' => 2], ['sequence' => -1], ['extra' => true], ['seen' => PHP_INT_MAX], ['holders' => ['bad' => []]]] as $bad) {
    $store->states[$key] = array_merge($valid, $bad); leaseReason('storage.corrupt', function () use ($manager) { $manager->inspect('jobs', 'a'); });
}
$id = array_keys($valid['holders'])[0];
foreach (['digest' => 'secret', 'fence' => 2, 'issued' => -1, 'expires' => 0, 'absolute' => 1000000, 'owner' => 'unhashed'] as $field => $value) {
    $store->states[$key] = $valid; $store->states[$key]['holders'][$id][$field] = $value;
    leaseReason('storage.corrupt', function () use ($manager) { $manager->renew('jobs', 'a', 'worker-a', 'not-used'); $manager->inspect('jobs', 'a'); });
}
$store->states[$key] = $valid; $store->states[$key]['sequence'] = PHP_INT_MAX;
leaseReason('lease.capacity', function () use ($manager) { $manager->acquire('jobs', 'a', 'worker-b'); }); $store->states[$key] = $valid;
// Missing state is a hard failure after initialization, not an automatically recreated semaphore.
$store->states[$key] = null; leaseReason('lease.uninitialized', function () use ($manager) { $manager->acquire('jobs', 'a', 'worker-b'); });
foreach (['before', 'after'] as $position) {
    foreach (['acquire', 'renew', 'verify'] as $operation) {
        $c = new TestClock(); $s = new LeaseTestStore(); $m = new LeaseManager($s, new LeasePolicy(1, 2, 10), $c); $m->initialize('slow', 'a'); $credential = $m->acquire('slow', 'a', 'first');
        if ($operation === 'acquire') { $m->release('slow', 'a', 'first', $credential->token()); }
        $s->$position = static function () use ($c) { $c->time += 3; };
        leaseReason('lease.expired', function () use ($m, $operation, $credential) { if ($operation === 'acquire') { $m->acquire('slow', 'a', 'second'); } else { $m->$operation('slow', 'a', 'first', $credential->token()); } });
        $s->before = null; $s->after = null; $c->time = 100001;
        leaseReason('lease.clock',function () use ($m) { $m->acquire('slow','a','replacement'); });
        $c->time = 100020; Check::same(0,$m->inspect('slow','a')->active());
    }
}
$c = new TestClock(); $s = new LeaseTestStore(); $m = new LeaseManager($s, null, $c); $m->initialize('back', 'a'); $s->after = static function () use ($c) { --$c->time; };
leaseReason('lease.clock', function () use ($m) { $m->acquire('back', 'a', 'first'); });
$fault = new class implements AtomicStore { public function transact(string $key, callable $callback) { throw new StorageException('Fixed test outage.'); } };
// Any authoritative observation must retain its clock high-water mark, even when it did not grant a lease.
foreach (['verify','inspect','initialize'] as $observation) {
    $c = new TestClock(); $s = new MemoryStore($c); $m = new LeaseManager($s, new LeasePolicy(1,10,30), $c); $m->initialize('observed','a'); $l = $m->acquire('observed','a','worker');
    $c->time += 11;
    if ($observation === 'verify') { Check::same(null,$m->verify('observed','a','worker',$l->token())); } else { $m->$observation('observed','a'); }
    $c->time -= 6;
    leaseReason('lease.clock',function () use ($m,$l) { $m->verify('observed','a','worker',$l->token()); });
    leaseReason('lease.clock',function () use ($m) { $m->acquire('observed','a','replacement'); });
    leaseReason('lease.clock',function () use ($m,$l) { $m->renew('observed','a','worker',$l->token()); });
}
Check::throws(StorageException::class, function () use ($fault) { (new LeaseManager($fault))->acquire('fault', 'a', 'owner'); });
$c = new TestClock(); $s = new MemoryStore($c); $bounded = new LeaseManager($s, new LeasePolicy(64, 10, 20), $c); $bounded->initialize('bounded', 'a');
for ($i = 0; $i < 64; ++$i) { Check::same($i + 1, $bounded->acquire('bounded', 'a', 'owner-' . $i)->fence()); }
Check::same(null, $bounded->acquire('bounded', 'a', 'overflow')); Check::same(64, $bounded->inspect('bounded', 'a')->active());
$c->time += 20; Check::same(0, $bounded->inspect('bounded', 'a')->active()); Check::same(65, $bounded->acquire('bounded', 'a', 'recovered')->fence());
foreach ([[0], [65], [1,0], [1,3601], [1,20,10], [1,10,86401]] as $bad) { Check::throws(ConfigurationException::class, function () use ($bad) { new LeasePolicy(...$bad); }); }
foreach ([["\xc3", "\xa9"], ['scope', ''], ['scope', str_repeat('x',1025)]] as $bad) { Check::throws(ConfigurationException::class, function () use ($manager, $bad) { $manager->initialize($bad[0], $bad[1]); }); }
$directory = privateDirectory();
try {
    $config = ['site' => 'lease-test', 'storage' => ['driver' => 'file', 'directory' => $directory], 'leases' => ['maximum' => 2, 'ttl' => 10, 'maximum_lifetime' => 25]];
    $factory = SoSecurity\Security::fromArray($config, [], $clock); Check::same(false, $factory->leases()->inspect('factory', 'a')->initialized());
    $factory->leases()->initialize('factory', 'a'); Check::same(1, $factory->leases()->acquire('factory', 'a', 'worker')->fence());
    Check::same('manual', array_column($factory->diagnose(), null, 'check')['leases.fencing']['status']);
    foreach (['memory','session'] as $driver) { Check::throws(ConfigurationException::class, function () use ($driver) { SoSecurity\Security::fromArray(['site'=>'a','storage'=>['driver'=>$driver],'leases'=>[]])->leases(); }); }
    Check::throws(ConfigurationException::class, function () { SoSecurity\Security::fromArray(['site'=>'a'])->leases(); });
    foreach ([null, ['ttl'=>'10'], ['unknown'=>true], ['ttl'=>301], ['maximum'=>65]] as $bad) { Check::throws(ConfigurationException::class, function () use ($bad) { SoSecurity\Security::fromArray(['site'=>'a','leases'=>$bad]); }); }
} finally { cleanDirectory($directory); }
Check::same(PHP_SESSION_NONE, session_status()); Check::same(false, headers_sent());
echo 'PASS leases: ' . Check::$assertions . ' assertions on PHP ' . PHP_VERSION . "; bounded owners, permanent sequence/epoch, renewal ceiling, expiry/recovery, retry purity, corruption, missing ledger and slow-I/O refusal\n";
