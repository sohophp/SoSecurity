<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\RateLimit\BudgetPolicy;
use SoSecurity\RateLimit\BudgetLimiter;
use SoSecurity\RateLimit\BudgetGroup;
use SoSecurity\RateLimit\CompositeLimiter;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Support\Guard;

/** Raw state inspection, retry simulation and deliberate I/O faults; not a production backend. */
final class BudgetTestStore implements AtomicStore
{
    public $states = [];
    public $expires = [];
    public $calls = 0;
    public $before;
    public $after;
    public $retry = false;
    public function transact(string $key, callable $callback)
    {
        ++$this->calls;
        if ($this->before !== null) { ($this->before)(); }
        $old = $this->states[$key] ?? null; $change = $callback($old);
        if ($this->retry) {
            $again = $callback($old);
            Check::same($change->value(), $again->value()); Check::same($change->expiresAt(), $again->expiresAt());
            Check::same(true, $change->result() == $again->result());
        }
        $this->states[$key] = $change->value(); $this->expires[$key] = $change->expiresAt();
        if ($this->after !== null) { ($this->after)(); }
        return $change->result();
    }
}
function budgetReason(string $expected, callable $operation): void
{
    try { $operation(); throw new LogicException('Expected storage rejection.'); }
    catch (StorageException $e) { Check::same($expected, $e->reason()); }
}
$clock = new TestClock(); $store = new BudgetTestStore(); $store->retry = true;
$policy = new BudgetPolicy('token_bucket', 3, 10, 5); $token = new BudgetLimiter($store, $policy, $clock);
$key = Guard::key('budget', 'token', 'alice');
Check::same(5, $token->inspect('token', 'alice')->remaining()); Check::same(null, $store->states[$key]);
$r = $token->consume('token', 'alice', 4); Check::same(true, $r->allowed()); Check::same(1, $r->remaining()); Check::same(100014, $r->reservedUntil());
$snapshot = $store->states; $ttls = $store->expires;
$r = $token->inspect('token', 'alice', 2); Check::same(false, $r->allowed()); Check::same(4, $r->retryAfter());
Check::same($snapshot, $store->states); Check::same($ttls, $store->expires);
$r = $token->consume('token', 'alice', 2); Check::same(false, $r->allowed()); Check::same(4, $r->retryAfter());
Check::same($ttls, $store->expires); $clock->time += 3; Check::same(false, $token->consume('token', 'alice', 2)->allowed());
$clock->time += 1; $r = $token->consume('token', 'alice', 2); Check::same(true, $r->allowed()); Check::same(0, $r->remaining());
$clock->time += 100; Check::same(5, $token->inspect('token', 'alice')->remaining());
$r = $token->consume('token', 'alice', 6); Check::same('rate.cost_exceeds_limit', $r->reason()); Check::same(0, $r->retryAfter());
Check::same(true, $token->consume('token', 'alice', 5)->allowed());
foreach ([0, -1, 1000001] as $bad) { Check::throws(ValidationException::class, function () use ($token, $bad) { $token->consume('token', 'alice', $bad); }); }
budgetReason('rate.policy_changed', function () use ($store, $clock) { (new BudgetLimiter($store, new BudgetPolicy('token_bucket', 4, 10, 5), $clock))->consume('token', 'alice'); });
$clock->time -= 1; budgetReason('rate.clock', function () use ($token) { $token->inspect('token', 'alice'); }); $clock->time += 1;
$good = $store->states[$key];
foreach ([['v' => 2], ['extra' => 1], ['expires' => 0], ['data' => ['at' => $clock->time, 'credit' => -1]], ['data' => ['at' => $clock->time, 'credit' => 50]]] as $bad) {
    $store->states[$key] = array_merge($good, $bad);
    budgetReason('storage.corrupt', function () use ($token) { $token->inspect('token', 'alice'); });
}
$store->states[$key] = $good;
$fixed = new BudgetLimiter($store, new BudgetPolicy('fixed_window', 5, 10), $clock);
$start = $clock->time; Check::same(true, $fixed->consume('fixed', 'alice', 3)->allowed());
$clock->time += 9; $r = $fixed->consume('fixed', 'alice', 3); Check::same(false, $r->allowed()); Check::same(1, $r->retryAfter());
Check::same(true, $fixed->consume('fixed', 'alice', 2)->allowed());
$clock->time = $start + 10; Check::same(true, $fixed->consume('fixed', 'alice', 5)->allowed());
$slide = new BudgetLimiter($store, new BudgetPolicy('sliding_window', 8, 10, null, 2), $clock);
$start = $clock->time; Check::same(true, $slide->consume('slide', 'alice', 2)->allowed());
Check::same(true, $slide->consume('slide', 'alice', 1)->allowed());
$clock->time += 1; Check::same(true, $slide->consume('slide', 'alice', 2)->allowed());
$clock->time += 1; $r = $slide->consume('slide', 'alice', 1); Check::same('rate.capacity', $r->reason()); Check::same(8, $r->retryAfter());
$r = $slide->consume('slide', 'alice', 5); Check::same('rate.capacity', $r->reason()); Check::same(8, $r->retryAfter());
$clock->time = $start + 10; Check::same(true, $slide->consume('slide', 'alice', 6)->allowed());
$r = $slide->consume('slide', 'alice', 1); Check::same(false, $r->allowed()); Check::same(1, $r->retryAfter());
$clock->time += 1; Check::same(true, $slide->consume('slide', 'alice', 2)->allowed());
Check::same(2, count($store->states[Guard::key('budget', 'slide', 'alice')]['data']['events']));

$group = new BudgetGroup($store, ['fast' => new BudgetPolicy('token_bucket', 8, 10), 'slow' => new BudgetPolicy('fixed_window', 3, 100)], $clock);
$r = $group->consume('group', 'alice', ['fast' => 2, 'slow' => 3]); Check::same(true, $r->allowed()); Check::same(['fast','slow'], $r->charged()); Check::same('atomic', $r->mode());
$r = $group->consume('group', 'alice'); Check::same(false, $r->allowed()); Check::same([], $r->charged()); Check::same(['slow'], $r->blocked());
Check::same(6, $group->inspect('group', 'alice')->decisions()['fast']->remaining());
$snapshot = $store->states; $ttls = $store->expires; $group->inspect('group', 'alice'); Check::same($snapshot, $store->states); Check::same($ttls, $store->expires);
budgetReason('rate.policy_changed', function () use ($store, $clock) { (new BudgetGroup($store, ['fast' => new BudgetPolicy()], $clock))->consume('group', 'alice'); });
$groupKey = Guard::key('budget-group', 'group', 'alice'); $good = $store->states[$groupKey]; $store->states[$groupKey]['limits']['slow']['data']['used'] = 0;
budgetReason('storage.corrupt', function () use ($group) { $group->consume('group', 'alice'); }); $store->states[$groupKey] = $good;
$group->reset('group', 'alice'); Check::same(true, $group->consume('group', 'alice')->allowed());
// Reordering policies shares the same ledger; changing its definitions is an explicit migration.
$reordered = new BudgetGroup($store, ['slow' => new BudgetPolicy('fixed_window', 3, 100), 'fast' => new BudgetPolicy('token_bucket', 8, 10)], $clock);
Check::same(2, $reordered->inspect('group', 'alice')->decisions()['slow']->remaining());

$ip = new BudgetLimiter($store, new BudgetPolicy('fixed_window', 10, 300), $clock);
$account = new BudgetLimiter($store, new BudgetPolicy('fixed_window', 2, 300), $clock);
$tenant = new BudgetLimiter($store, new BudgetPolicy('fixed_window', 10, 300), $clock);
$composite = new CompositeLimiter(['ip' => $ip, 'account' => $account, 'tenant' => $tenant], $clock);
$binding = ['ip' => '192.0.2.1', 'account' => 'tenant:alice', 'tenant' => 'tenant'];
Check::same(true, $composite->consume('action', $binding)->allowed());
$binding['ip'] = '192.0.2.2'; Check::same(true, $composite->consume('action', $binding)->allowed());
$r = $composite->consume('action', $binding); Check::same(false, $r->allowed()); Check::same('ordered', $r->mode()); Check::same(['ip'], $r->charged()); Check::same(['account'], $r->blocked());
Check::same(['ip', 'account'], array_keys($r->decisions()));
Check::same(8, $tenant->inspect(CompositeLimiter::scopeFor('action', 'tenant'), 'tenant')->remaining());
Check::same(8, $ip->inspect(CompositeLimiter::scopeFor('action', 'ip'), '192.0.2.2')->remaining());
$beforeCalls = $store->calls;
foreach ([['ip' => 'x'], $binding + ['extra' => 'x'], array_merge($binding, ['account' => 1])] as $bad) {
    Check::throws(ValidationException::class, function () use ($composite, $bad) { $composite->consume('action', $bad); });
}
foreach ([['ip' => 1], ['ip' => 1, 'account' => 1, 'tenant' => 0], ['ip' => 1, 'account' => '1', 'tenant' => 1]] as $bad) {
    Check::throws(ValidationException::class, function () use ($composite, $binding, $bad) { $composite->consume('action', $binding, $bad); });
}
Check::same($beforeCalls, $store->calls);
$binding['account'] = 'tenant:bob'; Check::same(true, $composite->consume('action', $binding, ['ip' => 2, 'account' => 1, 'tenant' => 3])->allowed());
// Storage outages retain earlier committed attempts and never turn into permission to work.
$fault = new BudgetTestStore(); $fault->before = static function () { throw new StorageException('Unavailable.'); };
$failing = new CompositeLimiter(['ip' => $ip, 'account' => new BudgetLimiter($fault, new BudgetPolicy(), $clock)], $clock);
Check::throws(StorageException::class, function () use ($failing) { $failing->consume('outage', ['ip' => 'x', 'account' => 'a']); });
Check::same(9, $ip->inspect(CompositeLimiter::scopeFor('outage', 'ip'), 'x')->remaining());
// Expired storage reservations must not authorize an operation, even after a successful commit.
foreach (['single', 'group', 'ordered'] as $kind) {
    foreach (['before', 'after'] as $position) {
        $c = new TestClock(); $slow = new BudgetTestStore(); $slow->$position = static function () use ($c) { $c->time += 10; };
        $p = new BudgetPolicy('fixed_window', 1, 1); $service = new BudgetLimiter($slow, $p, $c);
        if ($kind === 'group') { $service = new BudgetGroup($slow, ['short' => $p, 'long' => new BudgetPolicy('fixed_window', 10, 100)], $c); }
        if ($kind === 'ordered') { $service = new CompositeLimiter(['one' => $service], $c); }
        budgetReason('rate.expired', function () use ($kind, $service) { $service->consume('slow', $kind === 'ordered' ? ['one' => 'alice'] : 'alice'); });
    }
}
$c = new TestClock(); $normal = new BudgetTestStore(); $late = new BudgetTestStore();
$late->after = static function () use ($c) { $c->time += 5; };
$expiring = new CompositeLimiter(['short' => new BudgetLimiter($normal, new BudgetPolicy('fixed_window', 1, 2), $c), 'long' => new BudgetLimiter($late, new BudgetPolicy('fixed_window', 1, 100), $c)], $c);
budgetReason('rate.expired', function () use ($expiring) { $expiring->consume('slow', ['short' => 'a', 'long' => 'a']); });
$c = new TestClock(); $backward = new BudgetTestStore(); $backward->after = static function () use ($c) { --$c->time; };
budgetReason('rate.clock', function () use ($backward, $c) { (new BudgetLimiter($backward, new BudgetPolicy(), $c))->consume('back', 'a'); });
// Maximum configured exact sliding history fits the shared Codec record and node limits.
if (PHP_INT_SIZE >= 8) {
    $c = new TestClock(); $c->time = PHP_INT_MAX - 31538000; $s = new MemoryStore($c);
    $bounded = new BudgetGroup($s, ['a' => new BudgetPolicy('sliding_window', 1000000, 86400, null, 1024), 'b' => new BudgetPolicy('sliding_window', 1000000, 86400, null, 512)], $c);
    for ($i = 0; $i < 512; ++$i) { Check::same(true, $bounded->consume('bounded', 'a')->allowed()); ++$c->time; }
    Check::same('rate.capacity', $bounded->consume('bounded', 'a')->decisions()['b']->reason());
    // Fill the longer child separately in a raw valid record to exercise the combined upper bound.
    $raw = new BudgetTestStore(); $c->time = PHP_INT_MAX - 31536001; $g = new BudgetGroup($raw, ['a' => new BudgetPolicy('sliding_window', 1000000, 86400, null, 1024), 'b' => new BudgetPolicy('sliding_window', 1000000, 86400, null, 512)], $c);
    $g->consume('bounded', 'a'); $k = Guard::key('budget-group', 'bounded', 'a'); $state = $raw->states[$k];
    foreach (['a' => 1024, 'b' => 512] as $name => $count) {
        $events = []; for ($i = 0; $i < $count; ++$i) { $events[] = [$c->time - $count + 1 + $i, 976]; }
        $state['limits'][$name]['data']['events'] = $events;
    }
    Check::same(true, strlen(SoSecurity\Storage\Codec::encode(new Change($state, $c->time + 86400, null))) < 65536);
    $raw->states[$k] = $state; Check::same(true, $g->inspect('bounded', 'a')->allowed());
}
foreach ([['unknown'], ['token_bucket', 0], ['token_bucket', 1, 0], ['fixed_window', 1, 10, 2], ['sliding_window', 1, 10, null, 1025], ['token_bucket', 1, 86400, 1000000]] as $bad) {
    Check::throws(ConfigurationException::class, function () use ($bad) { new BudgetPolicy(...$bad); });
}
Check::throws(ConfigurationException::class, function () use ($store) { new BudgetGroup($store, ['a' => new BudgetPolicy('sliding_window', 1, 10, null, 1024), 'b' => new BudgetPolicy('sliding_window', 1, 10, null, 1024)]); });
foreach ([[], [new BudgetPolicy()], ['INVALID' => new BudgetPolicy()]] as $bad) { Check::throws(ConfigurationException::class, function () use ($store, $bad) { new BudgetGroup($store, $bad); }); }
Check::throws(ConfigurationException::class, function () use ($policy) { $policy->limit = 100; });
Check::throws(ConfigurationException::class, function () use ($r) { serialize($r); });
$directory = privateDirectory();
try {
    $configuration = ['site' => 'budget-test', 'storage' => ['driver' => 'file', 'directory' => $directory], 'budgets' => ['ip' => ['algorithm' => 'fixed_window', 'limit' => 5], 'account' => ['limit' => 2]]];
    $factory = SoSecurity\Security::fromArray($configuration, [], $clock);
    Check::same(true, $factory->budgetLimiter('ip')->consume('factory', 'a', 2)->allowed());
    Check::same(true, $factory->budgetGroup(['ip', 'account'])->consume('factory', 'a')->allowed());
    Check::same(true, $factory->budgetComposite(['ip', 'account'])->consume('factory', ['ip' => 'x', 'account' => 'a'])->allowed());
    foreach ([[], ['ip','ip'], ['missing']] as $bad) { Check::throws(ConfigurationException::class, function () use ($factory, $bad) { $factory->budgetGroup($bad); }); }
    foreach (['memory','session'] as $driver) { Check::throws(ConfigurationException::class, function () use ($driver) { SoSecurity\Security::fromArray(['site' => 'a', 'storage' => ['driver' => $driver], 'budgets' => ['one' => []]])->budgetLimiter('one'); }); }
    foreach ([['one' => ['limit' => '1']], ['one' => ['burst' => 0]], ['one' => ['unknown' => 1]], ['INVALID' => []]] as $bad) { Check::throws(ConfigurationException::class, function () use ($bad) { SoSecurity\Security::fromArray(['site' => 'a', 'budgets' => $bad]); }); }
} finally { cleanDirectory($directory); }
require dirname(__DIR__) . '/examples/request-budgets.php';
$directory = privateDirectory();
try {
    $factory = SoSecurity\Security::fromArray(['site' => 'report-example', 'storage' => ['driver' => 'file', 'directory' => $directory], 'budgets' => ['ip' => ['limit' => 20], 'account' => ['limit' => 5], 'tenant' => ['limit' => 50]]], [], $clock);
    $actor = new SoSecurity\Auth\Account('tenant', 'alice', '1'); $executed = 0;
    foreach (['report.export','report.export','report.preview'] as $action) { if (SoSecurity\Examples\reserveReportBudget($factory, $action, '2001:db8::1', $actor)->allowed()) { ++$executed; } }
    Check::same(2, $executed);
    Check::throws(ValidationException::class, function () use ($factory, $actor) { SoSecurity\Examples\reserveReportBudget($factory, 'unknown', '192.0.2.1', $actor); });
    Check::same('manual', array_column($factory->diagnose(), null, 'check')['budgets.clock']['status']);
} finally { cleanDirectory($directory); }
Check::same(PHP_SESSION_NONE, session_status()); Check::same(false, headers_sent());
echo 'PASS budgets: ' . Check::$assertions . ' assertions on PHP ' . PHP_VERSION . "; weighted token/fixed/exact-second sliding, atomic groups, ordered dimensions, retry purity, bounded state and fail-closed storage\n";
