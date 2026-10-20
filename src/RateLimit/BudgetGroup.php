<?php
declare(strict_types=1);
namespace SoSecurity\RateLimit;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** One owner, one ledger, atomic all-or-none debit. Does not share counters with independent BudgetLimiter keys. */
final class BudgetGroup
{
    private $store;
    private $policies = [];
    private $fingerprint;
    private $clock;
    public function __construct(AtomicStore $store, array $policies, ?Clock $clock = null)
    {
        if (!$policies || count($policies) > 8) { throw new ConfigurationException('Group 1-8 budget policies.', 'configuration.budget'); }
        $fingerprints = []; $entries = 0;
        foreach ($policies as $name => $policy) {
            BudgetBindings::name($name);
            if (!$policy instanceof BudgetPolicy) { throw new ConfigurationException('Expected budget policies.', 'configuration.budget'); }
            $this->policies[$name] = $policy; $fingerprints[$name] = $policy->fingerprint(); $entries += $policy->maximumEntries();
        }
        if ($entries > 1536) { throw new ConfigurationException('Atomic group sliding-entry budgets exceed the shared record limit.', 'configuration.budget'); }
        ksort($fingerprints); $this->fingerprint = hash('sha256', json_encode($fingerprints)); $this->store = $store; $this->clock = $clock ?? new SystemClock();
    }
    public function consume(string $scope, string $subject, array $costs = []): BudgetResult { return $this->evaluate($scope, $subject, $costs, true); }
    public function inspect(string $scope, string $subject, array $costs = []): BudgetResult { return $this->evaluate($scope, $subject, $costs, false); }
    private function evaluate(string $scope, string $subject, array $costs, bool $consume): BudgetResult
    {
        $now = $this->clock->now(); BudgetState::input($scope, $subject, 1, $now); $costs = BudgetBindings::costs(array_keys($this->policies), $costs);
        $result = $this->store->transact(Guard::key('budget-group', $scope, $subject), function ($state) use ($now, $costs, $consume) {
            $expiry = 0;
            if ($state !== null) {
                if (!is_array($state) || !BudgetState::fields($state, ['v','policy','seen','limits']) || $state['v'] !== 1 || !is_string($state['policy'])
                    || !preg_match('/\A[a-f0-9]{64}\z/D', $state['policy']) || !is_int($state['seen']) || $state['seen'] < 0 || !is_array($state['limits'])) { throw new StorageException('Corrupt atomic budget group.', 'storage.corrupt'); }
                if (!hash_equals($this->fingerprint, $state['policy'])) { throw new StorageException('Active budget group policy changed.', 'rate.policy_changed'); }
                if (!BudgetState::fields($state['limits'], array_keys($this->policies))) { throw new StorageException('Corrupt atomic group dimensions.', 'storage.corrupt'); }
                if ($state['seen'] > $now) { throw new StorageException('Budget group clock moved backwards.', 'rate.clock'); }
                foreach ($this->policies as $name => $policy) {
                    $child = $state['limits'][$name];
                    if (!is_array($child) || !isset($child['seen'], $child['expires']) || !is_int($child['seen']) || $child['seen'] > $state['seen']) { throw new StorageException('Corrupt budget group child.', 'storage.corrupt'); }
                    BudgetState::read($child, $policy, $now); $expiry = max($expiry, $child['expires']);
                }
                if ($expiry <= $now) { $state = null; $expiry = 0; }
            }
            $decisions = []; $all = true;
            foreach ($this->policies as $name => $policy) {
                $decisions[$name] = BudgetState::evaluate($state['limits'][$name] ?? null, $policy, $now, $costs[$name], false)->result();
                $all = $all && $decisions[$name]->allowed();
            }
            if (!$consume || !$all) {
                if ($consume && $state !== null) { $state['seen'] = $now; }
                return new Change($state, $expiry, new BudgetResult($decisions, count($this->policies), 'atomic', $consume));
            }
            $next = ['v' => 1, 'policy' => $this->fingerprint, 'seen' => $now, 'limits' => []]; $expiry = 0;
            foreach ($this->policies as $name => $policy) {
                $change = BudgetState::evaluate($state['limits'][$name] ?? null, $policy, $now, $costs[$name], true);
                $next['limits'][$name] = $change->value(); $decisions[$name] = $change->result(); $expiry = max($expiry, $change->expiresAt());
            }
            return new Change($next, $expiry, new BudgetResult($decisions, count($this->policies), 'atomic', true));
        });
        BudgetState::finish($now, $this->clock->now(), $consume && $result->allowed(), $result->reservedUntil());
        return $result;
    }
    /** Host authorizes this explicit maintenance operation. */
    public function reset(string $scope, string $subject): void
    {
        BudgetState::input($scope, $subject, 1, $this->clock->now());
        $this->store->transact(Guard::key('budget-group', $scope, $subject), static function () { return new Change(null, 0, null); });
    }
    public function __debugInfo(): array { return ['atomic_policies' => array_keys($this->policies)]; }
}
