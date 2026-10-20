<?php
declare(strict_types=1);
namespace SoSecurity\RateLimit;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

final class BudgetLimiter
{
    private $store;
    private $policy;
    private $clock;
    public function __construct(AtomicStore $store, BudgetPolicy $policy, ?Clock $clock = null) { $this->store = $store; $this->policy = $policy; $this->clock = $clock ?? new SystemClock(); }
    public function policy(): BudgetPolicy { return $this->policy; }
    public function consume(string $scope, string $subject, int $cost = 1): BudgetDecision { return $this->evaluate($scope, $subject, $cost, true); }
    public function inspect(string $scope, string $subject, int $cost = 1): BudgetDecision { return $this->evaluate($scope, $subject, $cost, false); }
    private function evaluate(string $scope, string $subject, int $cost, bool $consume): BudgetDecision
    {
        $now = $this->clock->now(); BudgetState::input($scope, $subject, $cost, $now);
        $decision = $this->store->transact(Guard::key('budget', $scope, $subject), function ($state) use ($now, $cost, $consume) { return BudgetState::evaluate($state, $this->policy, $now, $cost, $consume); });
        BudgetState::finish($now, $this->clock->now(), $consume && $decision->allowed(), $decision->reservedUntil());
        return $decision;
    }
    /** Explicit authorized maintenance only; never reset automatically after successful login. */
    public function reset(string $scope, string $subject): void
    {
        BudgetState::input($scope, $subject, 1, $this->clock->now());
        $this->store->transact(Guard::key('budget', $scope, $subject), static function () { return new Change(null, 0, null); });
    }
    public function __debugInfo(): array { return ['request_budget' => $this->policy->algorithm()]; }
}
