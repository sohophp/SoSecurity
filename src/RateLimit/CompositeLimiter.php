<?php
declare(strict_types=1);
namespace SoSecurity\RateLimit;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;

/** Ordered independent counters: fail at first rejection; previously committed charges are deliberately retained. */
final class CompositeLimiter
{
    private $limits = [];
    private $clock;
    public function __construct(array $limits, ?Clock $clock = null)
    {
        if (!$limits || count($limits) > 8) { throw new ConfigurationException('Combine 1-8 independent budget limiters.', 'configuration.budget'); }
        foreach ($limits as $name => $limit) {
            BudgetBindings::name($name);
            if (!$limit instanceof BudgetLimiter) { throw new ConfigurationException('Expected individual budget limiters.', 'configuration.budget'); }
            $this->limits[$name] = $limit;
        }
        $this->clock = $clock ?? new SystemClock();
    }
    public static function scopeFor(string $scope, string $dimension): string
    {
        BudgetBindings::name($dimension);
        if (!preg_match('//u', $scope)) { throw new ConfigurationException('Budget scope must be UTF-8.', 'configuration.budget'); }
        return Guard::key('budget-composite', $scope, $dimension);
    }
    public function consume(string $scope, array $subjects, array $costs = []): BudgetResult { return $this->evaluate($scope, $subjects, $costs, true); }
    public function inspect(string $scope, array $subjects, array $costs = []): BudgetResult { return $this->evaluate($scope, $subjects, $costs, false); }
    private function evaluate(string $scope, array $subjects, array $costs, bool $consume): BudgetResult
    {
        $now = $this->clock->now(); $names = array_keys($this->limits); $subjects = BudgetBindings::subjects($names, $subjects); $costs = BudgetBindings::costs($names, $costs); $decisions = [];
        foreach ($this->limits as $name => $limit) {
            $childScope = self::scopeFor($scope, $name);
            $decision = $consume ? $limit->consume($childScope, $subjects[$name], $costs[$name]) : $limit->inspect($childScope, $subjects[$name], $costs[$name]);
            $decisions[$name] = $decision;
            if (!$decision->allowed()) { break; }
        }
        $result = new BudgetResult($decisions, count($this->limits), 'ordered', $consume);
        BudgetState::finish($now, $this->clock->now(), $consume && $result->allowed(), $result->reservedUntil());
        return $result;
    }
    public function __debugInfo(): array { return ['ordered_dimensions' => array_keys($this->limits)]; }
}
