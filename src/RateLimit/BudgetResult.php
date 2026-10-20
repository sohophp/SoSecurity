<?php
declare(strict_types=1);
namespace SoSecurity\RateLimit;
use SoSecurity\Exception\ConfigurationException;

/** Composite outcome, including the explicitly retained charges. Not a reusable operation grant. */
final class BudgetResult
{
    private $decisions = [];
    private $allowed;
    private $charged = [];
    private $blocked = [];
    private $retry = 0;
    private $mode;
    private $until = 0;
    public function __construct(array $decisions, int $expected, string $mode, bool $consumed)
    {
        if ($expected < 1 || $expected > 8 || !$decisions || count($decisions) > $expected || !in_array($mode, ['atomic','ordered'], true)) { throw new ConfigurationException('Invalid composite budget result.', 'configuration.budget'); }
        $neverFits = false;
        foreach ($decisions as $name => $decision) {
            BudgetBindings::name($name);
            if (!$decision instanceof BudgetDecision) { throw new ConfigurationException('Expected budget decisions.', 'configuration.budget'); }
            $this->decisions[$name] = $decision;
            if (!$decision->allowed()) {
                $this->blocked[] = $name; $this->retry = max($this->retry, $decision->retryAfter());
                if ($decision->reason() === 'rate.cost_exceeds_limit') { $neverFits = true; }
            }
        }
        $this->allowed = count($decisions) === $expected && !$this->blocked; $this->mode = $mode;
        if ($neverFits) { $this->retry = 0; }
        if ($consumed && ($mode === 'ordered' || $this->allowed)) {
            foreach ($this->decisions as $name => $decision) { if ($decision->allowed()) { $this->charged[] = $name; } }
        }
        if ($consumed && $this->allowed) {
            foreach ($this->decisions as $decision) {
                if ($decision->reservedUntil() < 1) { throw new ConfigurationException('Admitted composites require committed reservations.', 'configuration.budget'); }
                $this->until = $this->until === 0 ? $decision->reservedUntil() : min($this->until, $decision->reservedUntil());
            }
        }
    }
    public function allowed(): bool { return $this->allowed; }
    public function decisions(): array { return $this->decisions; }
    public function charged(): array { return $this->charged; }
    public function blocked(): array { return $this->blocked; }
    public function retryAfter(): int { return $this->retry; }
    public function mode(): string { return $this->mode; }
    public function reservedUntil(): int { return $this->until; }
    public function __sleep(): array { throw new ConfigurationException('Recheck composite budgets.', 'configuration.budget_serialization'); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Budget results are immutable.', 'configuration.immutable'); }
}
