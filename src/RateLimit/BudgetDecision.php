<?php
declare(strict_types=1);
namespace SoSecurity\RateLimit;
use SoSecurity\Exception\ConfigurationException;

final class BudgetDecision
{
    private $allowed;
    private $remaining;
    private $retry;
    private $reason;
    private $until;
    public function __construct(bool $allowed, int $remaining, int $retryAfter = 0, string $reason = 'rate.allowed', int $reservedUntil = 0)
    {
        if ($remaining < 0 || $retryAfter < 0 || !in_array($reason, ['rate.allowed', 'rate.exhausted', 'rate.capacity', 'rate.cost_exceeds_limit'], true)
            || $allowed !== ($reason === 'rate.allowed') || ($allowed && $retryAfter !== 0) || $reservedUntil < 0 || (!$allowed && $reservedUntil !== 0)) { throw new ConfigurationException('Invalid budget decision.', 'configuration.budget'); }
        $this->allowed = $allowed; $this->remaining = $remaining; $this->retry = $retryAfter; $this->reason = $reason;
        $this->until = $reservedUntil;
    }
    public function allowed(): bool { return $this->allowed; }
    public function remaining(): int { return $this->remaining; }
    public function retryAfter(): int { return $this->retry; }
    public function reason(): string { return $this->reason; }
    public function reservedUntil(): int { return $this->until; }
    public function __sleep(): array { throw new ConfigurationException('Recheck budgets instead of serializing decisions.', 'configuration.budget_serialization'); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Budget decisions are immutable.', 'configuration.immutable'); }
}
