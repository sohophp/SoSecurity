<?php
declare(strict_types=1);
namespace SoSecurity\Concurrency;
use SoSecurity\Exception\ConfigurationException;

/** Aggregate inspection only; does not expose holder identifiers or secrets. */
final class LeaseStatus
{
    private $epoch;
    private $active;
    private $maximum;
    private $sequence;
    private $retry;
    public function __construct(?string $epoch, int $active, int $maximum, int $sequence, int $retryAfter = 0)
    {
        if (($epoch !== null && !preg_match('/\A[a-f0-9]{32}\z/D', $epoch)) || $maximum < 1 || $maximum > 64 || $active < 0 || $active > $maximum
            || $sequence < $active || $retryAfter < 0 || ($epoch === null && ($active !== 0 || $sequence !== 0 || $retryAfter !== 0))) { throw new ConfigurationException('Invalid lease status.', 'configuration.lease'); }
        $this->epoch = $epoch; $this->active = $active; $this->maximum = $maximum; $this->sequence = $sequence; $this->retry = $retryAfter;
    }
    public function initialized(): bool { return $this->epoch !== null; }
    public function epoch(): ?string { return $this->epoch; }
    public function active(): int { return $this->active; }
    public function maximum(): int { return $this->maximum; }
    public function available(): int { return $this->initialized() ? $this->maximum - $this->active : 0; }
    public function sequence(): int { return $this->sequence; }
    public function retryAfter(): int { return $this->retry; }
    public function __sleep(): array { throw new ConfigurationException('Recheck live lease state.', 'configuration.lease_serialization'); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Lease status is immutable.', 'configuration.immutable'); }
}
