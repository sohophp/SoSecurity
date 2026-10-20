<?php
declare(strict_types=1);
namespace SoSecurity\RateLimit;
use SoSecurity\Exception\ConfigurationException;

/** Integer-cost policy; token refill credits avoid floating-point drift and premature expiry. */
final class BudgetPolicy
{
    private $algorithm;
    private $limit;
    private $window;
    private $capacity;
    private $entries;
    public function __construct(string $algorithm = 'token_bucket', int $limit = 10, int $window = 60, ?int $burst = null, int $maximumEntries = 512)
    {
        if (!in_array($algorithm, ['token_bucket', 'fixed_window', 'sliding_window'], true) || $limit < 1 || $limit > 1000000
            || $window < 1 || $window > 86400 || $maximumEntries < 1 || $maximumEntries > 1024
            || ($algorithm !== 'token_bucket' && $burst !== null) || ($algorithm !== 'sliding_window' && $maximumEntries !== 512)) {
            throw new ConfigurationException('Invalid request-budget policy.', 'configuration.budget');
        }
        $capacity = $burst ?? $limit;
        if ($capacity < 1 || $capacity > 1000000 || $capacity > intdiv(PHP_INT_MAX, $window)
            || BudgetState::ceil($capacity * $window, $limit) > 31536000) { throw new ConfigurationException('Request-budget capacity/refill exceeds platform or retention limits.', 'configuration.budget'); }
        $this->algorithm = $algorithm; $this->limit = $limit; $this->window = $window; $this->capacity = $capacity;
        $this->entries = $algorithm === 'sliding_window' ? $maximumEntries : 0;
    }
    public function algorithm(): string { return $this->algorithm; }
    public function limit(): int { return $this->limit; }
    public function window(): int { return $this->window; }
    public function capacity(): int { return $this->capacity; }
    public function maximumEntries(): int { return $this->entries; }
    public function fingerprint(): string { return hash('sha256', json_encode([$this->algorithm, $this->limit, $this->window, $this->capacity, $this->entries])); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Budget policies are immutable.', 'configuration.immutable'); }
}
