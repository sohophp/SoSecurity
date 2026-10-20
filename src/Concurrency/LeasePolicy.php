<?php
declare(strict_types=1);
namespace SoSecurity\Concurrency;
use SoSecurity\Exception\ConfigurationException;

final class LeasePolicy
{
    private $maximum;
    private $ttl;
    private $lifetime;
    public function __construct(int $maximum = 1, int $ttl = 30, int $maximumLifetime = 300)
    {
        if ($maximum < 1 || $maximum > 64 || $ttl < 1 || $ttl > 3600 || $maximumLifetime < $ttl || $maximumLifetime > 86400) { throw new ConfigurationException('Invalid bounded lease policy.', 'configuration.lease'); }
        $this->maximum = $maximum; $this->ttl = $ttl; $this->lifetime = $maximumLifetime;
    }
    public function maximum(): int { return $this->maximum; }
    public function ttl(): int { return $this->ttl; }
    public function maximumLifetime(): int { return $this->lifetime; }
    public function fingerprint(): string { return hash('sha256', json_encode([$this->maximum, $this->ttl, $this->lifetime])); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Lease policies are immutable.', 'configuration.immutable'); }
}
