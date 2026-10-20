<?php
declare(strict_types=1);
namespace SoSecurity\Concurrency;
use SoSecurity\Exception\ConfigurationException;

/** An expiring owner credential, not proof that a business write can still commit. */
final class Lease
{
    private $token;
    private $epoch;
    private $fence;
    private $expires;
    private $absolute;
    public function __construct(string $token, int $fence, int $expiresAt, int $absoluteExpiresAt)
    {
        $parts = LeaseState::token($token);
        if ($parts === null || $fence < 1 || $expiresAt < 1 || $absoluteExpiresAt < $expiresAt) { throw new ConfigurationException('Invalid lease credential.', 'configuration.lease'); }
        $this->token = static function()use($token):string{return $token;}; $this->epoch = $parts['epoch']; $this->fence = $fence; $this->expires = $expiresAt; $this->absolute = $absoluteExpiresAt;
    }
    public function token(): string { if(!$this->token instanceof \Closure){throw new ConfigurationException('Reload private lease credential.','configuration.lease_serialization');}return ($this->token)(); }
    public function epoch(): string { return $this->epoch; }
    public function fence(): int { return $this->fence; }
    public function expiresAt(): int { return $this->expires; }
    public function absoluteExpiresAt(): int { return $this->absolute; }
    public function __debugInfo(): array { return ['credential' => '[REDACTED]', 'fence' => $this->fence, 'expires_at' => $this->expires]; }
    public function __sleep(): array { throw new ConfigurationException('Keep lease credentials in the owning worker, never serialized.', 'configuration.lease_serialization'); }
    public function __wakeup(): void { throw new ConfigurationException('Rebuild lease credentials in the owning worker.', 'configuration.lease_serialization'); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Lease credentials are immutable.', 'configuration.immutable'); }
}
