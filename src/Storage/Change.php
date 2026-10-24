<?php
declare(strict_types=1);

namespace SoSecurity\Storage;

/** The callback returns both committed state and its public result. Null deletes state. */
final class Change
{
    private $contents;

    public function __construct(?array $value, int $expiresAt, $result)
    {
        if ($expiresAt < 0) {
            throw new \SoSecurity\Exception\ConfigurationException('Expiry must be non-negative; zero means permanent.');
        }
        $this->contents = static function () use ($value, $expiresAt, $result): array { return [$value, $expiresAt, $result]; };
    }
    public function value(): ?array { return ($this->contents)()[0]; }
    public function expiresAt(): int { return ($this->contents)()[1]; }
    public function result() { return ($this->contents)()[2]; }
    public function __debugInfo(): array { return ['state_change' => '[redacted]']; }
    public function __sleep(): array
    {
        throw new \SoSecurity\Exception\ConfigurationException('Do not serialize private storage changes.', 'configuration.storage_serialization');
    }
    public function __wakeup(): void
    {
        throw new \SoSecurity\Exception\ConfigurationException('Rebuild storage changes from trusted state.', 'configuration.storage_serialization');
    }
    public function __set(string $name, $value): void
    {
        throw new \SoSecurity\Exception\ConfigurationException('State changes are immutable.', 'configuration.immutable');
    }
}
