<?php
declare(strict_types=1);

namespace SoSecurity\Storage;

/** The callback returns both committed state and its public result. Null deletes state. */
final class Change
{
    private $value;
    private $expiresAt;
    private $result;

    public function __construct(?array $value, int $expiresAt, $result)
    {
        if ($expiresAt < 0) {
            throw new \SoSecurity\Exception\ConfigurationException('Expiry must be non-negative; zero means permanent.');
        }
        $this->value = $value;
        $this->expiresAt = $expiresAt;
        $this->result = $result;
    }
    public function value(): ?array { return $this->value; }
    public function expiresAt(): int { return $this->expiresAt; }
    public function result() { return $this->result; }
    public function __set(string $name, $value): void
    {
        throw new \SoSecurity\Exception\ConfigurationException('State changes are immutable.', 'configuration.immutable');
    }
}
