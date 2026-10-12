<?php
declare(strict_types=1);

namespace SoSecurity\Storage;

/** The callback returns both committed state and its public result. Null deletes state. */
final class Change
{
    public $value;
    public $expiresAt;
    public $result;

    public function __construct(?array $value, int $expiresAt, $result)
    {
        if ($expiresAt < 0) {
            throw new \InvalidArgumentException('Expiry must be non-negative; zero means permanent.');
        }
        $this->value = $value;
        $this->expiresAt = $expiresAt;
        $this->result = $result;
    }
}
