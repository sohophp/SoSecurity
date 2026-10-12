<?php
declare(strict_types=1);

namespace SoSecurity\RateLimit;

final class Decision
{
    public $allowed;
    public $remaining;
    public $retryAfter;
    public $permanent;

    public function __construct(bool $allowed, int $remaining, int $retryAfter = 0, bool $permanent = false)
    {
        $this->allowed = $allowed;
        $this->remaining = $remaining;
        $this->retryAfter = $retryAfter;
        $this->permanent = $permanent;
    }
}
