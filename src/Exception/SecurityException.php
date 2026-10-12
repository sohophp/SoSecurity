<?php
declare(strict_types=1);
namespace SoSecurity\Exception;

/** Stable reason codes are safe to classify; exception text and previous exceptions are not public payloads. */
class SecurityException extends \RuntimeException
{
    private $reason;
    public function __construct(string $message, string $reason = 'security.unavailable', ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
        $this->reason = $reason;
    }
    public function reason(): string { return $this->reason; }
}
