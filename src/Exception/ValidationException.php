<?php
declare(strict_types=1);
namespace SoSecurity\Exception;

/** Expected invalid input. Boolean-verifier APIs still return false instead of throwing. */
final class ValidationException extends \InvalidArgumentException
{
    private $reason;
    public function __construct(string $message, string $reason = 'input.invalid', ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous); $this->reason = $reason;
    }
    public function reason(): string { return $this->reason; }
}
