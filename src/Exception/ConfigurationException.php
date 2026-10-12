<?php
declare(strict_types=1);
namespace SoSecurity\Exception;

/** Developer configuration failure; retains InvalidArgumentException compatibility. */
final class ConfigurationException extends \InvalidArgumentException
{
    private $reason;
    public function __construct(string $message, string $reason = 'configuration.invalid', ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
        $this->reason = $reason;
    }
    public function reason(): string { return $this->reason; }
}
