<?php
declare(strict_types=1);
namespace SoSecurity\Exception;

final class DependencyException extends SecurityException
{
    public function __construct(string $message, string $reason = 'dependency.unavailable', ?\Throwable $previous = null)
    {
        parent::__construct($message, $reason, $previous);
    }
}
