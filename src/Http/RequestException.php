<?php
declare(strict_types=1);
namespace SoSecurity\Http;

use SoSecurity\Exception\SecurityException;
final class RequestException extends SecurityException
{
    public function __construct(string $message, string $reason = 'http.unavailable', ?\Throwable $previous = null) { parent::__construct($message, $reason, $previous); }
}
