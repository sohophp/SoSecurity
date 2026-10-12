<?php
declare(strict_types=1);
namespace SoSecurity\Storage;

use SoSecurity\Exception\SecurityException;

final class StorageException extends SecurityException
{
    public function __construct(string $message, string $reason = 'storage.unavailable', ?\Throwable $previous = null)
    {
        parent::__construct($message, $reason, $previous);
    }
}
