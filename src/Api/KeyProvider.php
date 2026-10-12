<?php
declare(strict_types=1);
namespace SoSecurity\Api;
interface KeyProvider
{
    /** Trusted bounded lookup; returns only currently authorized keys. Exceptions must not become authentication success. */
    public function find(string $id): ?SigningKey;
}
