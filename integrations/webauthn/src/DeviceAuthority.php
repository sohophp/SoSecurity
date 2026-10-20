<?php
declare(strict_types=1);

namespace SoSecurity\WebAuthn;

/** Host must re-check current identity, recent authentication and one-use request proof. */
interface DeviceAuthority
{
    public function allow(string $phase, string $scope, string $userHandle, string $credentialId,
        $proof, int $now): bool;
}
