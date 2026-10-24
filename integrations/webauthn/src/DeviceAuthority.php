<?php
declare(strict_types=1);

namespace SoSecurity\WebAuthn;

/** Host must re-check current identity and recent authentication.
 * before consumes the one-use request proof; current rechecks after credential reads
 * without consuming it again; return rechecks after the SQL mutation.
 * Reject unknown phases. Current checks must not charge request budgets again. */
interface DeviceAuthority
{
    public function allow(string $phase, string $scope, string $userHandle, string $credentialId,
        $proof, int $now): bool;
}
