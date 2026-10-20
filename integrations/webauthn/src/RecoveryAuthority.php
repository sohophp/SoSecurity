<?php
declare(strict_types=1);

namespace SoSecurity\WebAuthn;

/**
 * Host integration: begin must consume independent strong approval and durably block old sessions
 * and new logins before returning true. Complete must keep that fence until recovery is reconciled.
 */
interface RecoveryAuthority
{
    public function begin(string $scope, string $userHandle, $proof, int $now): bool;
    public function complete(string $scope, string $userHandle, int $generation, int $now): bool;
}
