<?php
declare(strict_types=1);

namespace SoSecurity\Examples;

use SoSecurity\Mfa\Enrollment;
use SoSecurity\Mfa\TotpFactors;

/**
 * Host integration helpers, not standalone endpoints. Load after vendor/autoload.php.
 * Server-owned callbacks return exactly true on success; false/void/other values refuse the operation.
 * Bind scope/subject from authenticated identity, never from submitted account IDs.
 */
function beginMfaEnrollment(TotpFactors $mfa, string $tenant, string $subject, string $accountLabel,
    callable $authorizeManagement, callable $verifyCsrf, callable $reserveBudget): Enrollment
{
    requireMfaCheck($authorizeManagement); // Current account + strong re-authentication for replacement.
    requireMfaCheck($verifyCsrf); requireMfaCheck($reserveBudget);
    return $mfa->begin($tenant, $subject, $accountLabel);
}

function confirmMfaEnrollment(TotpFactors $mfa, string $tenant, string $subject, string $enrollmentId, $code,
    callable $authorizeManagement, callable $verifyCsrf, callable $reserveBudget, callable $invalidateSessions,
    callable $enqueueNotification): ?array
{
    requireMfaCheck($authorizeManagement); requireMfaCheck($verifyCsrf); requireMfaCheck($reserveBudget);
    $codes = $mfa->confirm($tenant, $subject, $enrollmentId, $code);
    if ($codes === null) { return null; }
    // Separate host operations: record/retry failures; do not claim a cross-resource transaction.
    requireMfaCheck($invalidateSessions);
    if ($enqueueNotification('mfa.changed') !== true) { throw new \SoSecurity\Exception\SecurityException('MFA lifecycle propagation is incomplete.', 'mfa.lifecycle_incomplete'); }
    return $codes; // One response only with Cache-Control: no-store; never log plaintext codes.
}

function verifyPendingMfaLogin(TotpFactors $mfa, string $tenant, string $subject, $code, bool $recovery,
    callable $validatePendingLogin, callable $verifyCsrf, callable $reserveBudget, callable $completeLogin): bool
{
    requireMfaCheck($validatePendingLogin); // Password-verified identity, deadline, current version.
    requireMfaCheck($verifyCsrf); requireMfaCheck($reserveBudget);
    $valid = $recovery ? $mfa->verifyRecovery($tenant, $subject, $code) : $mfa->verify($tenant, $subject, $code);
    if (!$valid) { return false; }
    requireMfaCheck($completeLogin); // Host rotates Session ID and creates full identity after acceptance.
    return true;
}

function requireMfaCheck(callable $check): void
{
    if ($check() !== true) { throw new \SoSecurity\Exception\SecurityException('Host MFA check was not confirmed.', 'mfa.host_check_failed'); }
}
