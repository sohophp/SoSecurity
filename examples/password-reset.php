<?php
declare(strict_types=1);

namespace SoSecurity\Examples;

use SoSecurity\Password\PasswordHasher;
use SoSecurity\Password\PasswordPolicy;
use SoSecurity\Password\ResetTokens;

/**
 * Host adapter example. The host explicitly creates/maps accounts(id, version, password_hash).
 * Does not create tables, manage mail/authentication or commit/rollback the host transaction.
 * Token consumption and host SQL are separate resources: on SQL failure issue a fresh token.
 */
function resetPassword(\PDO $pdo, ResetTokens $tokens, PasswordHasher $hasher, string $account,
    int $expectedVersion, $token, string $newPassword): string
{
    if ($expectedVersion < 1 || $account === '' || strlen($account) > 128) { return 'reset.invalid'; }
    if ((new PasswordPolicy())->errors($newPassword)) { return 'password.invalid'; }
    // Do expensive hashing before burning a valid token; the HTTP host must limit requests first.
    $hash = $hasher->hash($newPassword);
    if (!$tokens->consume($account . ':' . $expectedVersion, $token)) { return 'reset.invalid'; }
    $update = $pdo->prepare('UPDATE accounts SET password_hash = :hash, version = version + 1 WHERE id = :id AND version = :version');
    if ($update === false || !$update->execute(['hash' => $hash, 'id' => $account, 'version' => $expectedVersion])) {
        throw new \RuntimeException('Host password update failed; the consumed token must not be reused.');
    }
    // Concurrent password changes cannot be overwritten using a token bound to the prior version.
    if ($update->rowCount() !== 1) { return 'reset.conflict'; }
    try { $tokens->revoke($account . ':' . $expectedVersion); }
    catch (\SoSecurity\Storage\StorageException $e) {
        // The row version already changed: old-version tokens cannot overwrite it. Do not hide a committed update.
        return 'reset.applied_cleanup_pending';
    }
    return 'reset.applied';
}
