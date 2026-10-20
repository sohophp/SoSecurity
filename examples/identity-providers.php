<?php
declare(strict_types=1);
namespace SoSecurity\Examples;

use SoSecurity\Auth\Account;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Exception\SecurityException;

/**
 * Adapt an existing authority SDK, not browser claims or an unsigned identity endpoint.
 * SDK callbacks must use trusted fixed endpoints, TLS, bounded I/O, and verified service credentials/protocols.
 * Null means a definitive unknown/disabled/revoked identity. Outages MUST throw.
 */
function remoteIdentityProvider(callable $verifyCredentials, callable $loadCurrent): CallbackIdentityProvider
{
    return new CallbackIdentityProvider(
        static function (string $scope, string $identifier, string $password) use ($verifyCredentials): ?Account {
            return authorityAccount($verifyCredentials($scope, $identifier, $password), $scope);
        },
        static function (string $scope, string $subject) use ($loadCurrent): ?Account {
            return authorityAccount($loadCurrent($scope, $subject), $scope, $subject);
        });
}

/** Map a small, explicitly selected authority payload. Never pass the entire browser/SDK response implicitly. */
function authorityAccount($payload, string $scope, ?string $subject = null): ?Account
{
    if ($payload === null) { return null; }
    $fields = ['scope', 'subject', 'version', 'enabled', 'roles', 'mfa_required'];
    if (!is_array($payload) || count($payload) !== count($fields) || array_diff($fields, array_keys($payload))
        || !is_string($payload['scope']) || $payload['scope'] !== $scope || !is_string($payload['subject'])
        || ($subject !== null && $payload['subject'] !== $subject) || !is_string($payload['version'])
        || !is_bool($payload['enabled']) || !is_bool($payload['mfa_required']) || !is_array($payload['roles'])) {
        throw new SecurityException('Authority payload does not match the selected identity contract.', 'auth.provider');
    }
    try { return new Account($payload['scope'], $payload['subject'], $payload['version'], $payload['enabled'], $payload['roles'], $payload['mfa_required']); }
    catch (\SoSecurity\Exception\ConfigurationException $e) { throw new SecurityException('Authority returned invalid identity attributes.', 'auth.provider', $e); }
}
