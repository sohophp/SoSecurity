<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Password\PasswordHasher;

/** Local database/config adapter. Lookups return PasswordRecord|null; no credential writes or notifications. */
final class PasswordIdentityProvider implements IdentityProvider
{
    private $byIdentifier;
    private $bySubject;
    private $hasher;
    private $dummyHash;
    public function __construct(callable $byIdentifier, callable $bySubject, PasswordHasher $hasher, string $dummyHash)
    {
        PasswordRecord::validateHash($dummyHash);
        if (password_get_info($dummyHash)['algoName'] !== $hasher->profile() || password_get_info($dummyHash)['options'] != $hasher->parameters()) {
            throw new ConfigurationException('Dummy hash must use the configured verification profile.', 'configuration.dummy_hash');
        }
        $this->byIdentifier = $byIdentifier; $this->bySubject = $bySubject; $this->hasher = $hasher; $this->dummyHash = $dummyHash;
    }
    public function authenticate(string $scope, string $identifier, string $password): ?Account
    {
        $record = $this->record(($this->byIdentifier)($scope, $identifier), $scope);
        // Apply native verification for known/unknown/disabled accounts within the selected input profile.
        $valid = $this->hasher->verify($password, $record === null ? $this->dummyHash : $record->hash());
        return $valid && $record !== null && $record->account()->enabled() ? $this->identity($record) : null;
    }
    public function find(string $scope, string $subject): ?Account
    {
        $record = $this->record(($this->bySubject)($scope, $subject), $scope, $subject);
        return $record === null || !$record->account()->enabled() ? null : $this->identity($record);
    }
    private function record($record, string $scope, ?string $subject = null): ?PasswordRecord
    {
        if ($record === null) { return null; }
        if (!$record instanceof PasswordRecord || $record->account()->scope() !== $scope
            || ($subject !== null && $record->account()->subject() !== $subject)) {
            throw new SecurityException('Password lookup returned an invalid or cross-scope result.', 'auth.provider');
        }
        return $record;
    }
    private function identity(PasswordRecord $record): Account
    {
        // Include the actual saved hash, even when a legacy host forgets to increment its credential version.
        return $record->identity();
    }
    public function __debugInfo(): array { return ['credentials' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Do not serialize password providers.', 'configuration.identity_serialization'); }
}
