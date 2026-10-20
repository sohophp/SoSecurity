<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;

/** A fresh server-side identity snapshot; never deserialize an account from a client request. */
final class Account
{
    private $scope;
    private $subject;
    private $version;
    private $enabled;
    private $roles;
    private $mfaRequired;

    public function __construct(string $scope, string $subject, string $version, bool $enabled = true,
        array $roles = [], bool $mfaRequired = false)
    {
        foreach ([$scope, $subject, $version] as $value) {
            Guard::label($value);
            if (!preg_match('//u', $value)) { throw new ConfigurationException('Identity labels must be UTF-8.', 'configuration.identity'); }
        }
        if (count($roles) > 32) { throw new ConfigurationException('At most 32 roles are allowed.', 'configuration.identity'); }
        $copy = [];
        foreach ($roles as $role) {
            if (!is_string($role) || !preg_match('/\A[A-Za-z][A-Za-z0-9_:.-]{0,63}\z/D', $role)) { throw new ConfigurationException('Invalid role identifier.', 'configuration.identity'); }
            $copy[] = $role;
        }
        $copy = array_values(array_unique($copy)); sort($copy);
        $this->scope = $scope; $this->subject = $subject; $this->version = $version;
        $this->enabled = $enabled; $this->roles = $copy; $this->mfaRequired = $mfaRequired;
    }
    public function scope(): string { return $this->scope; }
    public function subject(): string { return $this->subject; }
    public function version(): string { return $this->version; }
    public function enabled(): bool { return $this->enabled; }
    public function roles(): array { return $this->roles; }
    public function mfaRequired(): bool { return $this->mfaRequired; }
    public function fingerprint(): string
    {
        return hash('sha256', json_encode([$this->scope, $this->subject, $this->version, $this->enabled, $this->roles, $this->mfaRequired]));
    }
    public function __set(string $name, $value): void { throw new ConfigurationException('Accounts are immutable.', 'configuration.immutable'); }
    public function __sleep(): array { throw new ConfigurationException('Do not cache identity snapshots as authentication; store only registry references.', 'configuration.identity_serialization'); }
}
