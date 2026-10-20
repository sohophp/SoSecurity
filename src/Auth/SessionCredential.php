<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

/** Sensitive opaque registry credential, normally retained in the host's protected native Session. */
final class SessionCredential
{
    private $token;
    private $id;
    private $expires;
    public function __construct(string $token, string $id, int $expiresAt) { $this->token = static function()use($token):string{return $token;}; $this->id = $id; $this->expires = $expiresAt; }
    public function token(): string { if(!$this->token instanceof \Closure){throw new \SoSecurity\Exception\ConfigurationException('Reload private session credential.','configuration.credential_serialization');}return ($this->token)(); }
    public function id(): string { return $this->id; }
    public function expiresAt(): int { return $this->expires; }
    public function __debugInfo(): array { return ['id' => $this->id, 'expires' => $this->expires, 'token' => '[redacted]']; }
    public function __sleep(): array { throw new \SoSecurity\Exception\ConfigurationException('Do not serialize credential objects; retain only the opaque token in a protected host session.', 'configuration.credential_serialization'); }
    public function __wakeup(): void { throw new \SoSecurity\Exception\ConfigurationException('Rebuild session credentials from trusted state.', 'configuration.credential_serialization'); }
    public function __set(string $name, $value): void { throw new \SoSecurity\Exception\ConfigurationException('Credentials are immutable.', 'configuration.immutable'); }
}
