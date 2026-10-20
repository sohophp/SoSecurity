<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

final class RememberCredential
{
    private $token;
    private $id;
    private $expires;
    public function __construct(string $token, string $id, int $expiresAt) { $this->token = static function()use($token):string{return $token;}; $this->id = $id; $this->expires = $expiresAt; }
    public function token(): string { if(!$this->token instanceof \Closure){throw new \SoSecurity\Exception\ConfigurationException('Reload private persistent credential.','configuration.credential_serialization');}return ($this->token)(); }
    public function id(): string { return $this->id; }
    public function expiresAt(): int { return $this->expires; }
    public function __debugInfo(): array { return ['id' => $this->id, 'expires' => $this->expires, 'token' => '[redacted]']; }
    public function __sleep(): array { throw new \SoSecurity\Exception\ConfigurationException('Do not serialize persistent credential objects.', 'configuration.credential_serialization'); }
    public function __wakeup(): void { throw new \SoSecurity\Exception\ConfigurationException('Rebuild persistent credentials from trusted state.', 'configuration.credential_serialization'); }
    public function __set(string $name, $value): void { throw new \SoSecurity\Exception\ConfigurationException('Credentials are immutable.', 'configuration.immutable'); }
}
