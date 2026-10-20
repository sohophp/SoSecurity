<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Exception\ConfigurationException;

/** Plaintext only at explicit issue/rotation; not JSON serializable. Do not log or serialize this object. */
final class Credential
{
    private $token;
    private $identity;
    private $expires;
    public function __construct(string $token,Identity $identity,int $expires) { $this->token=static function()use($token):string{return $token;}; $this->identity=$identity; $this->expires=$expires; }
    public function token(): string { if(!$this->token instanceof \Closure){throw new ConfigurationException('Reload private API credential.','configuration.api_credential_serialization');}return ($this->token)(); }
    public function identity(): Identity { return $this->identity; }
    public function expiresAt(): int { return $this->expires; }
    public function __debugInfo(): array { return ['identity'=>$this->identity,'expires'=>$this->expires,'token'=>'[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Do not serialize API bearer credentials.','configuration.api_credential_serialization'); }
    public function __wakeup(): void { throw new ConfigurationException('Rebuild API bearer credentials from trusted state.','configuration.api_credential_serialization'); }
}
