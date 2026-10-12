<?php
declare(strict_types=1);
namespace SoSecurity\Api;

/** Plaintext only at explicit issue/rotation; not JSON serializable. Do not log or serialize this object. */
final class Credential
{
    private $token;
    private $identity;
    private $expires;
    public function __construct(string $token,Identity $identity,int $expires) { $this->token=$token; $this->identity=$identity; $this->expires=$expires; }
    public function token(): string { return $this->token; }
    public function identity(): Identity { return $this->identity; }
    public function expiresAt(): int { return $this->expires; }
    public function __debugInfo(): array { return ['identity'=>$this->identity,'expires'=>$this->expires,'token'=>'[redacted]']; }
}
