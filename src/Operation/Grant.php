<?php
declare(strict_types=1);
namespace SoSecurity\Operation;
use SoSecurity\Exception\ConfigurationException;

/** One-use, exact-intent authorization; still requires the bound current authenticated session. */
final class Grant
{
    private $token;
    private $id;
    private $expires;
    public function __construct(string $token,int $expiresAt)
    {
        $reference = State::reference($token,'og1');
        if ($reference === null || $expiresAt < 1) { throw new ConfigurationException('Invalid operation grant.','configuration.operation'); }
        $this->token = static function()use($token):string{return $token;}; $this->id = $reference['id']; $this->expires = $expiresAt;
    }
    public function token(): string { if(!$this->token instanceof \Closure){throw new ConfigurationException('Reload private operation grant.','configuration.operation_serialization');}return ($this->token)(); }
    public function id(): string { return $this->id; }
    public function expiresAt(): int { return $this->expires; }
    public function __debugInfo(): array { return ['id'=>$this->id,'expires_at'=>$this->expires,'token'=>'[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Retain only protected opaque grant tokens.','configuration.operation_serialization'); }
    public function __wakeup(): void { throw new ConfigurationException('Rebuild operation grants from trusted state.','configuration.operation_serialization'); }
    public function __set(string $name,$value): void { throw new ConfigurationException('Operation grants are immutable.','configuration.immutable'); }
}
