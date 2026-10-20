<?php
declare(strict_types=1);
namespace SoSecurity\Operation;
use SoSecurity\Exception\ConfigurationException;

/** Present the exact intent, then reauthenticate and explicitly confirm using this session-bound nonce. */
final class Confirmation
{
    private $token;
    private $id;
    private $intent;
    private $expires;
    public function __construct(string $token,Intent $intent,int $expiresAt)
    {
        $reference = State::reference($token,'oc1');
        if ($reference === null || $expiresAt < 1) { throw new ConfigurationException('Invalid operation confirmation.','configuration.operation'); }
        $this->token = static function()use($token):string{return $token;}; $this->id = $reference['id']; $this->intent = $intent; $this->expires = $expiresAt;
    }
    public function token(): string { if(!$this->token instanceof \Closure){throw new ConfigurationException('Reload private operation confirmation.','configuration.operation_serialization');}return ($this->token)(); }
    public function id(): string { return $this->id; }
    public function intent(): Intent { return $this->intent; }
    public function expiresAt(): int { return $this->expires; }
    public function __debugInfo(): array { return ['id'=>$this->id,'expires_at'=>$this->expires,'token'=>'[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Retain only protected opaque confirmation tokens.','configuration.operation_serialization'); }
    public function __wakeup(): void { throw new ConfigurationException('Rebuild operation confirmations from trusted state.','configuration.operation_serialization'); }
    public function __set(string $name,$value): void { throw new ConfigurationException('Operation confirmations are immutable.','configuration.immutable'); }
}
