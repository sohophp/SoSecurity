<?php
declare(strict_types=1);
namespace SoSecurity\Operation;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Exception\ConfigurationException;

/** Consumed authority for an immediate host transaction, never a reusable credential. */
final class Permit
{
    private $id;
    private $intent;
    private $account;
    private $session;
    private $method;
    private $authenticated;
    private $expires;
    public function __construct(string $id,Intent $intent,Account $account,string $sessionId,string $method,int $authenticatedAt,int $expiresAt)
    {
        if (!State::hex($id,32) || !State::hex($sessionId,32) || !$account->enabled() || $account->scope() !== $intent->resource()->scope()
            || $authenticatedAt < 1 || $expiresAt <= $authenticatedAt) { throw new ConfigurationException('Invalid consumed operation authority.','configuration.operation'); }
        SessionRegistry::strength($method); $this->id = $id; $this->intent = $intent; $this->account = $account; $this->session = $sessionId;
        $this->method = $method; $this->authenticated = $authenticatedAt; $this->expires = $expiresAt;
    }
    public function id(): string { return $this->id; }
    public function intent(): Intent { return $this->intent; }
    public function account(): Account { return $this->account; }
    public function sessionId(): string { return $this->session; }
    public function method(): string { return $this->method; }
    public function authenticatedAt(): int { return $this->authenticated; }
    public function expiresAt(): int { return $this->expires; }
    public function __debugInfo(): array { return ['operation_id'=>$this->id,'expires_at'=>$this->expires,'authority'=>'[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Do not cache consumed operation authority.','configuration.operation_serialization'); }
    public function __set(string $name,$value): void { throw new ConfigurationException('Operation permits are immutable.','configuration.immutable'); }
}
