<?php
declare(strict_types=1);

namespace SoSecurity\Oidc;

use SoSecurity\Auth\Account;
use SoSecurity\Exception\ConfigurationException;

/** Authority exists only after FederatedSessions::verify() rechecks the provider link and logout fence. */
final class FederatedSession
{
    private $account;
    private $id;
    private $created;
    private $expires;

    public function __construct(Account $account, string $id, int $created, int $expires)
    {
        $this->account = $account; $this->id = $id; $this->created = $created; $this->expires = $expires;
    }
    public function account(): Account { return $this->account; }
    public function id(): string { return $this->id; }
    public function createdAt(): int { return $this->created; }
    public function expiresAt(): int { return $this->expires; }
    public function method(): string { return 'oidc'; }
    public function __sleep(): array { throw new ConfigurationException('Verify federated sessions on every request.', 'configuration.identity_serialization'); }
}
