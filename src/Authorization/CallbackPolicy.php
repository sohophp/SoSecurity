<?php
declare(strict_types=1);
namespace SoSecurity\Authorization;
use SoSecurity\Auth\Account;
use SoSecurity\Exception\ConfigurationException;

final class CallbackPolicy implements PolicyProvider
{
    private $callback;
    public function __construct(callable $callback) { $this->callback = $callback; }
    public function decide(Account $actor, string $action, Resource $resource, array $requestedFields = []): ?Decision
    {
        $decision = ($this->callback)($actor, $action, $resource, $requestedFields);
        if ($decision !== null && !$decision instanceof Decision) { throw new ConfigurationException('Policy must return Decision or null.', 'authorization.policy_contract'); }
        return $decision;
    }
    public function __debugInfo(): array { return ['policy' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Rebuild policy services.', 'configuration.authorization_serialization'); }
}
