<?php
declare(strict_types=1);
namespace SoSecurity\Authorization;
use SoSecurity\Auth\Account;
use SoSecurity\Exception\ConfigurationException;

/** Every policy must explicitly allow. Unsupported/denied wins; field whitelists intersect. */
final class PolicySet implements PolicyProvider
{
    private $policies = [];
    public function __construct(array $policies)
    {
        if (count($policies) > 32) { throw new ConfigurationException('At most 32 policies may be combined.', 'configuration.authorization'); }
        foreach ($policies as $policy) {
            if (!$policy instanceof PolicyProvider) { throw new ConfigurationException('Expected policy providers.', 'configuration.authorization'); }
            $this->policies[] = $policy;
        }
    }
    public function decide(Account $actor, string $action, Resource $resource, array $requestedFields = []): ?Decision
    {
        if (!$this->policies) { return null; }
        $fields = null;
        foreach ($this->policies as $policy) {
            $decision = $policy->decide($actor, $action, $resource, $requestedFields);
            if ($decision === null) { return Decision::deny('authorization.no_policy'); }
            if (!$decision->allowed()) { return $decision; }
            $fields = $fields === null ? $decision->fields() : array_values(array_intersect($fields, $decision->fields()));
        }
        return Decision::allow($fields ?? []);
    }
    public function __debugInfo(): array { return ['policy_count' => count($this->policies)]; }
    public function __sleep(): array { throw new ConfigurationException('Rebuild policy services.', 'configuration.authorization_serialization'); }
}
