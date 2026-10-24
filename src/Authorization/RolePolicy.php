<?php
declare(strict_types=1);
namespace SoSecurity\Authorization;
use SoSecurity\Auth\Account;
use SoSecurity\Exception\ConfigurationException;

/** Exact action/type rules with role, optional ownership and scalar attribute constraints; no global admin bypass. */
final class RolePolicy implements PolicyProvider
{
    private $rules = [];
    public function __construct(array $rules)
    {
        if (count($rules) > 128) { throw new ConfigurationException('Too many role rules.', 'configuration.authorization'); }
        foreach ($rules as $action => $rule) {
            if (!is_string($action) || !is_array($rule)) { throw new ConfigurationException('Invalid role rule.', 'configuration.authorization'); }
            Shape::name($action);
            if (count($rule) > 5 || array_diff(array_keys($rule), ['type', 'roles', 'fields', 'owner_attribute', 'match']) || !isset($rule['type'], $rule['roles'], $rule['fields'])
                || !is_string($rule['type']) || !is_array($rule['roles']) || !$rule['roles'] || count($rule['roles']) > 32 || !is_array($rule['fields'])) {
                throw new ConfigurationException('Explicit type, roles and fields are required.', 'configuration.authorization');
            }
            Shape::name($rule['type']); $roles = [];
            foreach ($rule['roles'] as $role) {
                if (!is_string($role) || !preg_match('/\A[A-Za-z][A-Za-z0-9_:.-]{0,63}\z/D', $role)) { throw new ConfigurationException('Invalid policy role.', 'configuration.authorization'); }
                $roles[] = $role;
            }
            $owner = $rule['owner_attribute'] ?? null;
            if (array_key_exists('owner_attribute', $rule) && (!is_string($owner) || !preg_match('/\A[A-Za-z_][A-Za-z0-9_]{0,63}\z/D', $owner))) { throw new ConfigurationException('Invalid owner attribute.', 'configuration.authorization'); }
            if (array_key_exists('match', $rule) && !is_array($rule['match'])) { throw new ConfigurationException('Invalid attribute constraints.', 'configuration.authorization'); }
            $this->rules[$action] = ['type' => $rule['type'], 'roles' => $roles, 'fields' => Shape::fields($rule['fields']),
                'owner' => $owner, 'match' => Shape::attributes($rule['match'] ?? [])];
        }
    }
    public function decide(Account $actor, string $action, Resource $resource, array $requestedFields = []): ?Decision
    {
        $rule = $this->rules[$action] ?? null;
        if ($rule === null || $rule['type'] !== $resource->type()) { return null; }
        if (!$actor->enabled() || $actor->scope() !== $resource->scope() || !array_intersect($actor->roles(), $rule['roles'])) { return Decision::deny(); }
        $attributes = $resource->attributes();
        if ($rule['owner'] !== null && (!isset($attributes[$rule['owner']]) || !is_string($attributes[$rule['owner']]) || !hash_equals($actor->subject(), $attributes[$rule['owner']]))) { return Decision::deny(); }
        foreach ($rule['match'] as $name => $expected) {
            if (!array_key_exists($name, $attributes) || $attributes[$name] !== $expected) { return Decision::deny(); }
        }
        return Decision::allow($rule['fields']);
    }
    /** Pure exact normalized rule configuration, including object and field restrictions. */
    public function fingerprint():string{return hash('sha256','SoSecurity.Authorization.RolePolicy.1.'.json_encode($this->rules,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));}
    public function __debugInfo(): array { return ['rule_count' => count($this->rules), 'rules' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Rebuild role policy configuration.', 'configuration.authorization_serialization'); }
}
