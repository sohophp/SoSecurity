<?php
declare(strict_types=1);
namespace SoSecurity\Authorization;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\IdentityProvider;
use SoSecurity\Audit\AuditLogger;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Support\Guard;

/** Each call requires an already authenticated host actor; lookup alone never proves authentication. */
final class Authorizer
{
    private $identities;
    private $policy;
    private $audit;
    public function __construct(IdentityProvider $identities, ?PolicyProvider $policy = null, ?AuditLogger $audit = null)
    {
        $this->identities = $identities; $this->policy = $policy; $this->audit = $audit;
    }
    public function decide(string $scope, ?Account $actor, string $action, Resource $resource, array $fields = []): Decision
    {
        return $this->decideBatch($scope, $actor, $action, [$resource], $fields);
    }
    public function decideBatch(string $scope, ?Account $actor, string $action, array $resources, array $fields = []): Decision
    {
        Guard::label($scope); Shape::name($action); $fields = Shape::fields($fields);
        if (!$resources || count($resources) > 100 || array_values($resources) !== $resources) { throw new ValidationException('Batch requires 1-100 resource snapshots.', 'authorization.batch'); }
        $seen = [];
        foreach ($resources as $resource) {
            if (!$resource instanceof Resource) { throw new ValidationException('Expected resource snapshots.', 'authorization.batch'); }
            $key = json_encode([$resource->scope(), $resource->type(), $resource->id()]);
            if (isset($seen[$key])) { throw new ValidationException('Duplicate batch resource.', 'authorization.batch'); } $seen[$key] = true;
        }
        $decision = $this->evaluate($scope, $actor, $action, $resources, $fields);
        if ($this->audit !== null) {
            try { $this->audit->record($decision->allowed() ? 'authorization.allowed' : 'authorization.denied', $scope, $actor === null ? null : $actor->subject(), ['allowed' => $decision->allowed()]); }
            catch (\Throwable $e) { throw new DependencyException('Authorization audit unavailable.', 'authorization.audit_unavailable'); }
        }
        return $decision;
    }
    private function evaluate(string $scope, ?Account $actor, string $action, array $resources, array $fields): Decision
    {
        if ($actor === null || !$actor->enabled() || $actor->scope() !== $scope) { return Decision::deny('authorization.identity'); }
        foreach ($resources as $resource) { if ($resource->scope() !== $scope) { return Decision::deny('authorization.scope'); } }
        if ($this->policy === null) { return Decision::deny('authorization.no_policy'); }
        try {
            $current = $this->current($scope, $actor);
            if ($current === null) { return Decision::deny('authorization.identity_changed'); }
            $allowedFields = null;
            foreach ($resources as $resource) {
                $decision = $this->policy->decide($current, $action, $resource, $fields);
                if ($decision === null) { return Decision::deny('authorization.no_policy'); }
                if (!$decision->allowed()) { return $decision; }
                if (array_diff($fields, $decision->fields())) { return Decision::deny('authorization.fields_denied'); }
                $allowedFields = $allowedFields === null ? $decision->fields() : array_values(array_intersect($allowedFields, $decision->fields()));
            }
            if ($this->current($scope, $current) === null) { return Decision::deny('authorization.identity_changed'); }
            return Decision::allow($allowedFields ?? []);
        } catch (\Throwable $e) { throw new DependencyException('Authorization authority unavailable.', 'authorization.unavailable'); }
    }
    private function current(string $scope, Account $expected): ?Account
    {
        $current = $this->identities->find($scope, $expected->subject());
        if ($current === null || !$current->enabled()) { return null; }
        if ($current->scope() !== $scope || $current->subject() !== $expected->subject()) { throw new ConfigurationException('Identity source returned a different actor.', 'authorization.identity_contract'); }
        return hash_equals($expected->fingerprint(), $current->fingerprint()) ? $current : null;
    }
    public function assertAllowed(string $scope, ?Account $actor, string $action, Resource $resource, array $fields = []): void
    {
        $this->enforce($this->decide($scope, $actor, $action, $resource, $fields));
    }
    public function assertBatch(string $scope, ?Account $actor, string $action, array $resources, array $fields = []): void
    {
        $this->enforce($this->decideBatch($scope, $actor, $action, $resources, $fields));
    }
    public function project(string $scope, ?Account $actor, string $action, Resource $resource, array $row, array $fields): array
    {
        $this->assertAllowed($scope, $actor, $action, $resource, $fields); $out = [];
        foreach ($fields as $field) {
            if (!array_key_exists($field, $row)) { throw new ConfigurationException('Requested projection field is absent from the server row.', 'authorization.projection'); }
            $out[$field] = $row[$field];
        }
        return $out;
    }
    private function enforce(Decision $decision): void
    {
        if (!$decision->allowed()) { throw new SecurityException('Authorization denied.', 'authorization.denied'); }
    }
    public function __debugInfo(): array { return ['authorization' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Rebuild authorization from trusted services.', 'configuration.authorization_serialization'); }
}
