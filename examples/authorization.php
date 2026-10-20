<?php
declare(strict_types=1);
namespace SoSecurity\Examples\Authorization;

use SoSecurity\Auth\Account;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Authorization\Resource;
use SoSecurity\Authorization\RolePolicy;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;

// Host owns documents(tenant,id,owner,version,title,body,confidential_note) and its transaction.
// No schema creation, routing, authentication, notifications or implicit commit/rollback on import.
function policy(): RolePolicy
{
    return new RolePolicy([
        'document.read' => ['type' => 'document', 'roles' => ['reader', 'editor', 'manager'], 'fields' => ['id', 'version', 'title']],
        'document.read_private' => ['type' => 'document', 'roles' => ['manager'], 'fields' => ['id', 'version', 'title', 'body', 'confidential_note']],
        'document.update' => ['type' => 'document', 'roles' => ['editor'], 'fields' => ['title', 'body'], 'owner_attribute' => 'owner'],
    ]);
}
function row(\PDO $pdo, string $tenant, string $id): array
{
    foreach ([$tenant, $id] as $value) {
        if ($value === '' || strlen($value) > 64 || !preg_match('//u', $value) || preg_match('/[\x00-\x1f\x7f]/', $value)) { throw new ValidationException('Invalid resource locator.', 'authorization.input'); }
    }
    $query = $pdo->prepare('SELECT tenant,id,owner,version FROM documents WHERE tenant=:tenant AND id=:id');
    if ($query === false || !$query->execute(['tenant' => $tenant, 'id' => $id])) { throw new \RuntimeException('Host document lookup failed.'); }
    $row = $query->fetch(\PDO::FETCH_ASSOC);
    if ($row === false) { throw new SecurityException('Authorization denied.', 'authorization.denied'); }
    return $row;
}
function resource(array $row): Resource
{
    $version = (string) $row['version'];
    if (!preg_match('/\A[1-9][0-9]{0,8}\z/D', $version)) { throw new ConfigurationException('Invalid host resource version.', 'authorization.resource'); }
    return new Resource($row['tenant'], 'document', $row['id'], $version, ['owner' => $row['owner']]);
}
function read(\PDO $pdo, Authorizer $authorizer, ?Account $actor, string $tenant, string $id,
    array $fields = ['id', 'version', 'title'], bool $private = false): array
{
    $row = row($pdo, $tenant, $id);
    $resource = resource($row); $action = $private ? 'document.read_private' : 'document.read';
    $authorizer->assertAllowed($tenant, $actor, $action, $resource, $fields);
    foreach ($fields as $field) {
        if (!in_array($field, ['id', 'version', 'title', 'body', 'confidential_note'], true)) { throw new ValidationException('Unknown document output field.', 'authorization.input'); }
    }
    if (!$fields) { return []; }
    // Fetch only authorized columns and retain the version predicate; no confidential column is loaded before authorization.
    $query = $pdo->prepare('SELECT ' . implode(',', $fields) . ' FROM documents WHERE tenant=:tenant AND id=:id AND version=:version');
    if ($query === false || !$query->execute(['tenant' => $tenant, 'id' => $id, 'version' => $row['version']])) { throw new \RuntimeException('Host document read failed.'); }
    $projected = $query->fetch(\PDO::FETCH_ASSOC);
    if ($projected === false) { throw new SecurityException('Resource version changed.', 'authorization.conflict'); }
    return $authorizer->project($tenant, $actor, $action, $resource, $projected, $fields);
}

/** All targets/fields authorize before the first write; a conflict MUST make the host roll back its transaction. */
function update(\PDO $pdo, Authorizer $authorizer, ?Account $actor, string $tenant, array $operations): int
{
    if (!$pdo->inTransaction()) { throw new ConfigurationException('Host must own the batch transaction.', 'authorization.transaction'); }
    if (!$operations || count($operations) > 20 || array_values($operations) !== $operations) { throw new ValidationException('Expected 1-20 document operations.', 'authorization.input'); }
    $rows = []; $resources = []; $allFields = []; $ids = [];
    foreach ($operations as $operation) {
        if (!is_array($operation) || count($operation) !== 3 || !isset($operation['id'], $operation['version'], $operation['changes'])
            || !is_string($operation['id']) || !is_int($operation['version']) || $operation['version'] < 1 || $operation['version'] >= 999999999
            || !is_array($operation['changes']) || !$operation['changes'] || count($operation['changes']) > 64 || in_array($operation['id'], $ids, true)) {
            throw new ValidationException('Invalid or duplicate document operation.', 'authorization.input');
        }
        $ids[] = $operation['id']; $row = row($pdo, $tenant, $operation['id']);
        $rows[] = $row; $resources[] = resource($row); $allFields = array_merge($allFields, array_keys($operation['changes']));
    }
    $allFields = array_values(array_unique($allFields));
    $authorizer->assertBatch($tenant, $actor, 'document.update', $resources, $allFields);
    // Payload shape validation cannot be replaced by permissions. Nested values and unknown columns never reach SQL.
    foreach ($operations as $index => $operation) {
        if ((string) $operation['version'] !== (string) $rows[$index]['version']) { throw new SecurityException('Resource version changed.', 'authorization.conflict'); }
        foreach ($operation['changes'] as $field => $value) {
            if (!in_array($field, ['title', 'body'], true) || !is_string($value) || $value === '' || strlen($value) > ($field === 'title' ? 200 : 4000) || !preg_match('//u', $value) || strpos($value, "\0") !== false) {
                throw new ValidationException('Invalid document payload.', 'authorization.input');
            }
        }
    }
    foreach ($operations as $index => $operation) {
        $row = $rows[$index]; $assignments = []; $parameters = ['tenant' => $tenant, 'id' => $row['id'], 'version' => $operation['version']];
        foreach (['title', 'body'] as $field) {
            if (array_key_exists($field, $operation['changes'])) { $assignments[] = $field . '=:' . $field; $parameters[$field] = $operation['changes'][$field]; }
        }
        $query = $pdo->prepare('UPDATE documents SET ' . implode(',', $assignments) . ',version=version+1 WHERE tenant=:tenant AND id=:id AND version=:version');
        if ($query === false || !$query->execute($parameters)) { throw new \RuntimeException('Host document update failed.'); }
        if ($query->rowCount() !== 1) { throw new SecurityException('Resource version changed.', 'authorization.conflict'); }
    }
    return count($operations);
}
