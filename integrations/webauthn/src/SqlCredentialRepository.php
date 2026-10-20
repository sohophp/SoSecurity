<?php
declare(strict_types=1);

namespace SoSecurity\WebAuthn;

use InvalidArgumentException;
use PDO;
use RuntimeException;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

/** Host-managed schema; only a local test database is used by this package's tests. */
final class SqlCredentialRepository
{
    private $pdo;
    private $driver;
    private $scope;
    private $scopeLabel;
    private $serializer;

    public function __construct(PDO $pdo, string $scope)
    {
        if ($scope === '' || strlen($scope) > 128 || preg_match('/[\x00-\x1f\x7f]/', $scope)) {
            throw new InvalidArgumentException('Invalid credential scope');
        }
        $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        if (($driver !== 'sqlite' && $driver !== 'mysql') ||
            $pdo->getAttribute(PDO::ATTR_ERRMODE) !== PDO::ERRMODE_EXCEPTION) {
            throw new InvalidArgumentException('SQLite or MySQL PDO in exception mode is required');
        }
        $this->pdo = $pdo;
        $this->driver = $driver;
        $this->scopeLabel = $scope;
        $this->scope = hash('sha256', $scope);
        $support = AttestationStatementSupportManager::create();
        $support->add(NoneAttestationStatementSupport::create());
        $this->serializer = (new WebauthnSerializerFactory($support))->create();
    }

    public function scope(): string { return $this->scopeLabel; }

    public function generation(string $userHandle): int
    {
        $this->identity('placeholder', $userHandle);
        $row = $this->one('SELECT ' . $this->boundedInteger('generation') . ' AS generation FROM sosecurity_webauthn_user '
            . 'WHERE scope_hash=:scope AND user_key=:user',
            ['scope' => $this->scope, 'user' => $this->userKey($userHandle)]);
        return $row === null ? 0 : $this->validGeneration($row['generation'] ?? null);
    }

    /** Insert a verified credential. Duplicate IDs, including other users' IDs, are rejected. */
    public function register(CredentialRecord $record, int $now, int $expectedGeneration): void
    {
        if ($expectedGeneration < 0) {
            throw new InvalidArgumentException('Invalid WebAuthn account generation');
        }
        $this->identity($record->publicKeyCredentialId, $record->userHandle);
        $json = $this->encode($record);
        $user = $this->userKey($record->userHandle);
        $credential = $this->credentialKey($record->publicKeyCredentialId);
        $this->transaction(function () use ($json, $user, $credential, $now, $expectedGeneration): void {
            $this->ensureUser($user);
            $state = $this->lockedState($user);
            $count = $state['count'];
            if ($state['generation'] !== $expectedGeneration) {
                throw new RuntimeException('WebAuthn registration generation changed');
            }
            if ($count >= 32) { throw new RuntimeException('WebAuthn device capacity exceeded'); }
            $this->execute('INSERT INTO sosecurity_webauthn_credential '
                . '(scope_hash,credential_key,user_key,record_json,revision,created_at,updated_at,revoked_at) '
                . 'VALUES (:scope,:credential,:user,:record,1,:created,:updated,NULL)',
                ['scope' => $this->scope, 'credential' => $credential, 'user' => $user,
                    'record' => $json, 'created' => $now, 'updated' => $now]);
            $this->execute('UPDATE sosecurity_webauthn_user SET active_count=active_count+1 '
                . 'WHERE scope_hash=:scope AND user_key=:user', ['scope' => $this->scope, 'user' => $user]);
        });
    }

    public function find(string $credentialId, string $userHandle): ?StoredCredential
    {
        $this->identity($credentialId, $userHandle);
        $select = $this->boundedSelect() . ' WHERE scope_hash=:scope AND credential_key=:credential '
            . 'AND user_key=:user AND revoked_at IS NULL';
        $row = $this->one($select, ['scope' => $this->scope,
            'credential' => $this->credentialKey($credentialId), 'user' => $this->userKey($userHandle)]);
        return $row === null ? null : $this->decode($row, $credentialId, $userHandle);
    }

    /** @return StoredCredential[] */
    public function forUser(string $userHandle): array
    {
        $this->identity('placeholder', $userHandle);
        $sql = $this->boundedSelect() . ' WHERE scope_hash=:scope AND user_key=:user '
            . 'AND revoked_at IS NULL ORDER BY credential_key LIMIT 33';
        $statement = $this->query($sql, ['scope' => $this->scope, 'user' => $this->userKey($userHandle)]);
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);
        if (count($rows) > 32) { throw new RuntimeException('WebAuthn device capacity exceeded'); }
        $result = [];
        foreach ($rows as $row) { $result[] = $this->decode($row, null, $userHandle); }
        return $result;
    }

    /** Persist a validated assertion's counter and backup state only if its snapshot is current. */
    public function commitAssertion(StoredCredential $before, CredentialRecord $after, int $now): bool
    {
        $original = $before->record();
        if ($original->publicKeyCredentialId !== $after->publicKeyCredentialId ||
            $original->userHandle !== $after->userHandle || $after->counter < $original->counter) {
            throw new InvalidArgumentException('Assertion cannot change credential identity or regress counter');
        }
        $json = $this->encode($after);
        $statement = $this->execute('UPDATE sosecurity_webauthn_credential SET record_json=:record, '
            . 'revision=revision+1, updated_at=:now WHERE scope_hash=:scope AND credential_key=:credential '
            . 'AND user_key=:user AND revision=:revision AND revoked_at IS NULL',
            ['record' => $json, 'now' => $now, 'scope' => $this->scope,
                'credential' => $this->credentialKey($original->publicKeyCredentialId),
                'user' => $this->userKey($original->userHandle), 'revision' => $before->revision()]);
        return $statement->rowCount() === 1;
    }

    /** Low-level revocation; caller must enforce recent authentication or recovery authority. */
    public function revoke(StoredCredential $before, int $now): bool
    {
        return $this->revokeWithMinimum($before, $now, 0);
    }

    /** Keep one active authenticator; checked under the per-user SQL lock. */
    public function revokeKeepingOne(StoredCredential $before, int $now): bool
    {
        return $this->revokeWithMinimum($before, $now, 1);
    }

    /** Low-level recovery mutation. Host MUST require independent strong approval and invalidate sessions. */
    public function revokeAllForRecovery(string $userHandle, int $now): int
    {
        $this->identity('placeholder', $userHandle);
        $user = $this->userKey($userHandle);
        return $this->transaction(function () use ($user, $now): int {
            $this->ensureUser($user);
            $this->lockSqliteUser($user);
            $state = $this->lockedState($user);
            if ($state['generation'] >= PHP_INT_MAX - 1) {
                throw new RuntimeException('WebAuthn account generation exhausted');
            }
            $changed = $this->execute('UPDATE sosecurity_webauthn_credential SET revoked_at=:revoked, '
                . 'revision=revision+1,updated_at=:updated WHERE scope_hash=:scope AND user_key=:user '
                . 'AND revoked_at IS NULL',
                ['revoked' => $now, 'updated' => $now, 'scope' => $this->scope, 'user' => $user])->rowCount();
            if ($changed !== $state['count']) { throw new RuntimeException('WebAuthn recovery device count mismatch'); }
            $this->execute('UPDATE sosecurity_webauthn_user SET active_count=0,generation=generation+1 '
                . 'WHERE scope_hash=:scope AND user_key=:user', ['scope' => $this->scope, 'user' => $user]);
            return $state['generation'] + 1;
        });
    }

    private function revokeWithMinimum(StoredCredential $before, int $now, int $minimum): bool
    {
        $record = $before->record();
        $this->identity($record->publicKeyCredentialId, $record->userHandle);
        $user = $this->userKey($record->userHandle);
        return $this->transaction(function () use ($before, $record, $user, $now, $minimum): bool {
            $this->lockSqliteUser($user);
            $state = $this->lockedState($user);
            $count = $state['count'];
            if ($state['generation'] >= PHP_INT_MAX - 1) {
                throw new RuntimeException('WebAuthn account generation exhausted');
            }
            if ($count <= $minimum) { return false; }
            $changed = $this->execute('UPDATE sosecurity_webauthn_credential SET revoked_at=:revoked, '
                . 'revision=revision+1, updated_at=:updated WHERE scope_hash=:scope AND credential_key=:credential '
                . 'AND user_key=:user AND revision=:revision AND revoked_at IS NULL',
                ['revoked' => $now, 'updated' => $now, 'scope' => $this->scope,
                    'credential' => $this->credentialKey($record->publicKeyCredentialId),
                    'user' => $user, 'revision' => $before->revision()])->rowCount();
            if ($changed !== 1) { return false; }
            $this->execute('UPDATE sosecurity_webauthn_user SET active_count=active_count-1,generation=generation+1 '
                . 'WHERE scope_hash=:scope AND user_key=:user', ['scope' => $this->scope, 'user' => $user]);
            return true;
        });
    }

    private function boundedSelect(): string
    {
        $length = $this->driver === 'mysql' ? 'OCTET_LENGTH(record_json)' : 'length(CAST(record_json AS BLOB))';
        $body = $this->driver === 'mysql'
            ? 'IF(' . $length . '<=32768,record_json,NULL)'
            : 'CASE WHEN ' . $length . '<=32768 THEN record_json ELSE NULL END';
        $credentialKey = $this->driver === 'mysql' ? 'credential_key' :
            "CASE WHEN typeof(credential_key)='text' AND length(CAST(credential_key AS BLOB))=64 "
                . 'THEN credential_key ELSE NULL END';
        return 'SELECT ' . $credentialKey . ' AS credential_key,user_key,'
            . $this->boundedInteger('revision') . ' AS revision,' . $length . ' AS record_bytes,'
            . $body . ' AS record_json FROM sosecurity_webauthn_credential';
    }

    private function boundedInteger(string $column): string
    {
        return $this->driver === 'mysql' ? $column
            : "CASE WHEN typeof($column)='integer' THEN $column ELSE NULL END";
    }

    private function decode(array $row, ?string $credentialId, string $userHandle): StoredCredential
    {
        $bytes = $row['record_bytes'] ?? null;
        $json = $row['record_json'] ?? null;
        $revision = $row['revision'] ?? null;
        if (!is_numeric($bytes) || (int) $bytes < 1 || (int) $bytes > 32768 ||
            !is_string($json) || strlen($json) !== (int) $bytes ||
            !is_numeric($revision) || (int) $revision < 1 ||
            !is_string($row['credential_key'] ?? null) || !is_string($row['user_key'] ?? null)) {
            throw new RuntimeException('Corrupt or oversized WebAuthn credential');
        }
        $record = $this->serializer->deserialize($json, CredentialRecord::class, 'json');
        if (!$record instanceof CredentialRecord ||
            ($credentialId !== null && !hash_equals($credentialId, $record->publicKeyCredentialId)) ||
            !hash_equals($userHandle, $record->userHandle) ||
            !hash_equals($row['credential_key'], $this->credentialKey($record->publicKeyCredentialId)) ||
            !hash_equals($row['user_key'], $this->userKey($record->userHandle))) {
            throw new RuntimeException('WebAuthn credential identity mismatch');
        }
        return new StoredCredential($record, (int) $revision);
    }

    private function encode(CredentialRecord $record): string
    {
        $this->identity($record->publicKeyCredentialId, $record->userHandle);
        $json = $this->serializer->serialize($record, 'json');
        if (strlen($json) > 32768) { throw new InvalidArgumentException('WebAuthn credential exceeds storage budget'); }
        return $json;
    }

    private function identity(string $credentialId, string $userHandle): void
    {
        if ($credentialId === '' || strlen($credentialId) > 1024 ||
            $userHandle === '' || strlen($userHandle) > 256) {
            throw new InvalidArgumentException('Invalid WebAuthn credential identity');
        }
    }

    private function userKey(string $handle): string { return hash('sha256', $handle); }
    private function credentialKey(string $id): string { return hash('sha256', $id); }

    private function ensureUser(string $key): void
    {
        $sql = $this->driver === 'mysql'
            ? 'INSERT INTO sosecurity_webauthn_user (scope_hash,user_key,active_count) VALUES (:scope,:user,0) '
                . 'ON DUPLICATE KEY UPDATE user_key=user_key'
            : 'INSERT OR IGNORE INTO sosecurity_webauthn_user (scope_hash,user_key,active_count) VALUES (:scope,:user,0)';
        $this->execute($sql, ['scope' => $this->scope, 'user' => $key]);
    }

    private function lockSqliteUser(string $key): void
    {
        if ($this->driver === 'sqlite') {
            $this->execute('UPDATE sosecurity_webauthn_user SET active_count=active_count '
                . 'WHERE scope_hash=:scope AND user_key=:user',
                ['scope' => $this->scope, 'user' => $key]);
        }
    }

    /** @return array{count:int,generation:int} */
    private function lockedState(string $key): array
    {
        $sql = 'SELECT ' . $this->boundedInteger('active_count') . ' AS active_count,'
            . $this->boundedInteger('generation') . ' AS generation '
            . 'FROM sosecurity_webauthn_user WHERE scope_hash=:scope AND user_key=:user'
            . ($this->driver === 'mysql' ? ' FOR UPDATE' : '');
        $row = $this->one($sql, ['scope' => $this->scope, 'user' => $key]);
        if ($row === null || !is_numeric($row['active_count']) ||
            (int) $row['active_count'] < 0 || (int) $row['active_count'] > 32) {
            throw new RuntimeException('Corrupt WebAuthn device count');
        }
        return ['count' => (int) $row['active_count'],
            'generation' => $this->validGeneration($row['generation'] ?? null)];
    }

    private function validGeneration($value): int
    {
        if ((!is_int($value) && (!is_string($value) || !ctype_digit($value))) ||
            (int) $value < 0 || (string) (int) $value !== (string) $value) {
            throw new RuntimeException('Corrupt WebAuthn account generation');
        }
        return (int) $value;
    }

    private function transaction(callable $operation)
    {
        if ($this->pdo->inTransaction()) { throw new RuntimeException('WebAuthn repository requires its own transaction'); }
        $this->pdo->beginTransaction();
        try {
            $result = $operation();
            $this->pdo->commit();
            return $result;
        } catch (\Throwable $e) {
            $this->rollbackIfActive();
            throw $e;
        }
    }

    private function rollbackIfActive(): void
    {
        if ($this->pdo->inTransaction()) { $this->pdo->rollBack(); }
    }

    private function query(string $sql, array $params): \PDOStatement
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
        return $statement;
    }

    private function execute(string $sql, array $params): \PDOStatement { return $this->query($sql, $params); }

    private function one(string $sql, array $params): ?array
    {
        $row = $this->query($sql, $params)->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : $row;
    }
}
