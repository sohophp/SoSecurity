<?php
declare(strict_types=1);
namespace SoSecurity\Storage;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Explicit InnoDB schema; owns only transactions it starts, and never silently retries uncertain commits. */
final class MySqlStore implements AtomicStore
{
    private $pdo;
    private $namespace;
    private $clock;
    private $lockWait;
    private $failed = false;

    public function __construct(\PDO $pdo, string $namespace, ?Clock $clock = null, int $lockWaitSeconds = 1)
    {
        Guard::label($namespace);
        if ($lockWaitSeconds < 1 || $lockWaitSeconds > 30) { throw new ConfigurationException('MySQL lock wait must be 1-30 seconds.'); }
        if ($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) !== 'mysql') { throw new ConfigurationException('MySqlStore requires PDO MySQL.'); }
        $this->pdo = $pdo; $this->namespace = hash('sha256', $namespace);
        $this->clock = $clock ?? new SystemClock(); $this->lockWait = $lockWaitSeconds;
        $this->verifySchema();
    }
    public static function schema(): string
    {
        $sql = file_get_contents(dirname(__DIR__, 2) . '/resources/sql/mysql.sql');
        if ($sql === false) { throw new StorageException('Schema artifact is unavailable.', 'storage.schema'); }
        return $sql;
    }
    /** Explicit deployment action only. Refuses host transactions and never alters an existing table. */
    public static function install(\PDO $pdo): void
    {
        if ($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) !== 'mysql' || $pdo->inTransaction()) {
            throw new ConfigurationException('Install MySQL schema outside a host transaction.', 'configuration.transaction');
        }
        try {
            if ($pdo->exec(self::schema()) === false) { throw new StorageException('Cannot install schema.', 'storage.schema'); }
        } catch (\PDOException $e) { throw new StorageException('Cannot install schema.', 'storage.schema', $e); }
        new self($pdo, 'schema-verification');
    }
    public function transact(string $key, callable $callback)
    {
        Guard::label($key);
        $key = hash('sha256', $key);
        return $this->owned(function () use ($key, $callback) {
            // A unique placeholder locks both new and existing keys, including concurrent missing-key inserts.
            $this->statement('INSERT INTO sosecurity_state (namespace_hash,state_key,payload,expires_at) VALUES (:namespace,:key,NULL,0) ON DUPLICATE KEY UPDATE state_key=:copy_key',
                ['namespace' => $this->namespace, 'key' => $key, 'copy_key' => $key]);
            $row = $this->statement('SELECT IF(OCTET_LENGTH(payload)<=65536,payload,NULL) AS payload,OCTET_LENGTH(payload) AS payload_bytes,expires_at FROM sosecurity_state WHERE namespace_hash=:namespace AND state_key=:key FOR UPDATE',
                ['namespace' => $this->namespace, 'key' => $key])->fetch(\PDO::FETCH_ASSOC);
            if (!is_array($row) || (int) $row['payload_bytes'] > 65536) { throw new StorageException('Locked state is unavailable or oversized.', 'storage.corrupt'); }
            $value = $row['payload'] === null ? null : Codec::decode($row['payload'], $this->clock->now());
            if ($row['payload'] !== null) {
                $envelope = json_decode($row['payload'], true, 32);
                if ((string) $row['expires_at'] !== (string) $envelope['expires']) {
                    throw new StorageException('Expiry metadata and payload disagree.', 'storage.corrupt');
                }
            }
            $change = $callback($value);
            if (!$change instanceof Change) { throw new StorageException('Callback must return Change.', 'storage.contract'); }
            if ($change->value() === null) {
                // Logical deletion retains a short-lived tombstone, avoiding duplicate-insert gap-lock races.
                $this->statement('UPDATE sosecurity_state SET payload=NULL,expires_at=:expires WHERE namespace_hash=:namespace AND state_key=:key',
                    ['expires' => $this->clock->now() + 60, 'namespace' => $this->namespace, 'key' => $key]);
            } else {
                $this->statement('UPDATE sosecurity_state SET payload=:payload,expires_at=:expires WHERE namespace_hash=:namespace AND state_key=:key',
                    ['payload' => Codec::encode($change), 'expires' => $change->expiresAt(), 'namespace' => $this->namespace, 'key' => $key]);
            }
            return $change->result();
        });
    }
    public function prune(int $limit = 1000): int
    {
        if ($limit < 1 || $limit > 10000) { throw new ConfigurationException('Prune batch must be 1-10000.'); }
        return $this->owned(function () use ($limit) {
            $rows = $this->statement('SELECT state_key,expires_at FROM sosecurity_state WHERE namespace_hash=:namespace AND expires_at>0 AND expires_at<=:now ORDER BY expires_at,state_key LIMIT ' . $limit . ' FOR UPDATE',
                ['namespace' => $this->namespace, 'now' => $this->clock->now()])->fetchAll(\PDO::FETCH_ASSOC);
            $removed = 0;
            foreach ($rows as $row) {
                $record = $this->statement('SELECT IF(OCTET_LENGTH(payload)<=65536,payload,NULL) AS payload,OCTET_LENGTH(payload) AS payload_bytes FROM sosecurity_state WHERE namespace_hash=:namespace AND state_key=:key',
                    ['namespace' => $this->namespace, 'key' => $row['state_key']])->fetch(\PDO::FETCH_ASSOC);
                if (!is_array($record) || (int) $record['payload_bytes'] > 65536) { throw new StorageException('Invalid prune candidate.', 'storage.corrupt'); }
                $payload = $record['payload'];
                if ($payload !== null) {
                    if (!is_string($payload)) { throw new StorageException('Invalid prune candidate.', 'storage.corrupt'); }
                    $value = Codec::decode($payload, $this->clock->now());
                    $envelope = json_decode($payload, true, 32);
                    if ($value !== null || (string) $row['expires_at'] !== (string) $envelope['expires']) {
                        throw new StorageException('Prune metadata and payload disagree.', 'storage.corrupt');
                    }
                }
                $removed += $this->statement('DELETE FROM sosecurity_state WHERE namespace_hash=:namespace AND state_key=:key',
                    ['namespace' => $this->namespace, 'key' => $row['state_key']])->rowCount();
            }
            return $removed;
        });
    }
    private function owned(callable $operation)
    {
        if ($this->failed) { throw new StorageException('Reconnect and rebuild after failed database cleanup.', 'storage.connection'); }
        if ($this->pdo->inTransaction()) { throw new ConfigurationException('Security storage cannot own an existing host transaction.', 'configuration.transaction'); }
        $owned = false;
        $original = null;
        try {
            $original = (int) $this->statement('SELECT @@SESSION.innodb_lock_wait_timeout')->fetchColumn();
            $this->execute('SET SESSION innodb_lock_wait_timeout = ' . $this->lockWait);
            if (!$this->pdo->beginTransaction()) { throw new StorageException('Cannot start database transaction.', 'storage.transaction'); }
            $owned = true;
            $result = $operation();
            if (!$this->pdo->commit()) { throw new StorageException('Database commit was not confirmed.', 'storage.commit'); }
            $owned = false;
            return $result;
        } catch (\PDOException $e) {
            throw new StorageException('Database security operation failed.', 'storage.database', $e);
        } finally {
            if ($owned && $this->pdo->inTransaction()) {
                try { if (!$this->pdo->rollBack()) { $this->failed = true; } }
                catch (\PDOException $ignored) { $this->failed = true; }
            }
            if ($original !== null && !$this->failed) {
                try { $this->execute('SET SESSION innodb_lock_wait_timeout = ' . $original); }
                catch (\Throwable $ignored) { $this->failed = true; }
            }
            if ($this->failed) { throw new StorageException('Database cleanup could not restore the connection; rebuild it.', 'storage.cleanup'); }
        }
    }
    private function verifySchema(): void
    {
        try {
            $engine = $this->statement("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_state'")->fetchColumn();
            if (!is_string($engine) || strtolower($engine) !== 'innodb') {
                throw new ConfigurationException('Install the dedicated InnoDB schema before use.', 'configuration.schema');
            }
            $columns = $this->statement("SELECT COLUMN_NAME,DATA_TYPE,COLUMN_TYPE,IS_NULLABLE,CHARACTER_MAXIMUM_LENGTH,COLUMN_DEFAULT FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_state'")->fetchAll(\PDO::FETCH_ASSOC);
            $byName = array_column($columns, null, 'COLUMN_NAME');
            if (count($byName) !== 4 || !isset($byName['namespace_hash'], $byName['state_key'], $byName['payload'], $byName['expires_at'])
                || $byName['namespace_hash']['DATA_TYPE'] !== 'char' || (int) $byName['namespace_hash']['CHARACTER_MAXIMUM_LENGTH'] !== 64
                || $byName['state_key']['DATA_TYPE'] !== 'char' || (int) $byName['state_key']['CHARACTER_MAXIMUM_LENGTH'] !== 64
                || $byName['payload']['DATA_TYPE'] !== 'mediumtext' || $byName['payload']['IS_NULLABLE'] !== 'YES'
                || $byName['expires_at']['DATA_TYPE'] !== 'bigint' || strpos($byName['expires_at']['COLUMN_TYPE'], 'unsigned') === false
                || $byName['expires_at']['IS_NULLABLE'] !== 'NO' || (string) $byName['expires_at']['COLUMN_DEFAULT'] !== '0') {
                throw new ConfigurationException('Existing security table schema is incompatible.', 'configuration.schema');
            }
            $primary = $this->statement("SELECT COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_state' AND INDEX_NAME='PRIMARY' ORDER BY SEQ_IN_INDEX")->fetchAll(\PDO::FETCH_COLUMN);
            if ($primary !== ['namespace_hash', 'state_key']) { throw new ConfigurationException('Security table needs the specified unique primary key.', 'configuration.schema'); }
            $expiry = $this->statement("SELECT COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_state' AND INDEX_NAME='sosecurity_expiry' ORDER BY SEQ_IN_INDEX")->fetchAll(\PDO::FETCH_COLUMN);
            if ($expiry !== ['namespace_hash', 'expires_at']) { throw new ConfigurationException('Security table needs its bounded cleanup index.', 'configuration.schema'); }
        } catch (\PDOException $e) { throw new StorageException('Cannot verify database schema.', 'storage.schema', $e); }
    }
    private function execute(string $sql): void
    {
        if ($this->pdo->exec($sql) === false) { throw new StorageException('Database statement failed.', 'storage.database'); }
    }
    private function statement(string $sql, array $parameters = []): \PDOStatement
    {
        $statement = $this->pdo->prepare($sql);
        if ($statement === false || !$statement->execute($parameters)) { throw new StorageException('Database statement failed.', 'storage.database'); }
        return $statement;
    }
}
