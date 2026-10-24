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
        // Construction may run inside a caller transaction. Change only its session policy,
        // never its transaction boundary, and restore even when schema verification refuses.
        $metadataTimeout=null;
        try{
            $metadataTimeout=$this->lockTimeout(true);
            $this->execute('SET SESSION lock_wait_timeout = '.min($metadataTimeout,$this->lockWait));
            $this->verifySchema();
        }catch(StorageException $error){
            if($error->reason()==='storage.database'){throw new StorageException('Cannot verify database security schema.','storage.schema');}
            throw $error;
        }finally{
            if($metadataTimeout!==null&&!$this->failed){try{$this->execute('SET SESSION lock_wait_timeout = '.$metadataTimeout);}catch(\Throwable $error){$this->failed=true;}}
            if($this->failed){throw new StorageException('Database constructor cleanup failed; rebuild the connection.','storage.cleanup');}
        }
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
        \SoSecurity\Support\SqlTransactionGuard::assertIdle($pdo,'mysql');
        try {
            if ($pdo->exec(self::schema()) === false) { throw new StorageException('Cannot install schema.', 'storage.schema'); }
        } catch (\PDOException $e) { throw new StorageException('Cannot install schema.', 'storage.schema'); }
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
        $original = null;$metadataTimeout = null;
        try {
            \SoSecurity\Support\SqlTransactionGuard::assertIdle($this->pdo,'mysql');
            $original = $this->lockTimeout(false);
            $metadataTimeout = $this->lockTimeout(true);
            $this->execute('SET SESSION innodb_lock_wait_timeout = ' . $this->lockWait);
            $this->execute('SET SESSION lock_wait_timeout = ' . min($metadataTimeout,$this->lockWait));
            if (!$this->pdo->beginTransaction()) { throw new StorageException('Cannot start database transaction.', 'storage.transaction'); }
            $owned = true;
            // Pin the table before rechecking its full schema; never reuse constructor-time facts.
            $this->statement(\SoSecurity\Support\SqlSchema::tableResolution('sosecurity_state'))->closeCursor();
            $this->verifySchema();
            $result = $operation();
            if (!$this->pdo->commit()) { throw new StorageException('Database commit was not confirmed.', 'storage.commit'); }
            $owned = false;
            return $result;
        } catch (\PDOException $e) {
            throw new StorageException('Database security operation failed.', 'storage.database');
        } finally {
            if ($owned && $this->pdo->inTransaction()) {
                try { if (!$this->pdo->rollBack()) { $this->failed = true; } }
                catch (\PDOException $ignored) { $this->failed = true; }
            }
            if ($metadataTimeout !== null && !$this->failed) {
                try { $this->execute('SET SESSION lock_wait_timeout = ' . $metadataTimeout); }
                catch (\Throwable $ignored) { $this->failed = true; }
            }
            if ($original !== null && !$this->failed) {
                try { $this->execute('SET SESSION innodb_lock_wait_timeout = ' . $original); }
                catch (\Throwable $ignored) { $this->failed = true; }
            }
            if ($this->failed) { throw new StorageException('Database cleanup could not restore the connection; rebuild it.', 'storage.cleanup'); }
        }
    }
    /** Read the complete fixed session value and close its cursor before any SET or BEGIN. */
    private function lockTimeout(bool $metadata):int
    {
        try{$query=$this->pdo->prepare($metadata?'SELECT @@SESSION.lock_wait_timeout':'SELECT @@SESSION.innodb_lock_wait_timeout');}catch(\Throwable $error){throw new StorageException('Database session policy unavailable.','storage.database');}
        if($query===false){throw new StorageException('Database session policy unavailable.','storage.database');}
        $failure=null;
        try{if(!$query->execute()){throw new StorageException('Database session policy unavailable.','storage.database');}$rows=$query->fetchAll(\PDO::FETCH_NUM);}catch(\Throwable $error){$failure=$error;}
        try{$closed=$query->closeCursor();}catch(\Throwable $error){$closed=false;}
        if(!$closed){$this->failed=true;throw new StorageException('Database session cursor cleanup failed.','storage.cleanup');}
        if($failure!==null){throw new StorageException('Database session policy unavailable.','storage.database');}
        if(count($rows)!==1||!is_array($rows[0])||count($rows[0])!==1){throw new StorageException('Invalid database session policy.','storage.corrupt');}
        try{$value=\SoSecurity\Support\SqlSchema::integer(reset($rows[0]));}catch(StorageException $error){throw new StorageException('Invalid database session policy.','storage.corrupt');}
        if($value<1||($metadata&&$value>31536000)){throw new StorageException('Invalid database session policy.','storage.corrupt');}
        return $value;
    }
    private function verifyDependencies(): void
    {
        foreach(\SoSecurity\Support\SqlSchema::foreignKeyChecks('mysql','sosecurity_state') as $check){$q=$this->statement($check['sql'],$check['parameters']);$related=$q->fetchColumn()!==false;$q->closeCursor();if($related){throw new ConfigurationException('Private security tables must not have foreign-key dependencies.','configuration.schema');}}
    }
    /** Empty trigger metadata is trustworthy only with proven current-account visibility. */
    private function verifyTriggers(): void
    {
        $identity=$this->statement('SELECT CASE WHEN OCTET_LENGTH(CURRENT_USER())<=288 THEN CURRENT_USER() ELSE NULL END')->fetchColumn();
        if(!is_string($identity)||!preg_match('/\A([A-Za-z0-9_.-]{1,32})@([A-Za-z0-9_.:%\/-]{1,255})\z/D',$identity,$match)){throw new ConfigurationException('Cannot prove private storage metadata visibility.','configuration.schema');}
        $grantee="'".$match[1]."'@'".$match[2]."'";
        // Keep proof and trigger observation in one statement; table grants may be revoked between queries.
        $visible=$this->statement("SELECT (EXISTS(SELECT 1 FROM information_schema.SCHEMA_PRIVILEGES WHERE BINARY GRANTEE=:schema_grantee AND BINARY TABLE_SCHEMA=BINARY DATABASE() AND PRIVILEGE_TYPE='TRIGGER') OR EXISTS(SELECT 1 FROM information_schema.TABLE_PRIVILEGES WHERE BINARY GRANTEE=:table_grantee AND BINARY TABLE_SCHEMA=BINARY DATABASE() AND BINARY TABLE_NAME='sosecurity_state' AND PRIVILEGE_TYPE='TRIGGER')) AS scoped,EXISTS(SELECT 1 FROM information_schema.USER_PRIVILEGES WHERE BINARY GRANTEE=:global_grantee AND PRIVILEGE_TYPE='TRIGGER') AS unrestricted,EXISTS(SELECT 1 FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE='sosecurity_state') AS has_trigger",['schema_grantee'=>$grantee,'table_grantee'=>$grantee,'global_grantee'=>$grantee])->fetch(\PDO::FETCH_ASSOC);
        if(!is_array($visible)||((string)$visible['scoped']!=='1'&&((string)$visible['unrestricted']!=='1'||(string)$this->statement('SELECT @@GLOBAL.partial_revokes')->fetchColumn()!=='0'))){throw new ConfigurationException('Direct private storage trigger metadata visibility is required.','configuration.schema');}
        if((string)$visible['has_trigger']!=='0'){throw new ConfigurationException('Private security tables must not have triggers.','configuration.schema');}
    }
    private function verifySchema(): void
    {
        try {
            $this->verifyDependencies();
            $this->verifyTriggers();
            $engine = $this->statement("SELECT CASE WHEN OCTET_LENGTH(ENGINE)<=32 THEN ENGINE ELSE NULL END FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_state' LIMIT 1")->fetchColumn();
            if (!is_string($engine) || strtolower($engine) !== 'innodb') {
                throw new ConfigurationException('Install the dedicated InnoDB schema before use.', 'configuration.schema');
            }
            $columns = $this->statement("SELECT COLUMN_NAME,DATA_TYPE,CASE WHEN OCTET_LENGTH(COLUMN_TYPE)<=128 THEN COLUMN_TYPE ELSE NULL END AS COLUMN_TYPE,IS_NULLABLE,CHARACTER_MAXIMUM_LENGTH,CASE WHEN COLUMN_NAME='expires_at' AND OCTET_LENGTH(COLUMN_DEFAULT)<=128 THEN COLUMN_DEFAULT ELSE NULL END AS COLUMN_DEFAULT FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_state' ORDER BY ORDINAL_POSITION LIMIT 5")->fetchAll(\PDO::FETCH_ASSOC);
            $byName = array_column($columns, null, 'COLUMN_NAME');
            if (count($byName) !== 4 || !isset($byName['namespace_hash'], $byName['state_key'], $byName['payload'], $byName['expires_at'])
                || $byName['namespace_hash']['DATA_TYPE'] !== 'char' || (int) $byName['namespace_hash']['CHARACTER_MAXIMUM_LENGTH'] !== 64
                || $byName['state_key']['DATA_TYPE'] !== 'char' || (int) $byName['state_key']['CHARACTER_MAXIMUM_LENGTH'] !== 64
                || $byName['payload']['DATA_TYPE'] !== 'mediumtext' || $byName['payload']['IS_NULLABLE'] !== 'YES'
                || $byName['expires_at']['DATA_TYPE'] !== 'bigint' || !is_string($byName['expires_at']['COLUMN_TYPE']) || strpos($byName['expires_at']['COLUMN_TYPE'], 'unsigned') === false
                || $byName['expires_at']['IS_NULLABLE'] !== 'NO' || (string) $byName['expires_at']['COLUMN_DEFAULT'] !== '0') {
                throw new ConfigurationException('Existing security table schema is incompatible.', 'configuration.schema');
            }
            $this->verifyIndexes();
        } catch (\PDOException $e) { throw new StorageException('Cannot verify database schema.', 'storage.schema'); }
    }
    /** Recheck after deployment changes, under the owned transaction's metadata lock. */
    private function verifyIndexes():void
    {
        $this->statement(\SoSecurity\Support\SqlSchema::tableResolution('sosecurity_state'))->closeCursor();
        // Only the full primary key may arbitrate ON DUPLICATE KEY UPDATE.
        // An extra unique index could redirect a missing-key insert into another record.
        $expected=['primary'=>['namespace_hash','state_key'],'sosecurity_expiry'=>['namespace_hash','expires_at']];$observed=['primary'=>[],'sosecurity_expiry'=>[]];
        $rows=$this->statement("SELECT INDEX_NAME,COLUMN_NAME,SUB_PART,NON_UNIQUE,INDEX_TYPE FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='sosecurity_state' AND (INDEX_NAME IN ('PRIMARY','sosecurity_expiry') OR NON_UNIQUE=0) ORDER BY INDEX_NAME,SEQ_IN_INDEX LIMIT 5")->fetchAll(\PDO::FETCH_ASSOC);
        foreach($rows as $row){
            $name=strtolower($row['INDEX_NAME']);
            if(!isset($expected[$name])||$row['SUB_PART']!==null||(string)$row['NON_UNIQUE']!==($name==='primary'?'0':'1')||$row['INDEX_TYPE']!=='BTREE'){throw new ConfigurationException('Security indexes must preserve complete keys and declared uniqueness.','configuration.schema');}
            $observed[$name][]=$row['COLUMN_NAME'];
        }
        if($observed!==$expected){throw new ConfigurationException('Security table requires its exact private indexes.','configuration.schema');}
    }

    private function execute(string $sql): void
    {
        try { $result=$this->pdo->exec($sql); }
        catch (\Throwable $error) { throw new StorageException('Database statement failed.', 'storage.database'); }
        if ($result === false) { throw new StorageException('Database statement failed.', 'storage.database'); }
    }
    private function statement(string $sql, array $parameters = []): \PDOStatement
    {
        $statement = $this->pdo->prepare($sql);
        if ($statement === false || !$statement->execute($parameters)) { throw new StorageException('Database statement failed.', 'storage.database'); }
        return $statement;
    }
}
