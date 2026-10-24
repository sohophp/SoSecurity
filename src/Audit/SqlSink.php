<?php
declare(strict_types=1);

namespace SoSecurity\Audit;

use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;

/** Bounded independent SQL audit log. Not a tamper-proof archive or a business transaction participant. */
final class SqlSink
{
    private $unit;
    private $clock;
    private $milliseconds;
    private $preparing = false;
    private $site;
    private $policy;
    private $maximum;
    private $retention;
    private $maintenance;
    private $read;

    public function __construct(PDO $connection, string $site, int $maximumRecords = 10000,
        int $retentionSeconds = 86400, ?Clock $clock = null, int $timeoutMilliseconds = 1000,
        ?callable $authorizeMaintenance = null, ?callable $authorizeRead = null)
    {
        Guard::label($site);
        if ($maximumRecords < 1 || $maximumRecords > 100000 || $retentionSeconds < 1 || $retentionSeconds > 31536000) {
            throw new ConfigurationException('Use bounded SQL audit retention and capacity.', 'configuration.audit_sql');
        }
        $this->clock = $clock ?? new SystemClock();
        $this->milliseconds = $timeoutMilliseconds;
        $this->unit = new SqlTransaction($connection, $this->clock, $timeoutMilliseconds);
        $this->site = hash('sha256', 'SoSecurity.AuditSql.Site.1.' . $site);
        $this->policy = hash('sha256', $maximumRecords . ':' . $retentionSeconds);
        $this->maximum = $maximumRecords;
        $this->retention = $retentionSeconds;
        $this->maintenance = static function () use ($authorizeMaintenance): bool {
            return $authorizeMaintenance !== null && $authorizeMaintenance() === true;
        };
        $this->read = static function () use ($authorizeRead): bool {
            return $authorizeRead !== null && $authorizeRead() === true;
        };
    }

    /** Pure exact-source declaration; this grants no permission to append or initialize records. */
    public function stateContext(PDO $connection, string $site, Clock $clock): ?array
    {
        if (strlen($site) > 256 || $connection !== $this->unit->connection() || $clock !== $this->clock
            || !hash_equals($this->site, hash('sha256', 'SoSecurity.AuditSql.Site.1.' . $site))) { return null; }
        return ['fingerprint' => hash('sha256', 'SoSecurity.AuditSql.State.1.' . $this->site . '.' . $this->policy . '.' . $this->milliseconds),
            'maximum_records' => $this->maximum,
            'tables' => [
                'sosecurity_audit_roots' => ['columns' => ['site'=>'digest','policy'=>'digest','next_sequence'=>'int','observed_at'=>'int'], 'primary'=>['site'], 'where'=>[]],
                'sosecurity_audit_records' => ['columns' => ['site'=>'digest','sequence_no'=>'int','recorded_at'=>'int','expires_at'=>'int','record'=>'blob:4096'], 'primary'=>['site','sequence_no'], 'where'=>[]],
            ]];
    }

    /** Explicit trusted bootstrap after installing the driver-specific audit schema. Never called by a log write. */
    public function initialize(): void
    {
        $this->unit->run(function (): void {
            $this->schema();
            $row = $this->root(false);
            if ($row !== null) { return; }
            if ($this->count() !== 0) {
                throw new StorageException('Orphan SQL audit records require operator review.', 'audit.sql_corrupt');
            }
            $inserted = $this->unit->execute('INSERT INTO ' . $this->unit->prefix() . 'sosecurity_audit_roots'
                . ' (site,policy,next_sequence,observed_at) VALUES (:site,:policy,0,:now)',
                ['site' => $this->site, 'policy' => $this->policy, 'now' => $this->unit->now()]);
            if ($inserted !== 1) { throw new StorageException('SQL audit initialization did not insert one root.', 'audit.sql_corrupt'); }
        });
    }

    /** Returns only after the independent database COMMIT has been confirmed. Never retries uncertain effects. */
    public function __invoke(array $record): void
    {
        $this->append(self::encode($record));
    }

    private function append(string $body, ?Deadline $deadline = null, ?array $expected = null, ?int $maximumRows = null): void
    {
        $this->unit->run(function () use ($body, $expected, $maximumRows): void {
            $this->schema();
            $row = $this->root();
            if ($expected !== null && $row !== $expected) {
                throw new StorageException('SQL audit root changed after admission.', 'audit.sql_changed');
            }
            $now = $this->unit->now();
            $this->pruneRows($now, 128);
            if ($maximumRows !== null && $this->total($maximumRows) >= $maximumRows) {
                throw new SecurityException('SQL audit source capacity exhausted.', 'audit.sql_capacity');
            }
            if ($this->count() >= $this->maximum) {
                throw new SecurityException('SQL audit log capacity exhausted.', 'audit.sql_capacity');
            }
            if ($row['next_sequence'] >= PHP_INT_MAX) {
                throw new StorageException('SQL audit sequence exhausted.', 'audit.sql_corrupt');
            }
            $sequence = $row['next_sequence'] + 1;
            $inserted = $this->unit->execute('INSERT INTO ' . $this->unit->prefix() . 'sosecurity_audit_records'
                . ' (site,sequence_no,recorded_at,expires_at,record) VALUES (:site,:sequence,:now,:expires,:record)',
                ['site' => $this->site, 'sequence' => $sequence, 'now' => $now,
                    'expires' => $now + $this->retention, 'record' => $body], ['record']);
            if ($inserted !== 1) { throw new StorageException('SQL audit append did not insert one record.', 'audit.sql_corrupt'); }
            $this->touch($sequence, $now);
        }, null, null, null, $deadline);
    }

    /** Prepare one bounded audit append without effects. Invoke the returned writer once inside the protected boundary. */
    public function prepareState(array $record, int $maximumRows, Deadline $deadline): \Closure
    {
        if ($this->preparing || $maximumRows < $this->maximum || $maximumRows > 1000000
            || !\SoSecurity\Support\SqlStateAccess::isProtected($this->unit->connection())) {
            throw new ConfigurationException('Use the exact protected audit source capacity.', 'configuration.audit_state');
        }
        $budget = new Deadline($this->milliseconds);$budget->restrictTo($deadline);
        // Publish the shorter audit deadline to the caller's pre-effect admission check.
        $deadline->restrictTo($budget);
        $body = self::encode($record);$original = $this->unit;
        $unit = SqlTransaction::forObservation($original->connection(), $this->clock, $this->milliseconds);
        $this->unit = $unit;$this->preparing = true;
        try {
            $observed = $unit->run(function () use ($maximumRows): array {
                $this->schema();$root = $this->root();$at = $this->unit->now();
                $rows = $this->unit->metadataRows('SELECT sequence_no FROM ' . $this->unit->prefix()
                    . 'sosecurity_audit_records WHERE site=:site AND expires_at<=:now ORDER BY expires_at,sequence_no LIMIT 128',
                    ['site'=>$this->site,'now'=>$at]);
                $prunable = count($rows);
                $total = $this->total($maximumRows);
                if ($total > $maximumRows) { throw new StorageException('SQL audit source exceeds its declared capacity.', 'audit.sql_corrupt'); }
                if ($this->count() - $prunable >= $this->maximum || $total - $prunable >= $maximumRows) {
                    throw new SecurityException('SQL audit source capacity exhausted.', 'audit.sql_capacity');
                }
                if ($root['next_sequence'] >= PHP_INT_MAX) { throw new StorageException('SQL audit sequence exhausted.', 'audit.sql_corrupt'); }
                return ['root'=>$root,'at'=>$at];
            }, null, null, null, $budget);
        } finally { $this->unit = $original;$this->preparing = false; }
        $used = false;
        return function () use (&$used, $body, $budget, $observed, $maximumRows): void {
            if ($used || $this->preparing) { throw new ConfigurationException('Use a prepared audit append only once.', 'configuration.audit_state_reuse'); }
            $used = true;$budget->check('audit.sql_timeout');$this->stateTime($observed['at']);
            $this->append($body, $budget, $observed['root'], $maximumRows);
            $this->stateTime($observed['at']);$budget->check('audit.sql_timeout');
        };
    }

    private function stateTime(int $minimum): void
    {
        try { $now = $this->clock->now(); } catch (\Throwable $error) { throw new StorageException('SQL audit clock unavailable.', 'audit.sql_clock'); }
        if ($now < $minimum || $now > PHP_INT_MAX - 31536001) { throw new StorageException('SQL audit clock moved backwards or is invalid.', 'audit.sql_clock'); }
    }

    /** Each bounded aggregate must return exactly one checked integer. */
    private function number(string $sql, array $parameters = []): int
    {
        $rows = $this->unit->metadataRows($sql, $parameters);
        if (count($rows) !== 1 || !isset($rows[0]) || count($rows[0]) !== 1) {
            throw new StorageException('Invalid SQL audit aggregate.', 'audit.sql_corrupt');
        }
        return SqlSchema::integer(reset($rows[0]));
    }

    private function total(int $maximumRows): int
    {
        return $this->number('SELECT COUNT(*) FROM (SELECT site FROM '
            . $this->unit->prefix() . 'sosecurity_audit_records LIMIT ' . ($maximumRows + 1) . ') audit_total');
    }

    /** Bounded explicit maintenance; missing, throwing or revoked host authorization refuses the operation. */
    public function prune(int $limit = 128): int
    {
        if ($limit < 1 || $limit > 1000) {
            throw new ConfigurationException('Use an audit prune batch of 1-1000.', 'configuration.audit_sql');
        }
        $this->authorize();
        return $this->unit->run(function () use ($limit): int {
            $this->schema();
            $row = $this->root();
            $now = $this->unit->now();
            $removed = $this->pruneRows($now, $limit);
            $this->touch($row['next_sequence'], $now);
            return $removed;
        }, null, function (): void { $this->authorize(); });
    }

    /** Oldest retained row after the cursor; explicit read authorization is separate from maintenance. */
    public function records(int $afterSequence = 0, int $limit = 100): array
    {
        $this->authorizeRead();
        if ($afterSequence < 0 || $limit < 1 || $limit > 100) {
            throw new ConfigurationException('Use bounded SQL audit pagination.', 'configuration.audit_sql_query');
        }
        return $this->unit->run(function () use ($afterSequence, $limit): array {
            $this->schema(); $root = $this->root(); $now = $this->unit->now();
            $length = SqlSchema::blobLength($this->unit->driver(), 'record');
            $projection = SqlSchema::boundedProjection($this->unit->driver(),
                ['sequence_no' => 'int', 'recorded_at' => 'int', 'expires_at' => 'int']);
            $rows = $this->unit->metadataRows('SELECT ' . $projection . ',CASE WHEN ' . $length
                . ' BETWEEN 0 AND 4096 THEN record ELSE NULL END AS record FROM '
                . $this->unit->prefix() . 'sosecurity_audit_records WHERE site=:site AND sequence_no>:after'
                . ' AND expires_at>:now ORDER BY sequence_no LIMIT ' . $limit
                . ($this->unit->driver() === 'mysql' && !$this->unit->isObservation() ? ' FOR UPDATE' : ''),
                ['site' => $this->site, 'after' => $afterSequence, 'now' => $now]);
            $records = []; $last = $afterSequence;
            foreach ($rows as $row) {
                $sequence = SqlSchema::integer($row['sequence_no']);
                $at = SqlSchema::integer($row['recorded_at']);
                $expires = SqlSchema::integer($row['expires_at']);
                $body = $row['record'];
                if ($sequence <= $last || $sequence > $root['next_sequence'] || $at > $root['observed_at']
                    || $at > $now || $at > PHP_INT_MAX - $this->retention || $expires !== $at + $this->retention
                    || !is_string($body) || strlen($body) > 4096) { $this->corruptRecord(); }
                $record = json_decode($body, true);
                try { $valid = is_array($record) && self::encode($record) === $body; }
                catch (ConfigurationException $error) { $valid = false; }
                if (!$valid) { $this->corruptRecord(); }
                $records[] = ['sequence' => $sequence, 'recorded_at' => $at, 'expires_at' => $expires, 'record' => $record];
                $last = $sequence;
            }
            return $records;
        }, null, function (): void { $this->authorizeRead(); });
    }

    private function corruptRecord(): void
    {
        throw new StorageException('SQL audit record differs from its bounded protocol.', 'audit.sql_corrupt');
    }

    private function authorizeRead(): void
    {
        try { $allowed = ($this->read)(); }
        catch (\Throwable $error) { $allowed = false; }
        if (!$allowed) { throw new SecurityException('SQL audit read access denied.', 'audit.sql_read_forbidden'); }
    }

    private function authorize(): void
    {
        try { $allowed = ($this->maintenance)(); }
        catch (\Throwable $error) { $allowed = false; }
        if (!$allowed) { throw new SecurityException('SQL audit maintenance denied.', 'audit.sql_forbidden'); }
    }

    private function schema(): void
    {
        SqlSchema::durable($this->unit);
        SqlSchema::table($this->unit, 'sosecurity_audit_roots',
            ['site' => 'digest', 'policy' => 'digest', 'next_sequence' => 'int', 'observed_at' => 'int'], ['site']);
        SqlSchema::table($this->unit, 'sosecurity_audit_records',
            ['site' => 'digest', 'sequence_no' => 'int', 'recorded_at' => 'int', 'expires_at' => 'int', 'record' => 'blob'],
            ['site', 'sequence_no'], ['sosecurity_audit_expiry' => ['unique' => false, 'columns' => ['site', 'expires_at', 'sequence_no']]]);
    }

    /** Root lock serializes capacity, pruning and sequence assignment across independent writers. */
    private function root(bool $required = true): ?array
    {
        $rows = $this->unit->metadataRows('SELECT ' . SqlSchema::boundedProjection($this->unit->driver(),
            ['policy' => 'digest', 'next_sequence' => 'int', 'observed_at' => 'int'])
            . ' FROM ' . $this->unit->prefix() . 'sosecurity_audit_roots WHERE site=:site LIMIT 1'
            . ($this->unit->driver() === 'mysql' && !$this->unit->isObservation() ? ' FOR UPDATE' : ''), ['site' => $this->site]);
        if (count($rows) > 1) { throw new StorageException('Invalid SQL audit root.', 'audit.sql_corrupt'); }
        $row = $rows[0] ?? false;
        if ($row === false && !$required) { return null; }
        if (!is_array($row) || !is_string($row['policy']) || !hash_equals($this->policy, $row['policy'])) {
            throw new StorageException('SQL audit site is uninitialized or policy changed.', 'audit.sql_policy');
        }
        $row['next_sequence'] = SqlSchema::integer($row['next_sequence']);
        $row['observed_at'] = SqlSchema::integer($row['observed_at']);
        if ($this->unit->now() < $row['observed_at']) {
            throw new StorageException('SQL audit clock moved backwards.', 'audit.sql_clock');
        }
        return $row;
    }

    // MySQL schema reads may establish an older REPEATABLE READ snapshot before the root lock.
    // Count and prune with current locking reads; the root lock alone does not refresh that snapshot.
    private function count(): int
    {
        $count = $this->number('SELECT COUNT(*) FROM (SELECT sequence_no FROM '
            . $this->unit->prefix() . 'sosecurity_audit_records WHERE site=:site LIMIT '
            . ($this->maximum + 1) . ($this->unit->driver() === 'mysql' && !$this->unit->isObservation() ? ' FOR UPDATE' : '')
            . ') audit_count', ['site' => $this->site]);
        if ($count > $this->maximum) { throw new StorageException('SQL audit capacity state is invalid.', 'audit.sql_corrupt'); }
        return $count;
    }

    private function pruneRows(int $now, int $limit): int
    {
        $rows = $this->unit->metadataRows('SELECT sequence_no FROM ' . $this->unit->prefix()
            . 'sosecurity_audit_records WHERE site=:site AND expires_at<=:now ORDER BY expires_at,sequence_no LIMIT ' . $limit
            . ($this->unit->driver() === 'mysql' && !$this->unit->isObservation() ? ' FOR UPDATE' : ''),
            ['site' => $this->site, 'now' => $now]);
        foreach ($rows as $row) {
            if (!array_key_exists('sequence_no', $row)) { throw new StorageException('Invalid SQL audit prune key.', 'audit.sql_corrupt'); }
            $deleted = $this->unit->execute('DELETE FROM ' . $this->unit->prefix()
                . 'sosecurity_audit_records WHERE site=:site AND sequence_no=:sequence',
                ['site' => $this->site, 'sequence' => SqlSchema::integer($row['sequence_no'])]);
            if ($deleted !== 1) { throw new StorageException('SQL audit prune did not delete one record.', 'audit.sql_corrupt'); }
        }
        return count($rows);
    }

    private function touch(int $sequence, int $now): void
    {
        $affected = $this->unit->execute('UPDATE ' . $this->unit->prefix()
            . 'sosecurity_audit_roots SET next_sequence=:sequence,observed_at=:now WHERE site=:site',
            ['sequence' => $sequence, 'now' => $now, 'site' => $this->site]);
        if ($affected > 1) { throw new StorageException('Invalid SQL audit root update.', 'audit.sql_corrupt'); }
        if ($affected === 0) {
            // Native MySQL reports changed rows: a same-value maintenance UPDATE can be zero.
            $row = $this->root();
            if ($row['next_sequence'] !== $sequence || $row['observed_at'] !== $now) {
                throw new StorageException('SQL audit root was not updated.', 'audit.sql_corrupt');
            }
        }
    }

    private static function encode(array $record): string
    {
        if (count($record) !== 5 || array_keys($record) !== ['time', 'event', 'scope', 'subject', 'context']
            || !is_int($record['time']) || $record['time'] < 0
            || !is_string($record['event']) || !preg_match('/\A[a-z][a-z0-9_.]{0,63}\z/D', $record['event'])
            || !is_string($record['scope']) || $record['scope'] === '' || strlen($record['scope']) > 256
            || preg_match('/[\x00-\x1f\x7f]/', $record['scope'])
            || ($record['subject'] !== null && (!is_string($record['subject']) || !preg_match('/\A[a-f0-9]{64}\z/D', $record['subject'])))
            || !is_array($record['context']) || count($record['context']) > 3) {
            throw new ConfigurationException('Invalid SQL audit record.', 'configuration.audit_record');
        }
        foreach ($record['context'] as $key => $value) {
            if (($key === 'allowed' && !is_bool($value))
                || (in_array($key, ['retry_after', 'status'], true) && (!is_int($value) || $value < 0))
                || !in_array($key, ['allowed', 'retry_after', 'status'], true)) {
                throw new ConfigurationException('Invalid SQL audit context.', 'configuration.audit_record');
            }
        }
        $body = json_encode($record, JSON_UNESCAPED_SLASHES);
        if (!is_string($body) || strlen($body) > 4096) {
            throw new ConfigurationException('SQL audit record exceeds its encoding limit.', 'configuration.audit_record');
        }
        return $body;
    }

    public function __debugInfo(): array { return ['sql_audit_sink' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Rebuild SQL audit sinks.', 'configuration.audit_serialization'); }
    public function __wakeup(): void { throw new ConfigurationException('Rebuild SQL audit sinks.', 'configuration.audit_serialization'); }
    public function __clone() { throw new ConfigurationException('Rebuild SQL audit sinks.', 'configuration.audit_serialization'); }
    public function __set(string $name, $value): void { throw new ConfigurationException('SQL audit configuration is immutable.', 'configuration.immutable'); }
}
