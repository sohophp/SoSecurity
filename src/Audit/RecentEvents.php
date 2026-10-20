<?php
declare(strict_types=1);

namespace SoSecurity\Audit;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\NamespacedStore;
use SoSecurity\Storage\SessionStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Bounded recent-event index for authorized operators, not an immutable audit log. */
final class RecentEvents
{
    private $write;
    private $read;
    private $sink;
    private $authorize;
    private $scopeBinding;
    private $capacity;

    public function __construct(AtomicStore $store, string $site, string $bindingKey, int $capacity,
        int $retentionSeconds, callable $sink, callable $authorize, ?Clock $clock = null)
    {
        Guard::label($site);
        $base = $store;
        while ($base instanceof NamespacedStore) { $base = $base->underlying(); }
        if ($base instanceof MemoryStore || $base instanceof SessionStore || strlen($bindingKey) < 32
            || $capacity < 1 || $capacity > 64 || $retentionSeconds < 1 || $retentionSeconds > 86400) {
            throw new ConfigurationException('Use shared storage and bounded recent-event settings.', 'configuration.audit_recent');
        }
        $this->capacity = $capacity;
        $this->scopeBinding = static function (string $scope) use ($bindingKey): string {
            return hash_hmac('sha256', "SoSecurity.AuditRecent.Scope.1.\0" . $scope, $bindingKey);
        };
        $this->authorize = static function () use ($authorize): bool { return $authorize() === true; };
        $this->sink = static function (array $record) use ($sink): void { $sink($record); };
        $policy = hash_hmac('sha256', $capacity . ':' . $retentionSeconds, $bindingKey);
        $key = Guard::key('audit-recent', $site, 'events');
        $clock = $clock ?? new SystemClock();
        $this->write = static function (array $entry) use ($store, $key, $clock, $policy, $capacity, $retentionSeconds): void {
            $now = $clock->now();
            $expires = self::expiry($now, $retentionSeconds);
            $store->transact($key, static function (?array $state) use ($entry, $now, $expires, $policy, $capacity, $retentionSeconds): Change {
                $entries = self::entries($state, $policy, $now, $capacity, $retentionSeconds);
                if (count($entries) >= $capacity) {
                    throw new SecurityException('Recent audit event capacity exhausted.', 'audit.recent_capacity');
                }
                $entry['at'] = $now;
                $entries[] = $entry;
                return new Change(['v' => 1, 'policy' => $policy, 'entries' => $entries], $expires, null);
            });
        };
        $this->read = static function () use ($store, $key, $clock, $policy, $capacity, $retentionSeconds): array {
            $now = $clock->now();
            $expires = self::expiry($now, $retentionSeconds);
            return $store->transact($key, static function (?array $state) use ($policy, $now, $expires, $capacity, $retentionSeconds): Change {
                $entries = self::entries($state, $policy, $now, $capacity, $retentionSeconds);
                if ($entries === []) { return new Change(null, 0, []); }
                return new Change(['v' => 1, 'policy' => $policy, 'entries' => $entries], $expires, $entries);
            });
        };
    }

    public function __invoke(array $record): void
    {
        self::recordShape($record);
        if (!$this->write instanceof \Closure || !$this->sink instanceof \Closure
            || !$this->scopeBinding instanceof \Closure) {
            throw new ConfigurationException('Rebuild recent audit events from trusted configuration.', 'configuration.audit_serialization');
        }
        $entry = ['at' => 0, 'event' => $record['event'],
            'scope_binding' => ($this->scopeBinding)($record['scope']),
            'subject' => $record['subject'], 'context' => $record['context']];
        ($this->write)($entry);
        ($this->sink)($record);
    }

    /** Newest first; authorization is rechecked before any storage access. */
    public function recent(int $limit = 32, ?string $event = null, ?string $scope = null): array
    {
        if (!$this->authorize instanceof \Closure || !$this->read instanceof \Closure
            || !$this->scopeBinding instanceof \Closure) {
            throw new ConfigurationException('Rebuild recent audit events from trusted configuration.', 'configuration.audit_serialization');
        }
        try { $authorized = ($this->authorize)(); }
        catch (\Throwable $error) { $authorized = false; }
        if (!$authorized) { throw new SecurityException('Recent audit event access denied.', 'audit.recent_forbidden'); }
        if ($limit < 1 || $limit > $this->capacity
            || ($event !== null && !preg_match('/\A[a-z][a-z0-9_.]{0,63}\z/D', $event))) {
            throw new ConfigurationException('Invalid recent-event query.', 'configuration.audit_recent_query');
        }
        if ($scope !== null) { Guard::label($scope); }
        $binding = $scope === null ? null : ($this->scopeBinding)($scope);
        $matches = [];
        foreach (array_reverse(($this->read)()) as $entry) {
            if (($event !== null && $entry['event'] !== $event)
                || ($binding !== null && !hash_equals($binding, $entry['scope_binding']))) { continue; }
            $matches[] = $entry;
            if (count($matches) === $limit) { break; }
        }
        return $matches;
    }

    private static function expiry(int $now, int $seconds): int
    {
        if ($now < 0 || $now > PHP_INT_MAX - $seconds) {
            throw new ConfigurationException('Invalid recent audit clock.', 'configuration.audit_recent');
        }
        return $now + $seconds;
    }

    private static function entries(?array $state, string $policy, int $now, int $capacity, int $seconds): array
    {
        if ($state === null) { return []; }
        if (array_keys($state) !== ['v', 'policy', 'entries'] || $state['v'] !== 1
            || !is_string($state['policy']) || !hash_equals($policy, $state['policy'])
            || !is_array($state['entries']) || count($state['entries']) > $capacity
            || (count($state['entries']) > 0 && array_keys($state['entries']) !== range(0, count($state['entries']) - 1))) {
            throw new StorageException('Corrupt recent audit event state.', 'storage.corrupt');
        }
        $kept = []; $last = -1;
        foreach ($state['entries'] as $entry) {
            if (!is_array($entry) || array_keys($entry) !== ['at', 'event', 'scope_binding', 'subject', 'context']
                || !is_int($entry['at']) || $entry['at'] < $last || $entry['at'] > $now
                || !is_string($entry['event']) || !preg_match('/\A[a-z][a-z0-9_.]{0,63}\z/D', $entry['event'])
                || !is_string($entry['scope_binding']) || !preg_match('/\A[a-f0-9]{64}\z/D', $entry['scope_binding'])
                || ($entry['subject'] !== null && (!is_string($entry['subject']) || !preg_match('/\A[a-f0-9]{64}\z/D', $entry['subject'])))
                || !self::contextShape($entry['context'])) {
                throw new StorageException('Corrupt recent audit event entry.', 'storage.corrupt');
            }
            $last = $entry['at'];
            if ($entry['at'] > $now - $seconds) { $kept[] = $entry; }
        }
        return $kept;
    }

    private static function recordShape(array $record): void
    {
        if (array_keys($record) !== ['time', 'event', 'scope', 'subject', 'context']
            || !is_int($record['time']) || $record['time'] < 0
            || !is_string($record['event']) || !preg_match('/\A[a-z][a-z0-9_.]{0,63}\z/D', $record['event'])
            || !is_string($record['scope']) || $record['scope'] === '' || strlen($record['scope']) > 256
            || preg_match('/[\x00-\x1f\x7f]/', $record['scope'])
            || ($record['subject'] !== null && (!is_string($record['subject']) || !preg_match('/\A[a-f0-9]{64}\z/D', $record['subject'])))
            || !self::contextShape($record['context'])) {
            throw new ConfigurationException('Invalid recent audit record.', 'configuration.audit_record');
        }
    }

    private static function contextShape($context): bool
    {
        if (!is_array($context) || count($context) > 3) { return false; }
        foreach ($context as $name => $value) {
            if (!in_array($name, ['allowed', 'retry_after', 'status'], true)
                || ($name === 'allowed' ? !is_bool($value) : (!is_int($value) || $value < 0))) { return false; }
        }
        return true;
    }

    public function __debugInfo(): array { return ['audit_recent_events' => '[redacted]']; }
    public function __sleep(): array
    {
        throw new ConfigurationException('Rebuild recent audit events from trusted configuration.', 'configuration.audit_serialization');
    }
    public function __wakeup(): void
    {
        throw new ConfigurationException('Rebuild recent audit events from trusted configuration.', 'configuration.audit_serialization');
    }
    public function __set(string $name, $value): void
    {
        throw new ConfigurationException('Recent audit event configuration is immutable.', 'configuration.immutable');
    }
}
