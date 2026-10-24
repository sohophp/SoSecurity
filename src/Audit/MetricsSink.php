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

/** Fixed-label audit attempt counters; alert signals are polled, never sent inside a transaction. */
final class MetricsSink
{
    private const CLASSES = ['authentication', 'authorization', 'abuse', 'availability'];
    private $events;
    private $thresholds;
    private $write;
    private $read;
    private $retained;
    private $sink;
    private $siteBinding;
    private $archiveProfile;

    public function __construct(AtomicStore $store, string $site, array $eventClasses, array $alertThresholds,
        int $maximumEvents, int $windowSeconds, callable $sink, ?Clock $clock = null, int $retainedWindows = 0)
    {
        Guard::label($site);
        $base = $store;
        while ($base instanceof NamespacedStore) { $base = $base->underlying(); }
        if ($base instanceof MemoryStore || $base instanceof SessionStore || $maximumEvents < 1 || $maximumEvents > 100000
            || $windowSeconds < 1 || $windowSeconds > 86400 || $retainedWindows < 0 || $retainedWindows > 64
            || count($eventClasses) < 1 || count($eventClasses) > 64) {
            throw new ConfigurationException('Use shared atomic storage and bounded audit metrics.', 'configuration.audit_metrics');
        }
        foreach ($eventClasses as $event => $class) {
            if (!is_string($event) || !preg_match('/\A[a-z][a-z0-9_.]{0,63}\z/D', $event)
                || !in_array($class, self::CLASSES, true)) {
                throw new ConfigurationException('Invalid audit event classification.', 'configuration.audit_metrics');
            }
        }
        foreach ($alertThresholds as $class => $threshold) {
            if (!in_array($class, self::CLASSES, true) || !is_int($threshold)
                || $threshold < 1 || $threshold > $maximumEvents) {
                throw new ConfigurationException('Invalid audit alert threshold.', 'configuration.audit_metrics');
            }
        }
        ksort($eventClasses); ksort($alertThresholds);
        $this->events = $eventClasses;
        $this->thresholds = $alertThresholds;
        $this->siteBinding = hash('sha256', 'SoSecurity.AuditMetrics.Site.1.' . $site);
        $policy = hash('sha256', json_encode([$eventClasses, $alertThresholds, $maximumEvents, $windowSeconds]));
        if ($retainedWindows > 0) { $policy = hash('sha256', $policy . ':retained:' . $retainedWindows); }
        $key = Guard::key('audit-metrics', $site, 'fixed-window');
        $clock = $clock ?? new SystemClock();
        $profile = ['policy' => $policy, 'site_binding' => $this->siteBinding,
            'maximum_events' => $maximumEvents, 'window_seconds' => $windowSeconds,
            'thresholds' => $alertThresholds, 'retained_windows' => $retainedWindows];
        $this->archiveProfile = static function (Clock $expected) use ($clock, $profile): ?array {
            if ($expected !== $clock && !($expected instanceof SystemClock && $clock instanceof SystemClock)) { return null; }
            return $profile;
        };
        if ($retainedWindows > 0) {
            $this->write = static function (string $class) use ($store, $key, $clock, $policy, $windowSeconds, $maximumEvents, $retainedWindows): void {
                $now = $clock->now();
                list($start, $expires) = self::window($now, $windowSeconds);
                $ttl = self::retainedExpiry($expires, $windowSeconds, $retainedWindows);
                $store->transact($key, static function (?array $state) use ($class, $policy, $start, $expires, $now, $maximumEvents, $retainedWindows, $windowSeconds, $ttl): Change {
                    $state = self::currentRetained($state, $policy, $start, $expires, $now, $maximumEvents, $retainedWindows, $windowSeconds);
                    if ($state['total'] >= $maximumEvents) {
                        throw new SecurityException('Audit metrics capacity exhausted.', 'audit.metrics_capacity');
                    }
                    ++$state['total']; ++$state['counts'][$class];
                    return new Change($state, $ttl, null);
                });
            };
            $this->read = static function () use ($store, $key, $clock, $policy, $windowSeconds, $maximumEvents, $retainedWindows): array {
                $now = $clock->now();
                list($start, $expires) = self::window($now, $windowSeconds);
                $ttl = self::retainedExpiry($expires, $windowSeconds, $retainedWindows);
                return $store->transact($key, static function (?array $state) use ($policy, $start, $expires, $now, $maximumEvents, $retainedWindows, $windowSeconds, $ttl): Change {
                    $state = self::currentRetained($state, $policy, $start, $expires, $now, $maximumEvents, $retainedWindows, $windowSeconds);
                    if ($state['total'] === 0 && $state['history'] === []) { return new Change(null, 0, $state); }
                    return new Change($state, $ttl, $state);
                });
            };
            $this->retained = true;
            $this->sink = static function (array $record) use ($sink): void { $sink($record); };
            return;
        }
        $this->write = static function (string $class) use ($store, $key, $clock, $policy, $windowSeconds, $maximumEvents): void {
            $now = $clock->now();
            list($start, $expires) = self::window($now, $windowSeconds);
            $store->transact($key, static function (?array $state) use ($class, $policy, $start, $expires, $now, $maximumEvents): Change {
                $state = self::current($state, $policy, $start, $expires, $now, $maximumEvents);
                if ($state['total'] >= $maximumEvents) {
                    throw new SecurityException('Audit metrics capacity exhausted.', 'audit.metrics_capacity');
                }
                ++$state['total']; ++$state['counts'][$class];
                return new Change($state, $expires, null);
            });
        };
        $this->read = static function () use ($store, $key, $clock, $policy, $windowSeconds, $maximumEvents): array {
            $now = $clock->now();
            list($start, $expires) = self::window($now, $windowSeconds);
            return $store->transact($key, static function (?array $state) use ($policy, $start, $expires, $now, $maximumEvents): Change {
                $current = self::current($state, $policy, $start, $expires, $now, $maximumEvents);
                $stored = $state !== null && $state['expires'] > $now ? $state : null;
                return new Change($stored, $stored === null ? 0 : $stored['expires'], $current);
            });
        };
        $this->sink = static function (array $record) use ($sink): void { $sink($record); };
    }

    /** Counters are admitted audit attempts, not proof that the downstream log was persisted. */
    public function __invoke(array $record): void
    {
        self::recordShape($record);
        $event = $record['event'];
        if (!isset($this->events[$event])) {
            throw new ConfigurationException('Audit event has no fixed metrics class.', 'configuration.audit_metrics_event');
        }
        if (!$this->write instanceof \Closure || !$this->sink instanceof \Closure) {
            throw new ConfigurationException('Rebuild audit metrics from trusted configuration.', 'configuration.audit_serialization');
        }
        ($this->write)($this->events[$event]);
        ($this->sink)($record);
    }

    /** Trusted operator polling: fixed labels and a window key for host-side alert deduplication. */
    public function inspect(): array
    {
        if (!$this->read instanceof \Closure) {
            throw new ConfigurationException('Rebuild audit metrics from trusted configuration.', 'configuration.audit_serialization');
        }
        $state = ($this->read)();
        return $this->snapshot($state);
    }

    /** Oldest retained window first; the current window is always last. */
    public function inspectRetained(): array
    {
        if (!$this->retained) { return [$this->inspect()]; }
        if (!$this->read instanceof \Closure) {
            throw new ConfigurationException('Rebuild audit metrics from trusted configuration.', 'configuration.audit_serialization');
        }
        $state = ($this->read)();
        $windows = [];
        foreach ($state['history'] as $previous) { $windows[] = $this->snapshot($previous); }
        $windows[] = $this->snapshot($state);
        return $windows;
    }

    private function snapshot(array $state): array
    {
        $alerts = [];
        foreach ($this->thresholds as $class => $threshold) {
            if ($state['counts'][$class] >= $threshold) { $alerts[] = $class; }
        }
        return ['window_start' => $state['start'], 'expires_at' => $state['expires'],
            'counts' => $state['counts'], 'total' => $state['total'], 'alerts' => $alerts];
    }

    /** Stable, non-secret binding for durable alert identities; never exposes the site label. */
    public function siteBinding(): string { return $this->siteBinding; }

    /** Pure fixed-policy metadata for an archive sharing the source's expiry clock. */
    public function archiveProfile(Clock $clock): ?array
    {
        if (!$this->archiveProfile instanceof \Closure) {
            throw new ConfigurationException('Rebuild audit metrics from trusted configuration.', 'configuration.audit_serialization');
        }
        return ($this->archiveProfile)($clock);
    }

    private static function window(int $now, int $seconds): array
    {
        if ($now < 0 || $now > PHP_INT_MAX - $seconds) {
            throw new ConfigurationException('Invalid audit metrics clock.', 'configuration.audit_metrics');
        }
        $start = intdiv($now, $seconds) * $seconds;
        return [$start, $start + $seconds];
    }

    private static function retainedExpiry(int $expires, int $seconds, int $windows): int
    {
        $extra = $seconds * $windows;
        if ($expires > PHP_INT_MAX - $extra) {
            throw new ConfigurationException('Invalid retained audit metrics clock.', 'configuration.audit_metrics');
        }
        return $expires + $extra;
    }

    private static function emptyRetained(string $policy, int $start, int $expires): array
    {
        return ['v' => 2, 'policy' => $policy, 'start' => $start, 'expires' => $expires,
            'counts' => array_fill_keys(self::CLASSES, 0), 'total' => 0, 'history' => []];
    }

    private static function validCounts(array $window, int $maximum, int $seconds): bool
    {
        if (!is_int($window['start']) || $window['start'] < 0 || !is_int($window['expires'])
            || $window['start'] > PHP_INT_MAX - $seconds || $window['expires'] !== $window['start'] + $seconds
            || !is_array($window['counts']) || array_keys($window['counts']) !== self::CLASSES
            || !is_int($window['total']) || $window['total'] < 0 || $window['total'] > $maximum) { return false; }
        $sum = 0;
        foreach ($window['counts'] as $count) {
            if (!is_int($count) || $count < 0 || $count > $maximum) { return false; }
            $sum += $count;
        }
        return $sum === $window['total'];
    }

    private static function currentRetained(?array $state, string $policy, int $start, int $expires,
        int $now, int $maximum, int $windows, int $seconds): array
    {
        if ($state === null) { return self::emptyRetained($policy, $start, $expires); }
        if (($state['v'] ?? null) !== 2 || ($state['policy'] ?? null) !== $policy) {
            throw new ConfigurationException('Audit metrics retention policy changed before old state drained.', 'configuration.audit_metrics_policy');
        }
        if (array_keys($state) !== ['v', 'policy', 'start', 'expires', 'counts', 'total', 'history']
            || !self::validCounts($state, $maximum, $seconds) || !is_array($state['history'])
            || count($state['history']) > $windows
            || (count($state['history']) > 0 && array_keys($state['history']) !== range(0, count($state['history']) - 1))) {
            throw new StorageException('Corrupt retained audit metrics state.', 'storage.corrupt');
        }
        $last = -1;
        foreach ($state['history'] as $previous) {
            if (!is_array($previous) || array_keys($previous) !== ['start', 'expires', 'counts', 'total']
                || !self::validCounts($previous, $maximum, $seconds)
                || $previous['start'] <= $last || $previous['expires'] > $state['start']) {
                throw new StorageException('Corrupt retained audit metrics history.', 'storage.corrupt');
            }
            $last = $previous['start'];
        }
        if ($state['start'] > $start || $state['expires'] > $expires) {
            throw new StorageException('Retained audit metrics clock moved backward.', 'storage.corrupt');
        }
        $history = array_values(array_filter($state['history'], static function (array $entry) use ($now, $seconds, $windows): bool {
            return $entry['expires'] > $now - $seconds * $windows;
        }));
        if ($state['start'] === $start) {
            if ($state['expires'] !== $expires) {
                throw new StorageException('Corrupt retained audit metrics window.', 'storage.corrupt');
            }
            $state['history'] = $history;
            return $state;
        }
        if ($state['total'] > 0) {
            $history[] = ['start' => $state['start'], 'expires' => $state['expires'],
                'counts' => $state['counts'], 'total' => $state['total']];
        }
        $history = array_values(array_filter($history, static function (array $entry) use ($now, $seconds, $windows): bool {
            return $entry['expires'] > $now - $seconds * $windows;
        }));
        if (count($history) > $windows) { $history = array_slice($history, -$windows); }
        $next = self::emptyRetained($policy, $start, $expires);
        $next['history'] = $history;
        return $next;
    }

    private static function current(?array $state, string $policy, int $start, int $expires, int $now, int $maximum): array
    {
        if ($state === null) {
            return ['v' => 1, 'policy' => $policy, 'start' => $start, 'expires' => $expires,
                'counts' => array_fill_keys(self::CLASSES, 0), 'total' => 0];
        }
        if (($state['v'] ?? null) === 2) {
            throw new ConfigurationException('Audit metrics retention policy changed before old state drained.', 'configuration.audit_metrics_policy');
        }
        if (array_keys($state) !== ['v', 'policy', 'start', 'expires', 'counts', 'total']
            || $state['v'] !== 1 || !is_string($state['policy']) || !is_int($state['start'])
            || !is_int($state['expires']) || !is_array($state['counts'])
            || array_keys($state['counts']) !== self::CLASSES || !is_int($state['total'])
            || $state['total'] < 0 || $state['total'] > $maximum) {
            throw new StorageException('Corrupt audit metrics state.', 'storage.corrupt');
        }
        $sum = 0;
        foreach ($state['counts'] as $count) {
            if (!is_int($count) || $count < 0 || $count > $maximum) {
                throw new StorageException('Corrupt audit metrics counts.', 'storage.corrupt');
            }
            $sum += $count;
        }
        if ($sum !== $state['total'] || $state['expires'] <= $state['start']) {
            throw new StorageException('Corrupt audit metrics totals.', 'storage.corrupt');
        }
        if ($state['expires'] <= $now) {
            return self::current(null, $policy, $start, $expires, $now, $maximum);
        }
        if ($state['policy'] !== $policy) {
            throw new ConfigurationException('Audit metrics policy changed before the old window drained.', 'configuration.audit_metrics_policy');
        }
        if ($state['start'] !== $start || $state['expires'] !== $expires) {
            throw new StorageException('Audit metrics clock or window disagrees with stored state.', 'storage.corrupt');
        }
        return $state;
    }

    private static function recordShape(array $record): void
    {
        if (count($record) !== 5 || array_keys($record) !== ['time', 'event', 'scope', 'subject', 'context']
            || !is_int($record['time']) || $record['time'] < 0
            || !is_string($record['event']) || !preg_match('/\A[a-z][a-z0-9_.]{0,63}\z/D', $record['event'])
            || !is_string($record['scope']) || $record['scope'] === '' || strlen($record['scope']) > 256
            || preg_match('/[\x00-\x1f\x7f]/', $record['scope'])
            || ($record['subject'] !== null && (!is_string($record['subject']) || !preg_match('/\A[a-f0-9]{64}\z/D', $record['subject'])))
            || !is_array($record['context']) || count($record['context']) > 3) {
            throw new ConfigurationException('Invalid audit metrics record.', 'configuration.audit_record');
        }
        foreach ($record['context'] as $name => $value) {
            if (!in_array($name, ['allowed', 'retry_after', 'status'], true)
                || ($name === 'allowed' ? !is_bool($value) : (!is_int($value) || $value < 0))) {
                throw new ConfigurationException('Invalid audit metrics context.', 'configuration.audit_record');
            }
        }
    }

    public function __debugInfo(): array { return ['audit_metrics' => '[redacted]']; }
    public function __sleep(): array
    {
        throw new ConfigurationException('Rebuild audit metrics from trusted configuration.', 'configuration.audit_serialization');
    }
}
