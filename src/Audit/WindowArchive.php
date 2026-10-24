<?php
declare(strict_types=1);

namespace SoSecurity\Audit;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\NamespacedStore;
use SoSecurity\Storage\SessionStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Explicit bounded copies of still-available closed windows, never a log reconstruction. */
final class WindowArchive
{
    private const CLASSES = ['authentication', 'authorization', 'abuse', 'availability'];
    private const MAXIMUM_BYTES = 32768;
    private $access;
    private $active = false;
    private $reentered = false;
    private $lastTime;

    public function __construct(MetricsSink $metrics, AtomicStore $store, callable $permission,
        int $maximumWindows, int $retentionSeconds, ?Clock $clock = null, int $timeoutMilliseconds = 1000)
    {
        $base = $store;
        while ($base instanceof NamespacedStore) { $base = $base->underlying(); }
        if ($base instanceof MemoryStore || $base instanceof SessionStore
            || $maximumWindows < 1 || $maximumWindows > 64
            || $retentionSeconds < 1 || $retentionSeconds > 31536000
            || $timeoutMilliseconds < 1 || $timeoutMilliseconds > 30000) {
            throw new ConfigurationException('Use shared storage and bounded audit window settings.', 'configuration.audit_window');
        }
        $clock = $clock ?? new SystemClock();
        try { $raw = $metrics->archiveProfile($clock); }
        catch (\Throwable $error) {
            throw new ConfigurationException('Use an exact retained audit metrics source and clock.', 'configuration.audit_window');
        }
        if (!self::profileShape($raw)) {
            throw new ConfigurationException('Use an exact retained audit metrics source and clock.', 'configuration.audit_window');
        }
        $thresholds = [];
        foreach ($raw['thresholds'] as $class => $threshold) { $thresholds[$class] = $threshold; }
        $profile = ['policy' => $raw['policy'], 'site_binding' => $raw['site_binding'],
            'maximum_events' => $raw['maximum_events'], 'window_seconds' => $raw['window_seconds'],
            'thresholds' => $thresholds, 'retained_windows' => $raw['retained_windows']];
        $key = Guard::key('audit-window-archive', $profile['site_binding'], 'closed');
        $policy = hash('sha256', 'SoSecurity.AuditWindowArchive.1.'
            . json_encode([$profile, $maximumWindows, $retentionSeconds], JSON_UNESCAPED_SLASHES));
        // Closures keep source objects and host callback captures out of ordinary exports.
        $this->access = static function () use ($metrics, $store, $permission, $clock, $profile,
            $key, $policy, $maximumWindows, $retentionSeconds, $timeoutMilliseconds): array {
            return ['source' => $metrics, 'store' => $store, 'permission' => $permission,
                'clock' => $clock, 'profile' => $profile, 'key' => $key, 'policy' => $policy,
                'maximum' => $maximumWindows, 'retention' => $retentionSeconds,
                'milliseconds' => $timeoutMilliseconds];
        };
    }

    /** Copies only source-owned closed windows; an existing identical copy is also returned. */
    public function checkpointClosedWindows(): array
    {
        $this->enter();
        try {
            $context = $this->context(); $budget = $this->budget($context, null);
            $this->authorize($context, 'write', $budget);
            $this->now($context, $budget);
            try { $snapshots = $context['source']->inspectRetained(); }
            catch (\Throwable $error) {
                $this->uninterrupted();
                throw new DependencyException('Closed audit metric windows are unavailable.', 'audit.window_source');
            }
            $at = $this->now($context, $budget);
            $copies = self::closed($snapshots, $context['profile'], $at, $context['retention']);
            $this->authorize($context, 'write', $budget);
            $at = $this->now($context, $budget);
            $saved = $this->transact($context, static function (?array $state) use ($context, $copies, $at): Change {
                $windows = self::windows($state, $context, $at);
                $byStart = [];
                foreach ($windows as $snapshot) { $byStart[$snapshot['window_start']] = $snapshot; }
                $saved = [];
                foreach ($copies as $snapshot) {
                    if (self::expires($snapshot, $context['retention']) <= $at) { continue; }
                    $start = $snapshot['window_start'];
                    if (isset($byStart[$start])) {
                        if ($byStart[$start] !== $snapshot) {
                            throw new SecurityException('An audit window checkpoint conflicts with its original copy.', 'audit.window_conflict');
                        }
                    } else {
                        if (count($byStart) >= $context['maximum']) {
                            throw new SecurityException('Audit window archive capacity is exhausted.', 'audit.window_capacity');
                        }
                        $byStart[$start] = $snapshot;
                    }
                    $saved[] = $start;
                }
                ksort($byStart, SORT_NUMERIC);
                return self::change(array_values($byStart), $context, $at, $saved);
            });
            $at = $this->now($context, $budget);
            if (!is_array($saved) || count($saved) > $context['profile']['retained_windows']
                || !self::isList($saved)) { self::corrupt(); }
            $byStart = [];
            foreach ($copies as $snapshot) { $byStart[$snapshot['window_start']] = $snapshot; }
            $last = -1; $expected = [];
            foreach ($saved as $start) {
                if (!is_int($start) || $start <= $last || $start < 0
                    || $start % $context['profile']['window_seconds'] !== 0
                    || $start > PHP_INT_MAX - $context['profile']['window_seconds'] - $context['retention']
                    || !isset($byStart[$start])) { self::corrupt(); }
                if ($start + $context['profile']['window_seconds'] + $context['retention'] <= $at) { throw self::missing(); }
                $expected[] = $byStart[$start];
                $last = $start;
            }
            $this->authorize($context, 'write', $budget);
            $this->verify($context, $at, $expected);
            $this->uninterrupted();
            $budget->check('audit.window_timeout');
            return $saved;
        } finally { $this->active = false; }
    }

    /** Returns one exact original window, or refuses a missing or expired checkpoint. */
    public function window(int $windowStart, ?Deadline $budget = null): array
    {
        $this->enter();
        try {
            $context = $this->context(); $budget = $this->budget($context, $budget);
            if ($windowStart < 0 || $windowStart % $context['profile']['window_seconds'] !== 0
                || $windowStart > PHP_INT_MAX - $context['profile']['window_seconds'] - $context['retention']) {
                throw new ConfigurationException('Use an exact bounded audit window start.', 'configuration.audit_window_query');
            }
            $this->authorize($context, 'read', $budget);
            $at = $this->now($context, $budget);
            $snapshot = $this->transact($context, static function (?array $state) use ($context, $at, $windowStart): Change {
                $windows = self::windows($state, $context, $at);
                foreach ($windows as $snapshot) {
                    if ($snapshot['window_start'] === $windowStart) {
                        return self::change($windows, $context, $at, $snapshot);
                    }
                }
                throw self::missing();
            });
            $at = $this->now($context, $budget);
            $snapshot = self::snapshot($snapshot, $context['profile'], $at, $context['retention'], true);
            if ($snapshot['window_start'] !== $windowStart) { self::corrupt(); }
            if (self::expires($snapshot, $context['retention']) <= $at) { throw self::missing(); }
            $this->authorize($context, 'read', $budget);
            $this->verify($context, $at, [$snapshot]);
            $this->uninterrupted();
            $budget->check('audit.window_timeout');
            return $snapshot;
        } finally { $this->active = false; }
    }

    public function matches(MetricsSink $metrics): bool { return $this->context()['source'] === $metrics; }

    private function enter(): void
    {
        if ($this->active) {
            $this->reentered = true;
            throw new SecurityException('Audit window archive reentry is not allowed.', 'audit.window_reentry');
        }
        $this->active = true; $this->reentered = false;
    }

    private function uninterrupted(): void
    {
        if ($this->reentered) {
            throw new SecurityException('Audit window archive reentry is not allowed.', 'audit.window_reentry');
        }
    }

    private function context(): array
    {
        if (!$this->access instanceof \Closure) {
            throw new ConfigurationException('Rebuild audit window archives from trusted configuration.', 'configuration.audit_serialization');
        }
        return ($this->access)();
    }

    private function budget(array $context, ?Deadline $parent): Deadline
    {
        $budget = new Deadline($context['milliseconds']);
        if ($parent !== null) { $budget->restrictTo($parent); $parent->restrictTo($budget); }
        $budget->check('audit.window_timeout');
        return $budget;
    }

    private function authorize(array $context, string $action, Deadline $budget): void
    {
        $budget->check('audit.window_timeout');
        try { $allowed = ($context['permission'])($action); }
        catch (\Throwable $error) { $allowed = false; }
        $this->uninterrupted(); $budget->check('audit.window_timeout');
        if ($allowed !== true) {
            throw new SecurityException('Audit window archive access denied.', 'audit.window_forbidden');
        }
    }

    private function now(array $context, Deadline $budget): int
    {
        $this->uninterrupted(); $budget->check('audit.window_timeout');
        try { $at = $context['clock']->now(); }
        catch (\Throwable $error) {
            $this->uninterrupted();
            throw new StorageException('Audit window clock is unavailable or moved backwards.', 'audit.window_clock');
        }
        $this->uninterrupted(); $budget->check('audit.window_timeout');
        if (!is_int($at) || $at < 0 || $at > PHP_INT_MAX - 31536001
            || ($this->lastTime !== null && $at < $this->lastTime)) {
            throw new StorageException('Audit window clock is unavailable or moved backwards.', 'audit.window_clock');
        }
        $this->lastTime = $at;
        return $at;
    }

    private function transact(array $context, callable $callback)
    {
        try { $result = $context['store']->transact($context['key'], $callback); }
        catch (\Throwable $error) {
            $this->uninterrupted();
            $reason = ($error instanceof ConfigurationException || $error instanceof StorageException
                || get_class($error) === SecurityException::class) ? $error->reason() : '';
            if ($reason === 'audit.window_missing') { throw self::missing(); }
            if ($reason === 'audit.window_corrupt') { self::corrupt(); }
            if ($reason === 'audit.window_clock') {
                throw new StorageException('Audit window clock is unavailable or moved backwards.', $reason);
            }
            if ($reason === 'configuration.audit_window_policy') {
                throw new ConfigurationException('Audit window archive policy differs from its original source.', $reason);
            }
            if ($reason === 'audit.window_conflict') {
                throw new SecurityException('An audit window checkpoint conflicts with its original copy.', $reason);
            }
            if ($reason === 'audit.window_changed') {
                throw new SecurityException('An audit window checkpoint changed before returning.', $reason);
            }
            if ($reason === 'audit.window_capacity') {
                throw new SecurityException('Audit window archive capacity is exhausted.', $reason);
            }
            throw new StorageException('Audit window archive storage is unavailable.', 'audit.window_storage');
        }
        $this->uninterrupted();
        return $result;
    }

    /** After the final host callbacks, compare live targets without changing their state or expiry. */
    private function verify(array $context, int $at, array $expected): void
    {
        $this->transact($context, static function (?array $state) use ($context, $at, $expected): Change {
            $windows = self::windows($state, $context, $at);
            $byStart = [];
            foreach ($windows as $snapshot) { $byStart[$snapshot['window_start']] = $snapshot; }
            foreach ($expected as $snapshot) {
                $start = $snapshot['window_start'];
                if (!isset($byStart[$start])) { throw self::missing(); }
                if ($byStart[$start] !== $snapshot) {
                    throw new SecurityException('An audit window checkpoint changed before returning.', 'audit.window_changed');
                }
            }
            if ($state === null) { return new Change(null, 0, null); }
            if ($state['windows'] === []) { self::corrupt(); }
            $last = $state['windows'][count($state['windows']) - 1];
            return new Change($state, self::expires($last, $context['retention']), null);
        });
    }

    private static function profileShape($profile): bool
    {
        if (!is_array($profile) || count($profile) !== 6
            || array_keys($profile) !== ['policy', 'site_binding', 'maximum_events', 'window_seconds', 'thresholds', 'retained_windows']
            || !self::digest($profile['policy']) || !self::digest($profile['site_binding'])
            || !is_int($profile['maximum_events']) || $profile['maximum_events'] < 1 || $profile['maximum_events'] > 100000
            || !is_int($profile['window_seconds']) || $profile['window_seconds'] < 1 || $profile['window_seconds'] > 86400
            || !is_int($profile['retained_windows']) || $profile['retained_windows'] < 1 || $profile['retained_windows'] > 64
            || !is_array($profile['thresholds']) || count($profile['thresholds']) > 4) { return false; }
        foreach ($profile['thresholds'] as $class => $threshold) {
            if (!in_array($class, self::CLASSES, true) || !is_int($threshold)
                || $threshold < 1 || $threshold > $profile['maximum_events']) { return false; }
        }
        $ordered = $profile['thresholds']; ksort($ordered);
        return $ordered === $profile['thresholds'];
    }

    private static function digest($value): bool
    {
        return is_string($value) && strlen($value) === 64 && preg_match('/\A[a-f0-9]{64}\z/D', $value) === 1;
    }

    private static function isList(array $values): bool
    {
        return $values === [] || array_keys($values) === range(0, count($values) - 1);
    }

    private static function closed($snapshots, array $profile, int $now, int $retention): array
    {
        if (!is_array($snapshots) || count($snapshots) < 1
            || count($snapshots) > $profile['retained_windows'] + 1 || !self::isList($snapshots)) { self::corrupt(); }
        $last = count($snapshots) - 1; $windows = []; $previous = -1;
        foreach ($snapshots as $index => $raw) {
            $snapshot = self::snapshot($raw, $profile, $now, $retention, $index !== $last);
            if ($snapshot['window_start'] < $previous) { self::corrupt(); }
            $previous = $snapshot['expires_at'];
            // The last item is the source's current window, even if time advanced during its read.
            if ($index !== $last && self::expires($snapshot, $retention) > $now) { $windows[] = $snapshot; }
        }
        return $windows;
    }

    private static function snapshot($raw, array $profile, int $now, int $retention, bool $closed): array
    {
        if (!is_array($raw) || count($raw) !== 5
            || array_keys($raw) !== ['window_start', 'expires_at', 'counts', 'total', 'alerts']
            || !is_int($raw['window_start']) || $raw['window_start'] < 0 || $raw['window_start'] > $now
            || $raw['window_start'] % $profile['window_seconds'] !== 0
            || $raw['window_start'] > PHP_INT_MAX - $profile['window_seconds'] - $retention
            || !is_int($raw['expires_at']) || $raw['expires_at'] !== $raw['window_start'] + $profile['window_seconds']
            || ($closed && $raw['expires_at'] > $now)
            || !is_array($raw['counts']) || count($raw['counts']) !== 4 || array_keys($raw['counts']) !== self::CLASSES
            || !is_int($raw['total']) || $raw['total'] < 0 || $raw['total'] > $profile['maximum_events']
            || !is_array($raw['alerts']) || count($raw['alerts']) > 4 || !self::isList($raw['alerts'])) { self::corrupt(); }
        $counts = []; $total = 0; $alerts = [];
        foreach (self::CLASSES as $class) {
            $count = $raw['counts'][$class];
            if (!is_int($count) || $count < 0 || $count > $profile['maximum_events']) { self::corrupt(); }
            $counts[$class] = $count; $total += $count;
        }
        if ($total !== $raw['total']) { self::corrupt(); }
        foreach ($profile['thresholds'] as $class => $threshold) {
            if ($counts[$class] >= $threshold) { $alerts[] = $class; }
        }
        if ($raw['alerts'] !== $alerts) { self::corrupt(); }
        return ['window_start' => $raw['window_start'], 'expires_at' => $raw['expires_at'],
            'counts' => $counts, 'total' => $total, 'alerts' => $alerts];
    }

    private static function windows(?array $state, array $context, int $now): array
    {
        if ($state === null) { return []; }
        if (count($state) !== 5 || array_keys($state) !== ['v', 'policy', 'profile', 'observed_at', 'windows']
            || $state['v'] !== 1 || !self::digest($state['policy']) || !self::profileShape($state['profile'])
            || !is_int($state['observed_at']) || $state['observed_at'] < 0
            || !is_array($state['windows']) || count($state['windows']) > 64 || !self::isList($state['windows'])) { self::corrupt(); }
        if ($state['policy'] !== $context['policy'] || $state['profile'] !== $context['profile']) {
            throw new ConfigurationException('Audit window archive policy differs from its original source.', 'configuration.audit_window_policy');
        }
        if ($state['observed_at'] > $now) {
            throw new StorageException('Audit window clock is unavailable or moved backwards.', 'audit.window_clock');
        }
        if (count($state['windows']) > $context['maximum']) { self::corrupt(); }
        $kept = []; $last = -1;
        foreach ($state['windows'] as $raw) {
            $snapshot = self::snapshot($raw, $context['profile'], $now, $context['retention'], true);
            if ($snapshot['window_start'] < $last || $snapshot['expires_at'] > $state['observed_at']) { self::corrupt(); }
            $last = $snapshot['expires_at'];
            if (self::expires($snapshot, $context['retention']) > $now) { $kept[] = $snapshot; }
        }
        self::size($state);
        return $kept;
    }

    private static function expires(array $snapshot, int $retention): int { return $snapshot['expires_at'] + $retention; }

    private static function change(array $windows, array $context, int $now, $result): Change
    {
        if ($windows === []) { return new Change(null, 0, $result); }
        $state = ['v' => 1, 'policy' => $context['policy'], 'profile' => $context['profile'],
            'observed_at' => $now, 'windows' => $windows];
        self::size($state);
        return new Change($state, self::expires($windows[count($windows) - 1], $context['retention']), $result);
    }

    private static function size(array $state): void
    {
        $body = json_encode($state, JSON_UNESCAPED_SLASHES);
        if (!is_string($body) || strlen($body) > self::MAXIMUM_BYTES) { self::corrupt(); }
    }

    private static function corrupt(): void
    {
        throw new StorageException('Audit window archive differs from its bounded protocol.', 'audit.window_corrupt');
    }

    private static function missing(): SecurityException
    {
        return new SecurityException('The exact audit window checkpoint is missing or expired.', 'audit.window_missing');
    }

    public function __debugInfo(): array { return ['audit_window_archive' => '[redacted]']; }
    public function __sleep(): array
    {
        throw new ConfigurationException('Rebuild audit window archives from trusted configuration.', 'configuration.audit_serialization');
    }
    public function __wakeup(): void
    {
        throw new ConfigurationException('Rebuild audit window archives from trusted configuration.', 'configuration.audit_serialization');
    }
    public function __set(string $name, $value): void
    {
        throw new ConfigurationException('Audit window archive configuration is immutable.', 'configuration.immutable');
    }
}
