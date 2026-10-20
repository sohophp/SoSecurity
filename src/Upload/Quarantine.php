<?php
declare(strict_types=1);
namespace SoSecurity\Upload;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Bounded persistent private quarantine. Host code owns authorization, CSRF and worker scheduling. */
final class Quarantine
{
    private $services;
    private $policy;
    private $options;
    private $key;
    private $fingerprint;
    private $observed = 0;
    public function __construct(AtomicStore $store, Policy $uploadPolicy, Scanner $scanner, string $directory,
        string $documentRoot, string $scope, array $options = [], ?Clock $clock = null)
    {
        Guard::label($scope); $this->options = QuarantineState::options($options);
        $files = new QuarantineFiles($directory, $documentRoot, $uploadPolicy); $validator = $files->validator(); $clock = $clock ?? new SystemClock();
        $this->services = static function () use ($store, $files, $validator, $scanner, $clock): array {
            return ['store' => $store, 'files' => $files, 'validator' => $validator, 'scanner' => $scanner, 'clock' => $clock];
        };
        $this->policy = $uploadPolicy;
        $this->key = Guard::key('upload-quarantine', $scope, $files->binding());
        $this->fingerprint = hash('sha256', json_encode([$uploadPolicy->options(), $this->options, $files->binding()]));
    }
    private function now(): int
    {
        $now = ($this->services)()['clock']->now();
        if ($now < $this->observed || $now < 0 || $now > PHP_INT_MAX - 2592001) { throw new StorageException('Quarantine clock is invalid or moved backwards.', 'upload.quarantine_clock'); }
        $this->observed = $now; return $now;
    }
    /** Only pure state transformations run under AtomicStore. No scanner, file I/O or random generation. */
    private function change(int $now, callable $operation)
    {
        return ($this->services)()['store']->transact($this->key, function ($value) use ($now, $operation) {
            $state = QuarantineState::read($value, $this->fingerprint, $this->policy, $this->options, $now);
            return $operation($state);
        });
    }
    public function enqueueUpload(array $file): QuarantineStatus { return $this->enqueue(($this->services)()['validator']->inspectUpload($file)); }
    /** The source path must come from authorized server code; it is copied and never deleted. */
    public function enqueueFile(string $trustedPath, string $originalName): QuarantineStatus
    {
        return $this->enqueue(($this->services)()['validator']->inspectFile($trustedPath, $originalName));
    }
    private function enqueue(Candidate $candidate): QuarantineStatus
    {
        return ($this->services)()['files']->locked(function () use ($candidate): QuarantineStatus { return $this->enqueueLocked($candidate); });
    }
    private function enqueueLocked(Candidate $candidate): QuarantineStatus
    {
        $now = $this->now(); $id = bin2hex(random_bytes(16));
        $entry = ['file' => ['extension' => $candidate->extension(), 'mime' => $candidate->mime(), 'bytes' => $candidate->bytes(),
            'source_bytes' => $candidate->sourceBytes(), 'sha256' => $candidate->digest(), 'width' => $candidate->width(), 'height' => $candidate->height()],
            'state' => 'staging', 'attempts' => 0, 'generation' => 1, 'created' => $now, 'expires' => $now + $this->options['lifetime_seconds'],
            'lease' => 0, 'token' => '', 'retry' => 0, 'error' => null];
        // Reserve the exact random filename before touching it. A crash leaves a removable staging record.
        $this->change($now, function (array $state) use ($id, $entry): Change {
            $bytes = 0; foreach ($state['entries'] as $existing) { $bytes += $existing['file']['bytes']; }
            if (count($state['entries']) >= $this->options['maximum_entries'] || isset($state['entries'][$id])
                || $bytes + $entry['file']['bytes'] > $this->options['maximum_total_bytes']) {
                throw new StorageException('Quarantine is full or its identifier collided.', 'upload.quarantine_capacity');
            }
            $state['entries'][$id] = $entry; return new Change($state, 0, null);
        });
        ($this->services)()['files']->write($id, $candidate);
        $finished = $this->now();
        return $this->change($finished, static function (array $state) use ($id, $finished): Change {
            if (!isset($state['entries'][$id])) { throw new StorageException('Quarantine reservation disappeared.', 'upload.quarantine_missing'); }
            $entry = $state['entries'][$id];
            if ($entry['state'] === 'staging' && $entry['generation'] === 1) { $entry = QuarantineState::advance($entry); $entry['state'] = 'pending'; $state['entries'][$id] = $entry; }
            return new Change($state, 0, QuarantineState::status($id, $entry, $finished));
        });
    }
    public function inspect(string $id): ?QuarantineStatus
    {
        $entry = $this->entry($id); return $entry === null ? null : QuarantineState::status($id, $entry, $this->now());
    }
    private function entry(string $id): ?array
    {
        QuarantineState::id($id); $now = $this->now();
        return $this->change($now, static function (array $state) use ($id): Change { return new Change($state, 0, $state['entries'][$id] ?? null); });
    }
    /** Bounded enumeration, including failed/expired/staging entries for authorized maintenance. */
    public function items(int $limit = 64): array
    {
        if ($limit < 1 || $limit > 64) { throw new ConfigurationException('List 1-64 quarantine entries.', 'configuration.quarantine'); }
        $now = $this->now();
        return $this->change($now, static function (array $state) use ($now, $limit): Change {
            $result = []; foreach ($state['entries'] as $id => $entry) { $result[] = QuarantineState::status($id, $entry, $now); if (count($result) === $limit) { break; } }
            return new Change($state, 0, $result);
        });
    }
    /** Process one due entry. A null identifier selects the first due item. No I/O occurs inside the claim callback. */
    public function process(?string $id = null): ?QuarantineStatus
    {
        if ($id !== null) { QuarantineState::id($id); }
        $now = $this->now(); $token = bin2hex(random_bytes(32)); $deadline = new Deadline($this->options['scan_milliseconds']);
        $claim = $this->change($now, function (array $state) use ($id, $now, $token): Change {
            foreach ($state['entries'] as $candidate => $entry) {
                if (($id !== null && $id !== $candidate) || $entry['expires'] <= $now) { continue; }
                $due = $entry['state'] === 'pending' || ($entry['state'] === 'retry' && $entry['retry'] <= $now)
                    || ($entry['state'] === 'scanning' && $entry['lease'] <= $now);
                if (!$due) { continue; }
                $entry = QuarantineState::advance($entry);
                if ($entry['attempts'] >= $this->options['maximum_attempts']) {
                    $entry['state'] = 'failed'; $entry['error'] = 'attempts.exhausted'; $state['entries'][$candidate] = $entry;
                    continue;
                }
                ++$entry['attempts']; $entry['state'] = 'scanning'; $entry['error'] = null;
                $entry['lease'] = $now + $this->options['lease_seconds']; $entry['token'] = hash('sha256', $token); $state['entries'][$candidate] = $entry;
                return new Change($state, 0, ['id' => $candidate, 'entry' => $entry]);
            }
            return new Change($state, 0, null);
        });
        if ($claim === null) { return $id === null ? null : $this->inspect($id); }
        $id = $claim['id']; $entry = $claim['entry']; $error = null; $passed = false;
        if ($deadline->remaining() <= 0) { $error = 'scan.timeout'; }
        else {
            try { $snapshot = ($this->services)()['files']->read($id, $entry['file']); }
            catch (\Throwable $failure) { $error = 'content.invalid'; }
        }
        if ($error === null) {
            try {
                $deadline->check('upload.quarantine_timeout');
                $passed = ($this->services)()['scanner']->scan($snapshot);
                $deadline->check('upload.quarantine_timeout');
            } catch (\Throwable $failure) { $error = $deadline->remaining() <= 0 ? 'scan.timeout' : 'scan.failed'; }
        }
        if ($passed && $error === null) {
            try { ($this->services)()['files']->read($id, $entry['file']); }
            catch (\Throwable $failure) { $error = 'content.invalid'; }
        }
        if ($deadline->remaining() <= 0) { $error = 'scan.timeout'; }
        $finished = $this->now();
        if ($finished >= $entry['lease'] || $finished >= $entry['expires']) { $passed = false; $error = 'scan.timeout'; }
        return $this->change($finished, function (array $state) use ($id, $entry, $token, $passed, $error, $finished): Change {
            $current = $state['entries'][$id] ?? null;
            if ($current === null) { return new Change($state, 0, null); }
            if ($current['state'] === 'scanning' && $current['generation'] === $entry['generation'] && hash_equals($current['token'], hash('sha256', $token))) {
                $current = QuarantineState::advance($current); $current['error'] = $error;
                if ($error !== null) {
                    $retry = $finished + $this->options['retry_seconds'];
                    $current['state'] = $error !== 'content.invalid' && $current['attempts'] < $this->options['maximum_attempts'] && $retry < $current['expires'] ? 'retry' : 'failed';
                    if ($current['state'] === 'retry') { $current['retry'] = $retry; }
                } else { $current['state'] = $passed ? 'available' : 'rejected'; }
                $state['entries'][$id] = $current;
            }
            return new Change($state, 0, QuarantineState::status($id, $current, $finished));
        });
    }
    /** Privileged host action; never accepts an administrator's assertion that content is clean. */
    public function rescan(string $id): QuarantineStatus { return $this->admin($id, false); }
    /** Privileged host action. Immediately invalidates in-flight scans and future reads. */
    public function reject(string $id): QuarantineStatus { return $this->admin($id, true); }
    private function admin(string $id, bool $reject): QuarantineStatus
    {
        QuarantineState::id($id); $now = $this->now();
        return $this->change($now, static function (array $state) use ($id, $reject, $now): Change {
            $entry = $state['entries'][$id] ?? null;
            if ($entry === null || $entry['state'] === 'deleting' || (!$reject && ($entry['state'] === 'staging' || $entry['expires'] <= $now))) {
                throw new SecurityException('Quarantine action is not available.', 'upload.quarantine_state');
            }
            $entry = QuarantineState::advance($entry); $entry['state'] = $reject ? 'rejected' : 'pending'; $entry['error'] = $reject ? 'admin.rejected' : null;
            if (!$reject) { $entry['attempts'] = 0; }
            $state['entries'][$id] = $entry; return new Change($state, 0, QuarantineState::status($id, $entry, $now));
        });
    }
    /** Returns a digest-checked immutable snapshot, never a path. Host authorization precedes every call. */
    public function readAvailable(string $id): Candidate
    {
        $entry = $this->entry($id); $now = $this->now();
        if ($entry === null || $entry['state'] !== 'available' || $entry['expires'] <= $now) { throw new SecurityException('Quarantine content is not available.', 'upload.quarantine_unavailable'); }
        $snapshot = ($this->services)()['files']->read($id, $entry['file']);
        $current = $this->entry($id); $finished = $this->now();
        if ($current === null || $current['state'] !== 'available' || $current['generation'] !== $entry['generation'] || $current['expires'] <= $finished) {
            throw new SecurityException('Quarantine state changed while reading.', 'upload.quarantine_unavailable');
        }
        return $snapshot;
    }
    /** Terminal/expired/staging cleanup. Mark before unlink; an unknown state commit never triggers deletion. */
    public function remove(string $id): bool
    {
        QuarantineState::id($id);
        return ($this->services)()['files']->locked(function () use ($id): bool { return $this->removeLocked($id); });
    }
    private function removeLocked(string $id): bool
    {
        QuarantineState::id($id); $now = $this->now();
        $entry = $this->change($now, static function (array $state) use ($id, $now): Change {
            $entry = $state['entries'][$id] ?? null;
            if ($entry === null) { return new Change($state, 0, null); }
            if ($entry['expires'] > $now && !in_array($entry['state'], ['staging', 'rejected', 'failed', 'deleting'], true)) {
                throw new SecurityException('Reject active content before removing it.', 'upload.quarantine_state');
            }
            $entry = QuarantineState::advance($entry); $entry['state'] = 'deleting'; $state['entries'][$id] = $entry;
            return new Change($state, 0, $entry);
        });
        if ($entry === null) { return false; }
        ($this->services)()['files']->remove($id, $entry['file']['extension']);
        return $this->change($this->now(), static function (array $state) use ($id, $entry): Change {
            if (isset($state['entries'][$id]) && $state['entries'][$id]['state'] === 'deleting' && $state['entries'][$id]['generation'] === $entry['generation']) {
                unset($state['entries'][$id]); return new Change($state, 0, true);
            }
            throw new StorageException('Quarantine cleanup state changed.', 'upload.quarantine_cleanup');
        });
    }
    public function __debugInfo(): array { return ['upload_quarantine' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Rebuild quarantine services.', 'configuration.upload_serialization'); }
    public function __wakeup(): void { throw new ConfigurationException('Rebuild quarantine services.', 'configuration.upload_serialization'); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Quarantine policy is immutable.', 'configuration.immutable'); }
}
