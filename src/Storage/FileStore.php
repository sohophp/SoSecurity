<?php
declare(strict_types=1);

namespace SoSecurity\Storage;

use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\SystemClock;

/** Local filesystem only. Private directory must be owned by the application, outside web root. */
final class FileStore implements AtomicStore
{
    private $directory;
    private $namespace;
    private $clock;
    private $lockTimeoutMs;
    private $pruneIterator;

    public function __construct(string $directory, string $namespace, ?Clock $clock = null, int $lockTimeoutMs = 1000)
    {
        Guard::label($namespace);
        new Deadline($lockTimeoutMs);
        $this->lockTimeoutMs = $lockTimeoutMs;
        $real = realpath($directory);
        if ($real === false || !is_dir($real) || !is_writable($real) || (fileperms($real) & 0077) !== 0) {
            throw new StorageException('Use an existing writable private directory (0700).');
        }
        $this->directory = $real;
        $this->namespace = $namespace;
        $this->clock = $clock ?? new SystemClock();
    }

    public function transact(string $key, callable $callback)
    {
        Guard::label($key);
        $hash = hash('sha256', $this->namespace . "\0" . $key);
        return $this->locked($hash, function () use ($hash, $callback) {
            $path = $this->directory . '/' . $hash . '.json';
            $value = null;
            if (file_exists($path)) {
                if (is_link($path)) {
                    throw new StorageException('Symlinks are forbidden in security storage.');
                }
                $raw = @file_get_contents($path, false, null, 0, 65537);
                if ($raw === false) {
                    throw new StorageException('Cannot read security state.', 'storage.io');
                }
                $value = Codec::decode($raw, $this->clock->now());
            }
            $change = $callback($value);
            if (!$change instanceof Change) {
                throw new StorageException('Callback must return Change.');
            }
            if ($change->value() === null) {
                if (file_exists($path) && !@unlink($path)) {
                    throw new StorageException('Cannot delete security state.', 'storage.io');
                }
            } else {
                $json = Codec::encode($change);
                $temporary = @tempnam($this->directory, '.write-');
                if ($temporary === false || dirname($temporary) !== $this->directory) {
                    if ($temporary !== false) { @unlink($temporary); }
                    throw new StorageException('Cannot allocate private security state.', 'storage.io');
                }
                try {
                    if (!@chmod($temporary, 0600) || @file_put_contents($temporary, $json) !== strlen($json)
                        || !@rename($temporary, $path)) {
                        throw new StorageException('Cannot commit security state.', 'storage.io');
                    }
                } finally {
                    if (file_exists($temporary)) {
                        @unlink($temporary);
                    }
                }
            }
            return $change->result();
        });
    }

    /** Compatibility helper: one bounded batch, not an unbounded directory walk. */
    public function prune(int $limit = 1000): int
    {
        return $this->pruneBatch($limit)->removed();
    }

    /** Repeat on the SAME instance until complete(); no global cursor file or lock-file deletion. */
    public function pruneBatch(int $limit = 1000): PruneResult
    {
        if ($limit < 1 || $limit > 10000) {
            throw new \SoSecurity\Exception\ConfigurationException('Prune batch must contain 1-10000 directory entries.');
        }
        if ($this->pruneIterator === null) {
            try { $this->pruneIterator = new \DirectoryIterator($this->directory); }
            catch (\UnexpectedValueException $e) { throw new StorageException('Cannot scan security storage.', 'storage.io', $e); }
        }
        $removed = 0;
        $scanned = 0;
        while ($this->pruneIterator->valid() && $scanned < $limit) {
            $filename = $this->pruneIterator->getFilename();
            $path = $this->pruneIterator->getPathname();
            $this->pruneIterator->next();
            ++$scanned;
            if (!preg_match('/^([a-f0-9]{64})\.json$/D', $filename, $matches)) { continue; }
            $removed += $this->locked($matches[1], function () use ($path) {
                if (is_link($path)) { throw new StorageException('Symlinks are forbidden in security storage.', 'storage.corrupt'); }
                if (!file_exists($path)) { return 0; }
                $raw = @file_get_contents($path, false, null, 0, 65537);
                if ($raw === false) { throw new StorageException('Cannot read security state.', 'storage.io'); }
                if (Codec::decode($raw, $this->clock->now()) === null) {
                    if (!@unlink($path)) { throw new StorageException('Cannot prune security state.', 'storage.io'); }
                    return 1;
                }
                return 0;
            });
        }
        $complete = !$this->pruneIterator->valid();
        if ($complete) { $this->pruneIterator = null; }
        return new PruneResult($removed, $scanned, $complete);
    }

    private function locked(string $hash, callable $operation)
    {
        // 64 permanent lock stripes bound lock-file growth, even with attacker-chosen keys.
        $path = $this->directory . '/lock-' . (hexdec(substr($hash, 0, 2)) % 64);
        if (is_link($path)) {
            throw new StorageException('Symlinks are forbidden in security storage.');
        }
        $handle = @fopen($path, 'c');
        if ($handle === false) {
            throw new StorageException('Cannot open security lock.', 'storage.io');
        }
        try {
            if (!@chmod($path, 0600)) { throw new StorageException('Cannot secure lock permissions.', 'storage.io'); }
            $deadline = new Deadline($this->lockTimeoutMs);
            while (!@flock($handle, LOCK_EX | LOCK_NB, $wouldBlock)) {
                if (!$wouldBlock) { throw new StorageException('Cannot acquire security lock.', 'storage.io'); }
                $deadline->check('storage.lock_timeout');
                usleep((int) min(1000, max(1, $deadline->remaining() * 1000000)));
            }
            $deadline->check('storage.lock_timeout');
            return $operation();
        } finally {
            @flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
