<?php
declare(strict_types=1);

namespace SoSecurity\Storage;

use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Local filesystem only. Private directory must be owned by the application, outside web root. */
final class FileStore implements AtomicStore
{
    private $directory;
    private $namespace;
    private $clock;

    public function __construct(string $directory, string $namespace, ?Clock $clock = null)
    {
        Guard::label($namespace);
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
                    throw new StorageException('Cannot read security state.');
                }
                $value = Codec::decode($raw, $this->clock->now());
            }
            $change = $callback($value);
            if (!$change instanceof Change) {
                throw new StorageException('Callback must return Change.');
            }
            if ($change->value === null) {
                if (file_exists($path) && !@unlink($path)) {
                    throw new StorageException('Cannot delete security state.');
                }
            } else {
                $json = Codec::encode($change);
                $temporary = @tempnam($this->directory, '.write-');
                if ($temporary === false) {
                    throw new StorageException('Cannot allocate security state.');
                }
                try {
                    if (!@chmod($temporary, 0600) || @file_put_contents($temporary, $json) !== strlen($json)
                        || !@rename($temporary, $path)) {
                        throw new StorageException('Cannot commit security state.');
                    }
                } finally {
                    if (file_exists($temporary)) {
                        @unlink($temporary);
                    }
                }
            }
            return $change->result;
        });
    }

    /** Schedule cleanup; locks remain stable to prevent deletion/recreation races. */
    public function prune(): int
    {
        $count = 0;
        foreach (new \DirectoryIterator($this->directory) as $entry) {
            if (!preg_match('/^([a-f0-9]{64})\.json$/D', $entry->getFilename(), $matches)) {
                continue;
            }
            $count += $this->locked($matches[1], function () use ($entry) {
                $path = $entry->getPathname();
                if (!file_exists($path)) {
                    return 0;
                }
                if (is_link($path)) {
                    throw new StorageException('Symlinks are forbidden in security storage.');
                }
                $raw = @file_get_contents($path, false, null, 0, 65537);
                if ($raw === false) {
                    throw new StorageException('Cannot read security state.');
                }
                if (Codec::decode($raw, $this->clock->now()) === null) {
                    if (!@unlink($path)) {
                        throw new StorageException('Cannot prune security state.');
                    }
                    return 1;
                }
                return 0;
            });
        }
        return $count;
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
            throw new StorageException('Cannot open security lock.');
        }
        try {
            if (!@chmod($path, 0600) || !@flock($handle, LOCK_EX)) {
                throw new StorageException('Cannot acquire security lock.');
            }
            return $operation();
        } finally {
            @flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
