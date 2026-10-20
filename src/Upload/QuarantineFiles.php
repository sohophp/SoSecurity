<?php
declare(strict_types=1);
namespace SoSecurity\Upload;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;

/** Internal local spool. All operations are outside AtomicStore callbacks. */
final class QuarantineFiles
{
    private $location;
    private $binding;
    private $policy;
    public function __construct(string $directory, string $documentRoot, Policy $policy)
    {
        $web = realpath($documentRoot); $real = realpath($directory);
        if ($web === false || !is_dir($web) || $real === false || $real !== $directory || !is_writable($real)) {
            throw new ConfigurationException('Use existing canonical private spool and Web root.', 'configuration.quarantine');
        }
        $prefix = rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        $comparison = DIRECTORY_SEPARATOR === '\\' ? strtolower($real) : $real;
        if ($comparison === (DIRECTORY_SEPARATOR === '\\' ? strtolower($web) : $web)
            || strpos($comparison, DIRECTORY_SEPARATOR === '\\' ? strtolower($prefix) : $prefix) === 0) {
            throw new ConfigurationException('Quarantine must be outside the Web root.', 'configuration.web_root');
        }
        $identity = self::directory($real);
        $this->binding = hash('sha256', base64_encode($real) . ':' . implode(':', $identity));
        $this->location = static function () use ($real, $identity): array { return [$real, $identity]; };
        $this->policy = $policy;
    }
    private static function directory(string $path): array
    {
        clearstatcache(true, $path); $stat = @lstat($path);
        if (!is_array($stat) || ($stat['mode'] & 0170000) !== 0040000 || ($stat['mode'] & 0777) !== 0700 || realpath($path) !== $path) {
            throw new StorageException('Quarantine directory identity or protection changed.', 'upload.quarantine_directory');
        }
        return [$stat['dev'], $stat['ino'], $stat['uid']];
    }
    private function path(string $id, string $extension): string
    {
        QuarantineState::id($id);
        if (QuarantineState::mime($this->policy, $extension) === null) { throw new StorageException('Invalid quarantine file type.', 'upload.quarantine_corrupt'); }
        list($path, $identity) = ($this->location)();
        if (self::directory($path) !== $identity) { throw new StorageException('Quarantine directory changed.', 'upload.quarantine_directory'); }
        return $path . DIRECTORY_SEPARATOR . $id . '.' . $extension;
    }
    public function binding(): string { return $this->binding; }
    public function validator(): Validator { return new Validator($this->policy, ($this->location)()[0]); }
    /** Serialize reservation/write and deletion across processes; the permanent lock file must not be removed. */
    public function locked(callable $operation)
    {
        list($directory, $identity) = ($this->location)();
        if (self::directory($directory) !== $identity) { throw new StorageException('Quarantine directory changed.', 'upload.quarantine_directory'); }
        $path = $directory . DIRECTORY_SEPARATOR . '.quarantine.lock'; clearstatcache(true, $path); $before = @lstat($path);
        if ($before !== false && (($before['mode'] & 0170000) !== 0100000 || ($before['mode'] & 0777) !== 0600 || $before['nlink'] !== 1)) {
            throw new StorageException('Quarantine lock is not protected.', 'upload.quarantine_lock');
        }
        $handle = @fopen($path, $before === false ? 'x+b' : 'r+b');
        if ($handle === false && $before === false) {
            // Another process may have won creation; retry through the checked existing-file path.
            clearstatcache(true, $path); $before = @lstat($path);
            if (is_array($before) && ($before['mode'] & 0170000) === 0100000 && ($before['mode'] & 0777) === 0600 && $before['nlink'] === 1) { $handle = @fopen($path, 'r+b'); }
        }
        if ($handle === false) { throw new StorageException('Cannot open quarantine lock.', 'upload.quarantine_lock'); }
        try {
            if ($before === false && !@chmod($path, 0600)) { throw new StorageException('Cannot protect quarantine lock.', 'upload.quarantine_lock'); }
            $deadline = new Deadline(1000);
            while (!@flock($handle, LOCK_EX | LOCK_NB)) { $deadline->check('upload.quarantine_lock_timeout'); usleep(1000); }
            clearstatcache(true, $path); $current = @lstat($path); $opened = fstat($handle);
            if (!is_array($current) || !is_array($opened) || ($current['mode'] & 0170000) !== 0100000 || ($current['mode'] & 0777) !== 0600
                || $current['nlink'] !== 1 || $current['dev'] !== $opened['dev'] || $current['ino'] !== $opened['ino']
                || ($before !== false && ($before['dev'] !== $opened['dev'] || $before['ino'] !== $opened['ino']))
                || self::directory($directory) !== $identity) { throw new StorageException('Quarantine lock changed.', 'upload.quarantine_lock'); }
            $deadline->check('upload.quarantine_lock_timeout'); return $operation();
        } finally { fclose($handle); }
    }
    public function write(string $id, Candidate $candidate): void
    {
        $path = $this->path($id, $candidate->extension()); $handle = @fopen($path, 'x+b');
        if ($handle === false) { throw new StorageException('Cannot allocate quarantine content.', 'upload.quarantine_io'); }
        $complete = false;
        try {
            if (!@chmod($path, 0600)) { throw new StorageException('Cannot protect quarantine content.', 'upload.quarantine_io'); }
            $contents = $candidate->contents(); $bytes = strlen($contents); $offset = 0;
            while ($offset < $bytes) {
                $written = @fwrite($handle, substr($contents, $offset, 8192));
                if ($written === false || $written === 0) { throw new StorageException('Cannot write quarantine content.', 'upload.quarantine_io'); }
                $offset += $written;
            }
            if (!@fflush($handle) || (function_exists('fsync') && !@fsync($handle))) { throw new StorageException('Cannot flush quarantine content.', 'upload.quarantine_io'); }
            $stat = fstat($handle);
            if (!is_array($stat) || $stat['size'] !== $bytes || ($stat['mode'] & 0170000) !== 0100000 || $stat['nlink'] !== 1) {
                throw new StorageException('Quarantine content disagrees with write.', 'upload.quarantine_io');
            }
            if (!@fclose($handle)) { throw new StorageException('Cannot close quarantine content.', 'upload.quarantine_io'); }
            $this->path($id, $candidate->extension()); $complete = true;
        } finally {
            if (is_resource($handle)) { @fclose($handle); }
            // The reserved staging record survives failures; cleanup never guesses an uncommitted file.
            if (!$complete) { $this->remove($id, $candidate->extension()); }
        }
    }
    public function read(string $id, array $file): Candidate
    {
        $path = $this->path($id, $file['extension']); clearstatcache(true, $path); $before = @lstat($path);
        if (!is_array($before) || ($before['mode'] & 0170000) !== 0100000 || ($before['mode'] & 0777) !== 0600
            || $before['nlink'] !== 1 || $before['size'] !== $file['bytes']) { throw new StorageException('Quarantine content is missing or changed.', 'upload.quarantine_content'); }
        // Validate budget before opening or asking PHP to allocate a read buffer.
        $working = $file['bytes'] * 3 + 1048576; $rawLimit = trim((string) ini_get('memory_limit')); $memory = null;
        if ($rawLimit !== '-1' && preg_match('/\A([0-9]+)\s*([KMG]?)\z/iD', $rawLimit, $parts)) {
            $factors = ['' => 1, 'K' => 1024, 'M' => 1048576, 'G' => 1073741824]; $memory = (float) $parts[1] * $factors[strtoupper($parts[2])];
        }
        if ($working > $this->policy->workingBytes() || ($memory !== null && memory_get_usage(true) + $working > $memory)) {
            throw new StorageException('Quarantine read exceeds memory budget.', 'upload.quarantine_memory');
        }
        $handle = @fopen($path, 'rb');
        if ($handle === false) { throw new StorageException('Cannot read quarantine content.', 'upload.quarantine_io'); }
        try {
            $opened = fstat($handle);
            if (!is_array($opened) || $opened['dev'] !== $before['dev'] || $opened['ino'] !== $before['ino'] || $opened['size'] !== $before['size']
                || ($opened['mode'] & 0170000) !== 0100000 || ($opened['mode'] & 0777) !== 0600 || $opened['nlink'] !== 1) {
                throw new StorageException('Quarantine content changed while opening.', 'upload.quarantine_content');
            }
            $bytes = @stream_get_contents($handle, $file['bytes'] + 1); $after = fstat($handle);
            if (!is_string($bytes) || strlen($bytes) !== $file['bytes'] || !is_array($after) || $after['size'] !== $file['bytes']
                || $after['mtime'] !== $opened['mtime'] || ($after['mode'] & 0777) !== 0600 || $after['nlink'] !== 1
                || !hash_equals($file['sha256'], hash('sha256', $bytes))) {
                throw new StorageException('Quarantine content digest disagrees.', 'upload.quarantine_content');
            }
            $this->path($id, $file['extension']);
            return new Candidate($bytes, $file['mime'], $file['extension'], $file['source_bytes'], $file['width'], $file['height']);
        } finally { fclose($handle); }
    }
    public function remove(string $id, string $extension): void
    {
        $path = $this->path($id, $extension); clearstatcache(true, $path); $stat = @lstat($path);
        if ($stat === false) { return; }
        if (($stat['mode'] & 0170000) !== 0100000 || $stat['nlink'] !== 1 || !@unlink($path)) {
            throw new StorageException('Cannot remove quarantine content safely.', 'upload.quarantine_cleanup');
        }
    }
    public function __debugInfo(): array { return ['quarantine_files' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Rebuild quarantine storage.', 'configuration.upload_serialization'); }
    public function __wakeup(): void { throw new ConfigurationException('Rebuild quarantine storage.', 'configuration.upload_serialization'); }
}
