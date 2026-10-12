<?php
declare(strict_types=1);
namespace SoSecurity\Upload;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;

/** Exclusive random names in a private directory, validated content snapshot, no source deletion or public serving. */
final class Saver
{
    private $validator;
    private $directory;
    private $scanner;
    public function __construct(Validator $validator, string $directory, string $documentRoot, ?Scanner $scanner = null)
    {
        $root = realpath($documentRoot); $real = realpath($directory);
        if ($root === false || !is_dir($root)) { throw new ConfigurationException('Provide the actual existing Web root.', 'configuration.document_root'); }
        if ($real === false || !is_dir($real) || !is_writable($real) || (fileperms($real) & 0077) !== 0) { throw new StorageException('Use an existing private writable 0700 upload directory.', 'upload.directory'); }
        $prefix = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (DIRECTORY_SEPARATOR === '\\') { $root = strtolower($root); $real = strtolower($real); $prefix = strtolower($prefix); }
        if ($real === $root || strpos($real, $prefix) === 0) { throw new ConfigurationException('Upload directory must be outside the Web root.', 'configuration.web_root'); }
        if ($validator->policy()->requiresScan() && $scanner === null) { throw new ConfigurationException('Upload policy requires a scanner adapter.', 'configuration.scanner'); }
        $this->validator = $validator->withTemporaryDirectory($real); $this->directory = $real; $this->scanner = $scanner;
    }
    public function saveUpload(array $file): StoredFile { return $this->save($this->validator->inspectUpload($file)); }
    /** Existing file-manager integration owns source authorization and quotas; this copies, never moves its source. */
    public function saveFile(string $trustedPath, string $originalName): StoredFile { return $this->save($this->validator->inspectFile($trustedPath, $originalName)); }
    private function save(Candidate $candidate): StoredFile
    {
        $scanned = false;
        if ($this->scanner !== null) {
            try { $scanned = $this->scanner->scan($candidate); }
            catch (\Throwable $e) { throw new SecurityException('Upload scanner failed.', 'upload.scan_failed', $e); }
            if (!$scanned) { throw new ValidationException('Upload scanner rejected content.', 'upload.scan_rejected'); }
        }
        for ($attempt = 0; $attempt < 4; ++$attempt) {
            $path = $this->directory . DIRECTORY_SEPARATOR . bin2hex(random_bytes(16)) . '.' . $candidate->extension();
            $handle = @fopen($path, 'x+b');
            if ($handle === false) {
                if (file_exists($path) || is_link($path)) { continue; }
                throw new StorageException('Cannot allocate a private upload.', 'upload.io');
            }
            $complete = false;
            try {
                if (!@chmod($path, 0600)) { throw new StorageException('Cannot protect upload permissions.', 'upload.io'); }
                $contents = $candidate->contents(); $offset = 0; $length = strlen($contents);
                while ($offset < $length) {
                    $written = @fwrite($handle, substr($contents, $offset));
                    if ($written === false || $written === 0) { throw new StorageException('Cannot complete upload write.', 'upload.io'); }
                    $offset += $written;
                }
                if (!@fflush($handle)) { throw new StorageException('Cannot flush upload write.', 'upload.io'); }
                $stat = fstat($handle);
                if (!is_array($stat) || $stat['size'] !== $length) { throw new StorageException('Stored upload size disagrees.', 'upload.io'); }
                if (!@fclose($handle)) { throw new StorageException('Cannot close upload write.', 'upload.io'); }
                $complete = true;
            } finally {
                if (is_resource($handle)) { @fclose($handle); }
                if (!$complete && !@unlink($path)) { throw new StorageException('Cannot remove incomplete private upload.', 'upload.cleanup'); }
            }
            return new StoredFile($path, $candidate, $scanned);
        }
        throw new StorageException('Upload name allocation exhausted.', 'upload.contention');
    }
}
