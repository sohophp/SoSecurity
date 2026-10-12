<?php
declare(strict_types=1);
namespace SoSecurity\Upload;

use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;

/** Reads bounded local regular files; never trusts Content-Type or changes the source file. */
final class Validator
{
    private $policy;
    private $finfo;
    private $temporaryDirectory;
    public function __construct(?Policy $policy = null, ?string $temporaryDirectory = null)
    {
        if (!extension_loaded('fileinfo')) { throw new DependencyException('Upload inspection requires ext-fileinfo.', 'dependency.fileinfo'); }
        $this->policy = $policy ?? new Policy();
        try { $this->finfo = @new \finfo(FILEINFO_MIME_TYPE); }
        catch (\Throwable $e) { throw new DependencyException('MIME inspection could not initialize.', 'dependency.fileinfo', $e); }
        $this->temporaryDirectory = $temporaryDirectory === null ? null : $this->privateTemporaryDirectory($temporaryDirectory);
    }
    /** Returns a copy; Saver supplies its already checked private directory for legacy WebP decoding. */
    public function withTemporaryDirectory(string $directory): self
    {
        $copy = clone $this; $copy->temporaryDirectory = $this->privateTemporaryDirectory($directory); return $copy;
    }
    private function privateTemporaryDirectory(string $directory): string
    {
        $real = realpath($directory);
        if ($real === false || !is_dir($real) || !is_writable($real) || (fileperms($real) & 0077) !== 0) {
            throw new \SoSecurity\Exception\ConfigurationException('Use a private writable temporary directory.', 'configuration.upload_temporary');
        }
        return $real;
    }
    public function policy(): Policy { return $this->policy; }
    public function inspectUpload(array $file): Candidate
    {
        foreach (['error', 'size', 'name', 'tmp_name'] as $key) { if (!array_key_exists($key, $file)) { throw new ValidationException('Malformed upload metadata.', 'upload.request'); } }
        if (!is_int($file['error']) || !is_int($file['size']) || !is_string($file['name']) || !is_string($file['tmp_name'])
            || (isset($file['type']) && !is_string($file['type']))) { throw new ValidationException('Only a single native upload is supported.', 'upload.request'); }
        switch ($file['error']) {
            case UPLOAD_ERR_OK: break;
            case UPLOAD_ERR_INI_SIZE: case UPLOAD_ERR_FORM_SIZE: throw new ValidationException('Upload exceeds request limit.', 'upload.too_large');
            case UPLOAD_ERR_PARTIAL: throw new ValidationException('Partial uploads are rejected.', 'upload.partial');
            case UPLOAD_ERR_NO_FILE: throw new ValidationException('No file was uploaded.', 'upload.no_file');
            case UPLOAD_ERR_NO_TMP_DIR: case UPLOAD_ERR_CANT_WRITE: throw new StorageException('Upload temporary storage failed.', 'upload.temporary');
            default: throw new ValidationException('Upload was rejected by the runtime.', 'upload.request');
        }
        if (!is_uploaded_file($file['tmp_name'])) { throw new ValidationException('A native HTTP upload is required.', 'upload.not_uploaded'); }
        return $this->prepare($file['tmp_name'], $file['name'], $file['size']);
    }
    /** File-manager adapter: path MUST come from authorized trusted host code, never arbitrary request parameters. */
    public function inspectFile(string $path, string $name): Candidate { return $this->prepare($path, $name, null); }
    private function prepare(string $path, string $name, ?int $expectedSize): Candidate
    {
        $extension = $this->extension($name); $expectedMime = $this->policy->mime($extension);
        if ($expectedMime === null) { throw new ValidationException('Filename extension is not allowed.', 'upload.extension'); }
        $contents = $this->read($path); $sourceBytes = strlen($contents);
        if ($expectedSize !== null && $expectedSize !== $sourceBytes) { throw new ValidationException('Upload size metadata disagrees.', 'upload.size_mismatch'); }
        $mime = $this->detect($contents);
        if ($mime !== $expectedMime) { throw new ValidationException('Detected MIME and extension disagree.', 'upload.mime'); }
        $width = null; $height = null;
        if (strpos($mime, 'image/') === 0) {
            list($contents, $width, $height) = $this->image($contents, $mime);
            if ($this->detect($contents) !== $mime) { throw new ValidationException('Reencoded image type disagrees.', 'upload.image'); }
        } elseif ($mime === 'text/plain') {
            if (!preg_match('//u', $contents) || preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', $contents)) {
                throw new ValidationException('Text requires UTF-8 without binary controls.', 'upload.text');
            }
        } elseif (!preg_match('/\A%PDF-(?:1\.[0-7]|2\.0)(?:\r|\n)/', $contents) || !preg_match('/%%EOF\s*\z/', substr($contents, -1024))) {
            throw new ValidationException('PDF envelope is invalid.', 'upload.document');
        }
        return new Candidate($contents, $mime, $extension === 'jpeg' ? 'jpg' : $extension, $sourceBytes, $width, $height);
    }
    private function detect(string $contents): string
    {
        try { $mime = @$this->finfo->buffer($contents); }
        catch (\Throwable $e) { throw new SecurityException('MIME inspection failed.', 'upload.inspection', $e); }
        if (!is_string($mime) || $mime === '') { throw new SecurityException('MIME inspection failed.', 'upload.inspection'); }
        return $mime;
    }
    private function extension(string $name): string
    {
        if ($name === '' || strlen($name) > 200 || !preg_match('//u', $name) || preg_match('/\p{C}/u', $name)
            || strpbrk($name, '/\\:%?*"<>|;') !== false || $name[0] === '.' || rtrim($name, '. ') !== $name
            || preg_match('/(?:^|\.)(?:php\d*|phtml|phar|htaccess|htpasswd|asp[x]?|jsp|cgi|pl|sh|bat|cmd|exe|dll)(?:\.|$)/iD', $name)
            || preg_match('/\A(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iD', $name)) {
            throw new ValidationException('Unsafe original filename.', 'upload.filename');
        }
        $position = strrpos($name, '.');
        if ($position === false || $position === 0) { throw new ValidationException('An allowed extension is required.', 'upload.extension'); }
        return strtolower(substr($name, $position + 1));
    }
    private function read(string $path): string
    {
        if ($path === '' || strlen($path) > 4096 || preg_match('/[\x00-\x1f\x7f]/', $path)
            || ($path[0] !== '/' && !preg_match('/\A[A-Za-z]:[\\\\\/]/', $path))) {
            throw new ValidationException('Use a trusted absolute local path.', 'upload.source');
        }
        clearstatcache(true, $path); $before = @lstat($path);
        if (!is_array($before) || ($before['mode'] & 0170000) !== 0100000 || is_link($path)) { throw new ValidationException('Only local regular files are accepted.', 'upload.source'); }
        if ($before['size'] < 1) { throw new ValidationException('Empty files are rejected.', 'upload.empty'); }
        if ($before['size'] > $this->policy->maximumBytes()) { throw new ValidationException('Upload exceeds byte limit.', 'upload.too_large'); }
        $reading = $before['size'] * 3 + 1048576; $memory = $this->memoryLimit();
        if ($reading > $this->policy->workingBytes() || ($memory !== null && memory_get_usage(true) + $reading > $memory)) {
            throw new ValidationException('Input exceeds estimated reading budget.', 'upload.memory_budget');
        }
        $handle = @fopen($path, 'rb');
        if ($handle === false) { throw new StorageException('Cannot read upload source.', 'upload.io'); }
        try {
            $opened = fstat($handle);
            if (!is_array($opened) || ($opened['mode'] & 0170000) !== 0100000 || $opened['ino'] !== $before['ino'] || $opened['dev'] !== $before['dev']) {
                throw new ValidationException('Source changed while opening.', 'upload.source');
            }
            $contents = @stream_get_contents($handle, $this->policy->maximumBytes() + 1);
            if ($contents === false) { throw new StorageException('Cannot read upload source.', 'upload.io'); }
            $after = fstat($handle);
            if (strlen($contents) > $this->policy->maximumBytes()) { throw new ValidationException('Upload exceeds byte limit.', 'upload.too_large'); }
            if (strlen($contents) !== $opened['size'] || !is_array($after) || $after['size'] !== $opened['size'] || $after['mtime'] !== $opened['mtime']) {
                throw new ValidationException('Source changed while reading.', 'upload.source');
            }
            return $contents;
        } finally { fclose($handle); }
    }
    private function image(string $contents, string $mime): array
    {
        if (!extension_loaded('gd')) { throw new DependencyException('Image uploads require ext-gd decode and reencoding.', 'dependency.gd'); }
        $info = @getimagesizefromstring($contents);
        if (!is_array($info) || $info['mime'] !== $mime || $info[0] < 1 || $info[1] < 1) {
            throw new ValidationException('Image header is invalid.', 'upload.image');
        }
        $width = $info[0]; $height = $info[1]; $pixels = $width * $height;
        $working = $pixels * 16 + strlen($contents) * 2 + 8388608;
        $memory = $this->memoryLimit();
        if ($width > $this->policy->maximumWidth() || $height > $this->policy->maximumHeight() || $pixels > $this->policy->maximumPixels()
            || $working > $this->policy->workingBytes() || ($memory !== null && memory_get_usage(true) + $working > $memory)) {
            throw new ValidationException('Image exceeds geometry or estimated working budget.', 'upload.image_budget');
        }
        if ($mime === 'image/webp' && (!function_exists('imagewebp') || !(imagetypes() & IMG_WEBP))) { throw new DependencyException('GD WebP encoding is unavailable.', 'dependency.gd_webp'); }
        $image = $mime === 'image/webp' && PHP_VERSION_ID < 70300 ? $this->legacyWebp($contents) : @imagecreatefromstring($contents);
        if ($image === false) { throw new ValidationException('Image cannot be decoded.', 'upload.image'); }
        try {
            if (imagesx($image) !== $width || imagesy($image) !== $height) { throw new ValidationException('Decoded dimensions disagree.', 'upload.image'); }
            imagealphablending($image, false); imagesavealpha($image, true);
            $encoded = ''; $oversized = false; $maximum = $this->policy->maximumBytes();
            $level = ob_get_level();
            if (!ob_start(function (string $chunk) use (&$encoded, &$oversized, $maximum) {
                if (!$oversized && strlen($encoded) + strlen($chunk) <= $maximum) { $encoded .= $chunk; }
                else { $oversized = true; }
                return '';
            }, 8192)) { throw new StorageException('Cannot isolate image encoding output.', 'upload.processing'); }
            try {
                switch ($mime) {
                    case 'image/jpeg': $ok = @imagejpeg($image, null, $this->policy->jpegQuality()); break;
                    case 'image/png': $ok = @imagepng($image, null, 6); break;
                    default: $ok = @imagewebp($image, null, $this->policy->jpegQuality());
                }
            } finally { while (ob_get_level() > $level) { ob_end_flush(); } }
            if ($oversized) { throw new ValidationException('Reencoded image exceeds byte limit.', 'upload.too_large'); }
            if (!$ok || $encoded === '') { throw new ValidationException('Image encoding failed.', 'upload.image'); }
            return [$encoded, $width, $height];
        } finally { if (is_resource($image)) { imagedestroy($image); } }
    }
    private function legacyWebp(string $contents)
    {
        if (!function_exists('imagecreatefromwebp')) { throw new DependencyException('GD WebP decoder is unavailable.', 'dependency.gd_webp'); }
        if ($this->temporaryDirectory === null) { throw new DependencyException('PHP 7.2 standalone WebP inspection needs a private temporary directory.', 'dependency.webp_temporary_directory'); }
        $path = $this->temporaryDirectory . DIRECTORY_SEPARATOR . '.decode-' . bin2hex(random_bytes(16));
        $handle = @fopen($path, 'x+b');
        if ($handle === false) { throw new StorageException('Cannot allocate private decoder input.', 'upload.io'); }
        try {
            if (!@chmod($path, 0600)) { throw new StorageException('Cannot protect decoder input.', 'upload.io'); }
            $offset = 0; $length = strlen($contents);
            while ($offset < $length) {
                $written = @fwrite($handle, substr($contents, $offset));
                if ($written === false || $written === 0) { throw new StorageException('Cannot write decoder input.', 'upload.io'); }
                $offset += $written;
            }
            if (!@fflush($handle) || !@fclose($handle)) { throw new StorageException('Cannot finish decoder input.', 'upload.io'); }
            return @imagecreatefromwebp($path);
        } finally {
            if (is_resource($handle)) { @fclose($handle); }
            if (!@unlink($path)) { throw new StorageException('Cannot remove private decoder input.', 'upload.cleanup'); }
        }
    }
    private function memoryLimit(): ?int
    {
        $limit = trim((string) ini_get('memory_limit'));
        if ($limit === '-1') { return null; }
        if (!preg_match('/\A([0-9]+)\s*([KMG]?)\z/i', $limit, $matches)) { return 0; }
        $factor = ['' => 1, 'K' => 1024, 'M' => 1048576, 'G' => 1073741824][strtoupper($matches[2])];
        $value = (float) $matches[1] * $factor;
        return $value > PHP_INT_MAX ? PHP_INT_MAX : (int) $value;
    }
}
