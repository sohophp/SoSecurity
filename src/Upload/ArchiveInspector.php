<?php
declare(strict_types=1);
namespace SoSecurity\Upload;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Support\Deadline;
use SoSecurity\Storage\StorageException;

/** Optional read-only ZIP preflight. Never extracts or calls host business code. */
final class ArchiveInspector
{
    private $limits;

    public function __construct(array $limits = [])
    {
        $defaults = [
            'archive_bytes' => 16777216,
            'entries' => 100,
            'path_bytes' => 1024,
            'depth' => 8,
            'entry_bytes' => 4194304,
            'total_bytes' => 33554432,
            'ratio' => 100,
            'milliseconds' => 10000,
        ];
        foreach ($limits as $key => $value) {
            if (!array_key_exists($key, $defaults) || !is_int($value) || $value < 1 || $value > $defaults[$key]) {
                throw new ConfigurationException('Use bounded ZIP inspection limits.', 'configuration.archive');
            }
        }
        $this->limits = array_replace($defaults, $limits);
    }

    private function reject(string $message): void
    {
        throw new ValidationException($message, 'upload.archive');
    }

    private function budget(): Deadline
    {
        try { return new Deadline($this->limits['milliseconds']); }
        catch (StorageException $error) { throw new ValidationException('ZIP inspection clock unavailable.', 'upload.archive'); }
    }

    private function check(Deadline $deadline): void
    {
        try { $deadline->check('upload.archive'); }
        catch (StorageException $error) { $this->reject('ZIP inspection deadline expired or clock unavailable.'); }
    }

    /** Keep runtime guards even when an extension or I/O stub claims a narrower return type. */
    private static function actualString($value): bool { return is_string($value); }
    private static function actualInteger($value): bool { return is_int($value); }
    private static function validStat($value): bool
    {
        if (!is_array($value)) { return false; }
        foreach (['name', 'size', 'comp_size', 'crc'] as $field) {
            if (!array_key_exists($field, $value)) { return false; }
        }
        return self::actualString($value['name']) && self::actualInteger($value['size'])
            && self::actualInteger($value['comp_size']) && self::actualInteger($value['crc'])
            && $value['size'] >= 0 && $value['comp_size'] >= 0;
    }

    private function name(string $name): array
    {
        $maximum = $this->limits['path_bytes'];
        if ($name === '' || strlen($name) > $maximum || strpos($name, "\0") !== false
            || strpos($name, '\\') !== false || $name[0] === '/' || strpos($name, ':') !== false) {
            $this->reject('Unsafe ZIP entry path.');
        }
        $directory = substr($name, -1) === '/';
        $path = $directory ? substr($name, 0, -1) : $name;
        $parts = explode('/', $path);
        if ($path === '' || count($parts) > $this->limits['depth']) {
            $this->reject('ZIP entry path exceeds its depth.');
        }
        foreach ($parts as $part) {
            if ($part === '' || $part === '.' || $part === '..'
                || $part[0] === '.' || substr($part, -1) === '.'
                || strlen($part) > 128 || preg_match('/\A[A-Za-z0-9._-]+\z/D', $part) !== 1
                || preg_match('/\A(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|\z)/iD', $part)) {
                $this->reject('Unsafe ZIP entry path segment.');
            }
        }
        if (!$directory && preg_match('/\.(?:zip|tar|tgz|gz|bz2|xz|7z|rar)\z/iD', $path)) {
            $this->reject('Nested archive is not accepted.');
        }
        return [$path, $directory];
    }

    private function ordinary(\ZipArchive $zip, int $index, bool $directory): void
    {
        $opsys = 0;
        $attributes = 0;
        if (!$zip->getExternalAttributesIndex($index, $opsys, $attributes)) {
            $this->reject('ZIP entry attributes are missing.');
        }
        if ($opsys === \ZipArchive::OPSYS_UNIX) {
            $kind = ($attributes >> 16) & 0170000;
            if ($kind !== 0 && $kind !== ($directory ? 0040000 : 0100000)) {
                $this->reject('ZIP links and special entries are not accepted.');
            }
        }
    }

    private function nested(string $prefix): bool
    {
        return substr($prefix, 0, 4) === "PK\x03\x04"
            || substr($prefix, 0, 4) === "PK\x05\x06"
            || substr($prefix, 0, 2) === "\x1f\x8b"
            || substr($prefix, 0, 3) === 'BZh'
            || substr($prefix, 0, 6) === "\xfd7zXZ\x00"
            || substr($prefix, 0, 6) === "7z\xbc\xaf\x27\x1c"
            || substr($prefix, 0, 7) === "Rar!\x1a\x07"
            || substr($prefix, 257, 5) === 'ustar';
    }

    /** Reject large/ambiguous central directories before libzip allocates entry records. */
    private function preflight(string $path, int $size, Deadline $deadline): array
    {
        $this->check($deadline);
        $stream = @fopen($path, 'rb');
        if (!is_resource($stream)) {
            $this->reject('ZIP file cannot be read.');
        }
        try {
            $tailSize = min($size, 65557);
            if (@fseek($stream, $size - $tailSize) !== 0) {
                $this->reject('ZIP directory cannot be located.');
            }
            $tail = @fread($stream, $tailSize);
            if (!self::actualString($tail) || strlen($tail) !== $tailSize) {
                $this->reject('ZIP directory cannot be read.');
            }
            $found = null;
            $this->check($deadline);
            for ($index = $tailSize - 22; $index >= 0; --$index) {
                if (($index & 255) === 0) { $this->check($deadline); }
                if (substr($tail, $index, 4) !== "PK\x05\x06") {
                    continue;
                }
                $end = unpack('vdisk/vstart/ventries_disk/ventries/Vsize/Voffset/vcomment', substr($tail, $index + 4, 18));
                if ($end['comment'] === $tailSize - $index - 22) {
                    $found = [$end, $size - $tailSize + $index];
                    break;
                }
            }
            if ($found === null) {
                $this->reject('ZIP end directory is missing.');
            }
            list($end, $endOffset) = $found;
            if ($end['disk'] !== 0 || $end['start'] !== 0 || $end['entries_disk'] !== $end['entries']
                || $end['entries'] < 1 || $end['entries'] > $this->limits['entries']
                || $end['size'] < $end['entries'] * 46
                || $end['size'] > $end['entries'] * (46 + $this->limits['path_bytes'] + 2048)
                || $end['offset'] > $endOffset || $end['size'] !== $endOffset - $end['offset']) {
                $this->reject('ZIP central directory exceeds its limit or uses an unsupported format.');
            }
            if (@fseek($stream, $end['offset']) !== 0) {
                $this->reject('ZIP central directory cannot be read.');
            }
            $directoryEnd = $end['offset'] + $end['size'];
            $names = [];
            $locals = [];
            for ($index = 0; $index < $end['entries']; ++$index) {
                $this->check($deadline);
                $position = ftell($stream);
                if (!is_int($position) || $position > $directoryEnd - 46) {
                    $this->reject('ZIP central directory is truncated.');
                }
                $header = @fread($stream, 46);
                if (!self::actualString($header) || strlen($header) !== 46 || substr($header, 0, 4) !== "PK\x01\x02") {
                    $this->reject('ZIP central directory entry is invalid.');
                }
                $lengths = unpack('vname/vextra/vcomment', substr($header, 28, 6));
                $suffix = $lengths['extra'] + $lengths['comment'];
                if ($lengths['name'] < 1 || $lengths['name'] > $this->limits['path_bytes']
                    || $lengths['extra'] > 1024 || $lengths['comment'] > 1024
                    || $lengths['name'] + $suffix > $directoryEnd - ($position + 46)) {
                    $this->reject('ZIP central directory entry exceeds its boundary.');
                }
                $name = @fread($stream, $lengths['name']);
                if (!self::actualString($name) || strlen($name) !== $lengths['name']
                    || @fseek($stream, $suffix, SEEK_CUR) !== 0) {
                    $this->reject('ZIP central directory name cannot be read.');
                }
                $this->name($name);
                $names[] = $name;
                $local = unpack('Voffset', substr($header, 42, 4))['offset'];
                if ($local >= $end['offset'] || isset($locals[$local])) {
                    $this->reject('ZIP local entry offset is invalid or repeated.');
                }
                $locals[$local] = $name;
            }
            if (ftell($stream) !== $directoryEnd) {
                $this->reject('ZIP central directory contains extra entries.');
            }
            foreach ($locals as $offset => $name) {
                $this->check($deadline);
                if (@fseek($stream, $offset) !== 0) {
                    $this->reject('ZIP local entry cannot be located.');
                }
                $header = @fread($stream, 30);
                if (!self::actualString($header) || strlen($header) !== 30 || substr($header, 0, 4) !== "PK\x03\x04") {
                    $this->reject('ZIP local entry header is invalid.');
                }
                $lengths = unpack('vname/vextra', substr($header, 26, 4));
                if ($lengths['name'] !== strlen($name) || $lengths['extra'] > 1024
                    || $offset + 30 + $lengths['name'] + $lengths['extra'] > $end['offset']) {
                    $this->reject('ZIP local entry name is invalid.');
                }
                $localName = @fread($stream, $lengths['name']);
                if (!self::actualString($localName) || $localName !== $name) {
                    $this->reject('ZIP local and central names differ.');
                }
            }
            $this->check($deadline);
            return $names;
        } finally {
            fclose($stream);
        }
    }

    private function contents(\ZipArchive $zip, string $name, int $size, int $crc, Deadline $deadline): void
    {
        $stream = @$zip->getStream($name);
        if (!is_resource($stream)) {
            $this->reject('ZIP entry could not be read.');
        }
        $length = 0;
        $prefix = '';
        $checksum = hash_init('crc32b');
        try {
            while (!feof($stream)) {
                $this->check($deadline);
                $remaining = $size - $length;
                $chunk = @fread($stream, min(8192, $remaining + 1));
                if (!self::actualString($chunk) || $chunk === '') {
                    if (!feof($stream)) {
                        $this->reject('ZIP entry read failed.');
                    }
                    break;
                }
                $length += strlen($chunk);
                if ($length > $size) {
                    $this->reject('ZIP entry exceeds its declared size.');
                }
                if (strlen($prefix) < 512) {
                    $prefix .= substr($chunk, 0, 512 - strlen($prefix));
                }
                hash_update($checksum, $chunk);
            }
        } finally {
            fclose($stream);
        }
        $this->check($deadline);
        if ($length !== $size || hash_final($checksum) !== sprintf('%08x', $crc & 0xffffffff)
            || $this->nested($prefix)) {
            $this->reject('ZIP entry content does not match its metadata or contains an archive.');
        }
    }

    public function inspect(string $path): array
    {
        if (!class_exists(\ZipArchive::class)) {
            throw new DependencyException('ZIP extension is required.', 'dependency.archive');
        }
        if ($path === '' || strlen($path) > 4096 || strpos($path, "\0") !== false
            || strpos($path, '://') !== false) {
            $this->reject('Use a local ZIP file path.');
        }
        $deadline = $this->budget();
        clearstatcache(true, $path);
        $source = @lstat($path);
        if (!is_array($source) || ($source['mode'] & 0170000) !== 0100000
            || $source['nlink'] !== 1 || $source['size'] < 1 || $source['size'] > $this->limits['archive_bytes']) {
            $this->reject('Use a bounded private regular ZIP file.');
        }
        $this->check($deadline);
        $digest = @hash_file('sha256', $path);
        $this->check($deadline);
        if (!is_string($digest)) {
            $this->reject('ZIP file cannot be read.');
        }
        $expectedNames = $this->preflight($path, $source['size'], $deadline);
        $this->check($deadline);
        $zip = new \ZipArchive();
        if ($zip->open($path, \ZipArchive::CHECKCONS) !== true) {
            $this->reject('Invalid ZIP archive.');
        }
        $entries = [];
        $seen = [];
        $total = 0;
        try {
            $this->check($deadline);
            $count = $zip->numFiles;
            if (!self::actualInteger($count) || $count !== count($expectedNames) || $count < 1 || $count > $this->limits['entries']) {
                $this->reject('ZIP entry count exceeds its limit.');
            }
            for ($index = 0; $index < $count; ++$index) {
                $this->check($deadline);
                $stat = $zip->statIndex($index);
                if (!self::validStat($stat)) {
                    $this->reject('ZIP entry metadata is invalid.');
                }
                if ($stat['name'] !== $expectedNames[$index]) {
                    $this->reject('ZIP entry name differs between directory readers.');
                }
                list($name, $directory) = $this->name($stat['name']);
                $key = strtolower($name);
                if (isset($seen[$key])) {
                    $this->reject('ZIP entry path is repeated.');
                }
                $seen[$key] = $directory ? 'directory' : 'file';
                $this->ordinary($zip, $index, $directory);
                if ($directory) {
                    if ($stat['size'] !== 0) {
                        $this->reject('ZIP directory has content.');
                    }
                } else {
                    $size = $stat['size'];
                    if ($size > $this->limits['entry_bytes']
                        || $size > $this->limits['total_bytes'] - $total
                        || $size / max(1, $stat['comp_size']) > $this->limits['ratio']) {
                        $this->reject('ZIP expansion exceeds its budget.');
                    }
                    $total += $size;
                    $this->contents($zip, $stat['name'], $size, $stat['crc'], $deadline);
                }
                $entries[] = ['path' => $name, 'directory' => $directory, 'bytes' => $stat['size']];
            }
            foreach ($seen as $pathName => $kind) {
                $parts = explode('/', $pathName);
                array_pop($parts);
                while ($parts !== []) {
                    $parent = implode('/', $parts);
                    if (isset($seen[$parent]) && $seen[$parent] === 'file') {
                        $this->reject('ZIP file conflicts with a descendant path.');
                    }
                    array_pop($parts);
                }
            }
        } finally {
            $zip->close();
        }
        clearstatcache(true, $path);
        $after = @lstat($path);
        if (!is_array($after) || $after['dev'] !== $source['dev'] || $after['ino'] !== $source['ino']
            || $after['size'] !== $source['size'] || @hash_file('sha256', $path) !== $digest) {
            $this->reject('ZIP source changed during inspection.');
        }
        $this->check($deadline);
        return ['sha256' => $digest, 'entries' => $entries, 'uncompressed_bytes' => $total];
    }
}
