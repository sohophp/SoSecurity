<?php
declare(strict_types=1);
namespace SoSecurityDemo;

use SoSecurity\Upload\Policy;
use SoSecurity\Upload\Validator;
use SoSecurity\Upload\Saver;
use SoSecurity\Upload\Scanner;
use SoSecurity\Upload\Candidate;
use SoSecurity\Storage\StorageException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Support\Deadline;

/** Bounded private playground. No download route, user paths, executable content or shared-business storage. */
final class UploadSandbox
{
    private $base;
    private $directory;
    private $web;
    public function __construct(string $base, string $web)
    {
        $real = realpath($base);
        if ($real === false || !is_dir($real) || (fileperms($real) & 0077) !== 0) { throw new StorageException('Private playground base required.', 'upload.directory'); }
        $this->base = $real; $this->directory = $real . '/uploads'; $this->web = $web;
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0700)) { throw new StorageException('Cannot create private playground.', 'upload.directory'); }
        if (is_link($this->directory) || (fileperms($this->directory) & 0077) !== 0) { throw new StorageException('Invalid playground permissions.', 'upload.directory'); }
    }
    private function saver(?Scanner $scanner = null): Saver
    {
        return new Saver(new Validator(new Policy(['maximum_bytes' => 1048576, 'maximum_width' => 1600, 'maximum_height' => 1600,
            'maximum_pixels' => 1000000, 'working_bytes' => 33554432])), $this->directory, $this->web, $scanner);
    }
    public function files(): array
    {
        $files = [];
        foreach ($_SESSION['demo_uploaded_files'] ?? [] as $entry) {
            $name = $entry['filename'] ?? null;
            if (is_string($name) && preg_match('/^[a-f0-9]{32}\.(png|jpg)$/D', $name)
                && is_file($this->directory . '/' . $name) && ($entry['expires_at'] ?? 0) > time()) { $files[] = $entry; }
        }
        return $files;
    }
    public function perform(string $action, array $upload = []): array
    {
        return $this->locked(function () use ($action, $upload) {
            list($count, $bytes) = $this->sweep();
            $own = $this->files(); $_SESSION['demo_uploaded_files'] = $own;
            if ($action === 'clear') {
                foreach ($own as $entry) { if (!@unlink($this->directory . '/' . $entry['filename'])) { throw new StorageException('Cannot clear own demo file.', 'upload.io'); } }
                $_SESSION['demo_uploaded_files'] = []; return ['message' => '已清理当前访客的演示文件。'];
            }
            if ($count >= 32 || $bytes + 1048576 > 16777216) { throw new StorageException('Playground capacity reached.', 'upload.demo_capacity'); }
            if (in_array($action, ['upload', 'normal_sample'], true) && count($own) >= 3) { throw new ValidationException('Three files per visitor; clear before retry.', 'upload.demo_quota'); }
            if ($action === 'upload') { $saved = $this->saver()->saveUpload($upload); }
            else {
                $source = tempnam($this->base, '.sample-');
                if ($source === false || dirname($source) !== $this->base) { throw new StorageException('Cannot create private sample.', 'upload.io'); }
                $temporary = null;
                try {
                    chmod($source, 0600); $name = 'demo.png'; $scanner = null;
                    if ($action === 'fake_sample') { file_put_contents($source, '<?php DEMO-EXECUTABLE-SAMPLE ?>'); }
                    elseif ($action === 'size_sample') { file_put_contents($source, str_repeat('x', 1048577)); }
                    elseif ($action === 'budget_sample') {
                        $header = pack('NNCCCCC', 60000, 60000, 8, 2, 0, 0, 0);
                        file_put_contents($source, "\x89PNG\r\n\x1a\n" . pack('N', 13) . 'IHDR' . $header . pack('N', crc32('IHDR' . $header)));
                    } else {
                        $image = imagecreatetruecolor(2, 2); imagepng($image, $source);
                        if (is_resource($image)) { imagedestroy($image); } unset($image);
                    }
                    if ($action === 'path_sample') { $name = '../outside.png'; }
                    if ($action === 'scanner_reject') {
                        $scanner = new class implements Scanner { public function scan(Candidate $c): bool { return false; } };
                    } elseif ($action === 'scanner_fail') {
                        $scanner = new class implements Scanner { public function scan(Candidate $c): bool { throw new \RuntimeException('Isolated sample scanner failure.'); } };
                    } elseif ($action === 'store_fail') {
                        $temporary = $this->base . '/isolated-upload-' . bin2hex(random_bytes(8)); mkdir($temporary, 0700); chmod($temporary, 0755);
                        new Saver(new Validator(), $temporary, $this->web);
                    }
                    $saved = $this->saver($scanner)->saveFile($source, $name);
                } finally {
                    @unlink($source);
                    if ($temporary !== null && is_dir($temporary)) { chmod($temporary, 0700); rmdir($temporary); }
                }
            }
            $entry = $saved->metadata(); $entry['expires_at'] = time() + 600;
            $_SESSION['demo_uploaded_files'][] = $entry;
            return ['saved' => $entry, 'message' => '已保存到私有演示区，不提供公开访问或执行入口。'];
        });
    }
    public function prune(): int
    {
        return $this->locked(function () { list($count, $bytes, $removed) = $this->sweep(); return $removed; });
    }
    private function sweep(): array
    {
        $count = 0; $bytes = 0; $removed = 0; $scanned = 0;
        foreach (new \DirectoryIterator($this->directory) as $entry) {
            if ($entry->isDot() || $entry->getFilename() === '.quota') { continue; }
            if (++$scanned > 64 || $entry->isLink() || !$entry->isFile() || !preg_match('/^[a-f0-9]{32}\.(png|jpg)$/D', $entry->getFilename())) {
                throw new StorageException('Playground state is unexpected.', 'upload.demo_state');
            }
            if ($entry->getMTime() <= time() - 600) {
                if (!@unlink($entry->getPathname())) { throw new StorageException('Cannot prune expired demo file.', 'upload.io'); }
                ++$removed;
            } else { ++$count; $bytes += $entry->getSize(); }
        }
        return [$count, $bytes, $removed];
    }
    private function locked(callable $operation)
    {
        $path = $this->directory . '/.quota';
        if (is_link($path)) { throw new StorageException('Invalid playground lock.', 'upload.demo_state'); }
        $handle = @fopen($path, 'c+b');
        if ($handle === false || !@chmod($path, 0600)) { if (is_resource($handle)) { fclose($handle); } throw new StorageException('Cannot open playground lock.', 'upload.io'); }
        try {
            $deadline = new Deadline(300);
            while (!flock($handle, LOCK_EX | LOCK_NB)) { if ($deadline->remaining() <= 0) { throw new StorageException('Playground lock timed out.', 'upload.lock_timeout'); } usleep(1000); }
            return $operation();
        } finally { flock($handle, LOCK_UN); fclose($handle); }
    }
}
