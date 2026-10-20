<?php
declare(strict_types=1);
namespace SoSecurity\Upload;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Support\Deadline;

/** Local, explicitly configured clamd INSTREAM client. A clean reply is not a general safety proof. */
final class ClamAvScanner implements Scanner
{
    private $configuration;

    public function __construct(string $socketPath, int $milliseconds = 5000, int $maximumBytes = 5242880)
    {
        new Deadline($milliseconds);
        if (strlen($socketPath) > 100 || preg_match('~\A/[A-Za-z0-9._/ -]+\z~D', $socketPath) !== 1
            || preg_match('~/\.{1,2}(?:/|$)~', $socketPath) || basename($socketPath) === ''
            || $maximumBytes < 1 || $maximumBytes > 20971520) {
            throw new ConfigurationException('Use a fixed local socket path and bounded ClamAV policy.', 'configuration.clamav');
        }
        $this->configuration = static function () use ($socketPath, $milliseconds, $maximumBytes): array {
            return [$socketPath, $milliseconds, $maximumBytes];
        };
    }

    private function remaining(Deadline $deadline): float
    {
        $remaining = $deadline->remaining();
        if ($remaining <= 0) { throw new DependencyException('ClamAV scan exceeded its total deadline.', 'dependency.clamav_timeout'); }
        return $remaining;
    }

    /** @param resource $stream */
    private function wait($stream, bool $reading, Deadline $deadline): void
    {
        $left = $this->remaining($deadline); $seconds = (int) floor($left);
        $micros = min(999999, max(1, (int) ceil(($left - $seconds) * 1000000)));
        // Local Unix streams do not use TCP out-of-band data. Read/write report transport failure.
        $read = $reading ? [$stream] : []; $write = $reading ? [] : [$stream]; $except = null;
        $ready = @stream_select($read, $write, $except, $seconds, $micros);
        $this->remaining($deadline);
        if ($ready === false) { throw new DependencyException('ClamAV transport failed.', 'dependency.clamav_unavailable'); }
        if ($ready === 0) { throw new DependencyException('ClamAV scan exceeded its total deadline.', 'dependency.clamav_timeout'); }
    }

    /** @param resource $stream */
    private function write($stream, string $bytes, Deadline $deadline): void
    {
        $offset = 0; $length = strlen($bytes);
        while ($offset < $length) {
            $this->wait($stream, false, $deadline);
            $written = @fwrite($stream, substr($bytes, $offset));
            if (!is_int($written) || $written < 1) { throw new DependencyException('ClamAV transport failed.', 'dependency.clamav_unavailable'); }
            $offset += $written; $this->remaining($deadline);
        }
    }

    private function nodes(string $path): array
    {
        $directory = dirname($path); clearstatcache(true, $directory); clearstatcache(true, $path);
        $parent = @lstat($directory); $socket = @lstat($path);
        if (realpath($directory) !== $directory || !is_array($parent) || ($parent['mode'] & 0170000) !== 0040000
            || ($parent['mode'] & 0022) !== 0 || !is_array($socket) || ($socket['mode'] & 0170000) !== 0140000
            || ($socket['mode'] & 0002) !== 0 || $socket['nlink'] !== 1) {
            throw new DependencyException('Use a protected canonical local ClamAV socket.', 'dependency.clamav_socket');
        }
        $identity = [];
        foreach ([$parent, $socket] as $node) {
            $identity[] = [$node['dev'], $node['ino'], $node['uid'], $node['gid'], $node['mode'], $node['nlink']];
        }
        return $identity;
    }

    public function scan(Candidate $candidate): bool
    {
        list($path, $milliseconds, $maximum) = ($this->configuration)();
        $contents = $candidate->contents(); $bytes = strlen($contents);
        if ($bytes > $maximum) { throw new DependencyException('Upload exceeds the configured scan limit.', 'dependency.clamav_limit'); }
        $deadline = new Deadline($milliseconds); $identity = $this->nodes($path);
        $stream = @stream_socket_client('unix://' . $path, $errno, $error, $this->remaining($deadline), STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT);
        if (!is_resource($stream)) { throw new DependencyException('ClamAV is unavailable.', 'dependency.clamav_unavailable'); }
        try {
            if (!stream_set_blocking($stream, false)) { throw new DependencyException('ClamAV transport failed.', 'dependency.clamav_unavailable'); }
            $this->wait($stream, false, $deadline);
            if ($this->nodes($path) !== $identity) { throw new DependencyException('ClamAV socket changed.', 'dependency.clamav_socket'); }
            $this->write($stream, "zINSTREAM\0", $deadline);
            for ($offset = 0; $offset < $bytes; $offset += 8192) {
                $chunk = substr($contents, $offset, 8192);
                $this->write($stream, pack('N', strlen($chunk)), $deadline);
                $this->write($stream, $chunk, $deadline);
            }
            $this->write($stream, pack('N', 0), $deadline);
            $reply = '';
            while (!feof($stream)) {
                $this->wait($stream, true, $deadline);
                // Nonblocking bounded drain; at most 1024 bytes are requested on every read.
                $part = @stream_get_contents($stream, min(1024, 4097 - strlen($reply)));
                if (!is_string($part)) { throw new DependencyException('ClamAV transport failed.', 'dependency.clamav_unavailable'); }
                $reply .= $part;
                if (strlen($reply) > 4096) { throw new DependencyException('ClamAV reply exceeded its bound.', 'dependency.clamav_protocol'); }
                $this->remaining($deadline);
            }
            if ($this->nodes($path) !== $identity) { throw new DependencyException('ClamAV socket changed.', 'dependency.clamav_socket'); }
            $this->remaining($deadline);
            if ($reply === "stream: OK\0") { return true; }
            if (strpos($reply, 'INSTREAM size limit exceeded') === 0 || strpos($reply, 'stream: Heuristics.Limits.Exceeded') === 0) {
                throw new DependencyException('ClamAV did not complete the scan within its limits.', 'dependency.clamav_limit');
            }
            if (preg_match('/\Astream: [^\x00-\x1f\x7f]{1,2048} FOUND\x00\z/D', $reply)) { return false; }
            throw new DependencyException('ClamAV returned an incomplete or invalid scan result.', 'dependency.clamav_protocol');
        } finally { fclose($stream); }
    }

    public function __debugInfo(): array { return ['clamav_scanner' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Rebuild the configured scanner.', 'configuration.clamav_serialization'); }
    public function __wakeup(): void { throw new ConfigurationException('Rebuild the configured scanner.', 'configuration.clamav_serialization'); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Scanner policy is immutable.', 'configuration.immutable'); }
}
