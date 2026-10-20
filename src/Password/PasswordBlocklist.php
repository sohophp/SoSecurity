<?php
declare(strict_types=1);
namespace SoSecurity\Password;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;

/** Exact whole-password matches. Digests are lookup data, never a password-storage algorithm. */
final class PasswordBlocklist
{
    private $digests = [];
    public function __construct(array $sha256)
    {
        if (count($sha256) > 100000) { throw new ConfigurationException('Password blocklist exceeds 100000 entries.', 'configuration.password_blocklist'); }
        foreach ($sha256 as $digest) {
            if (!is_string($digest) || !preg_match('/\A[a-fA-F0-9]{64}\z/D', $digest)) { throw new ConfigurationException('Expected SHA-256 blocklist entries.', 'configuration.password_blocklist'); }
            $this->digests[strtolower($digest)] = true;
        }
    }
    public static function fromPasswords(array $passwords): self
    {
        if (count($passwords) > 100000) { throw new ConfigurationException('Password blocklist exceeds 100000 entries.', 'configuration.password_blocklist'); }
        $digests = [];
        foreach ($passwords as $password) {
            if (!is_string($password) || $password === '' || strlen($password) > 4096 || strpos($password, "\0") !== false || !preg_match('//u', $password)) {
                throw new ConfigurationException('Invalid whole-password blocklist input.', 'configuration.password_blocklist');
            }
            $digests[] = hash('sha256', $password);
        }
        return new self($digests);
    }
    /** Small transparent baseline; deployments supplement it with maintained breach/context data. */
    public static function baseline(): self
    {
        $passwords = ['password', 'Password1!', 'Password123!', 'correcthorsebatterystaple', 'qwertyuiopasdfgh', 'qwertyuiopasdfghjkl',
            '123456789012345', '1234567890123456', '12345678901234567890', 'iloveyouiloveyou', 'letmeinletmeinletmein'];
        $list = new self([]);
        foreach ($passwords as $password) { $list->digests[hash('sha256', $password)] = true; }
        foreach (str_split('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') as $character) {
            for ($length = 8; $length <= 128; ++$length) { $list->digests[hash('sha256', str_repeat($character, $length))] = true; }
        }
        foreach (['password', '1234567890', 'qwerty', 'asdfgh', '123456', 'abcdef'] as $pattern) {
            for ($length = 2; strlen($pattern) * $length <= 128; ++$length) { $list->digests[hash('sha256', str_repeat($pattern, $length))] = true; }
        }
        return $list;
    }
    /** Explicit bounded snapshot import; pin the dataset checksum and replace files atomically. */
    public static function fromFile(string $path, string $expectedSha256): self
    {
        if (!preg_match('/\A[a-f0-9]{64}\z/D', $expectedSha256) || strpos($path, '://') !== false || strpos($path, "\0") !== false) {
            throw new ConfigurationException('Provide a local dataset and its SHA-256 snapshot checksum.', 'configuration.password_blocklist');
        }
        $before = @lstat($path);
        if ($before === false || ($before['mode'] & 0170000) !== 0100000 || $before['size'] > 8388608) { throw new DependencyException('Expected a bounded regular blocklist snapshot.', 'password.blocklist_unavailable'); }
        $handle = @fopen($path, 'rb');
        if ($handle === false) { throw new DependencyException('Cannot open password blocklist snapshot.', 'password.blocklist_unavailable'); }
        try {
            $stat = fstat($handle);
            if ($stat === false || ($stat['mode'] & 0170000) !== 0100000 || $stat['size'] > 8388608 || $stat['ino'] !== $before['ino'] || $stat['dev'] !== $before['dev']) { throw new DependencyException('Invalid password blocklist snapshot.', 'password.blocklist_unavailable'); }
            $body = stream_get_contents($handle, 8388609);
            if (!is_string($body) || strlen($body) > 8388608 || !hash_equals($expectedSha256, hash('sha256', $body))) {
                throw new DependencyException('Password blocklist snapshot checksum/size mismatch.', 'password.blocklist_unavailable');
            }
        } finally { fclose($handle); }
        $lines = preg_split('/\r?\n/', $body);
        if (end($lines) === '') { array_pop($lines); }
        if (!$lines || count($lines) > 100000) { throw new DependencyException('Invalid password blocklist record budget.', 'password.blocklist_unavailable'); }
        try { return new self($lines); }
        catch (ConfigurationException $e) { throw new DependencyException('Malformed password blocklist snapshot.', 'password.blocklist_unavailable'); }
    }
    public function contains(string $password): bool { return strlen($password) <= 4096 && isset($this->digests[hash('sha256', $password)]); }
    public function count(): int { return count($this->digests); }
    public function __debugInfo(): array { return ['entries' => $this->count(), 'digests' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Reload the trusted password blocklist snapshot.', 'configuration.password_blocklist'); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Password blocklists are immutable.', 'configuration.immutable'); }
}
