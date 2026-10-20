<?php
declare(strict_types=1);

namespace SoSecurity\Password;

final class PasswordPolicy
{
    private $minimum;
    private $maximumBytes;
    private $blocklist;
    private $checker;

    public function __construct(int $minimum = 15, int $maximumBytes = 72, ?PasswordBlocklist $blocklist = null, ?callable $breachChecker = null)
    {
        if ($minimum < 8 || $minimum > 128 || $maximumBytes < $minimum || $maximumBytes > 4096) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid password length policy.');
        }
        $this->minimum = $minimum;
        $this->maximumBytes = $maximumBytes;
        $this->blocklist = $blocklist; $this->checker = $breachChecker;
    }

    public static function forHasher(PasswordHasher $hasher, int $minimum = 15, ?int $maximumBytes = null,
        ?PasswordBlocklist $blocklist = null, ?callable $breachChecker = null): self
    {
        $maximumBytes = $maximumBytes ?? $hasher->maximumBytes();
        if ($maximumBytes > $hasher->maximumBytes()) { throw new \SoSecurity\Exception\ConfigurationException('Password policy exceeds the selected hash profile.', 'configuration.password_policy'); }
        return new self($minimum, $maximumBytes, $blocklist, $breachChecker);
    }

    /** Returns stable error codes for host localization. Optional breach checker returns true if compromised. */
    public function errors(string $password, ?callable $breachChecker = null): array
    {
        $errors = [];
        // Bound all Unicode work and external calls before scanning the supplied candidate.
        if (strlen($password) > $this->maximumBytes) { return ['password.too_long']; }
        if (!preg_match('//u', $password) || strpos($password, "\0") !== false) {
            return ['password.encoding'];
        }
        $length = preg_match_all('/./us', $password);
        if ($length < $this->minimum) {
            $errors[] = 'password.too_short';
        }
        if (!$errors && $this->blocklist !== null && $this->blocklist->contains($password)) { $errors[] = 'password.weak'; }
        $breachChecker = $breachChecker ?? $this->checker;
        if (!$errors && $breachChecker !== null) {
            try { $compromised = $breachChecker($password); }
            catch (\Throwable $e) { throw new \SoSecurity\Exception\DependencyException('Password breach check unavailable.', 'password.breach_unavailable'); }
            if (!is_bool($compromised)) { throw new \SoSecurity\Exception\DependencyException('Password breach checker must return bool.', 'password.breach_unavailable'); }
            if ($compromised) {
                $errors[] = 'password.compromised';
            }
        }
        return $errors;
    }
    public function __debugInfo(): array { return ['minimum' => $this->minimum, 'maximum_bytes' => $this->maximumBytes, 'services' => '[redacted]']; }
    public function __sleep(): array { throw new \SoSecurity\Exception\ConfigurationException('Rebuild password policy from trusted configuration.', 'configuration.password_policy'); }
    public function __set(string $name, $value): void { throw new \SoSecurity\Exception\ConfigurationException('Password policies are immutable.', 'configuration.immutable'); }
}
