<?php
declare(strict_types=1);

namespace SoSecurity\Password;

final class PasswordHasher
{
    private $algorithm;
    private $options;

    /** bcrypt is the portable profile. Explicit argon2id is preferred on capable modern runtimes. */
    public function __construct(string $profile = 'bcrypt', array $options = [])
    {
        if ($profile === 'bcrypt') {
            $cost = $options['cost'] ?? 12;
            if (array_diff(array_keys($options), ['cost']) || !is_int($cost) || $cost < 10 || $cost > 16) {
                throw new \InvalidArgumentException('bcrypt requires cost 10-16.');
            }
            $this->algorithm = PASSWORD_BCRYPT;
            $this->options = ['cost' => $cost];
        } elseif ($profile === 'argon2id' && defined('PASSWORD_ARGON2ID')) {
            $options += ['memory_cost' => 19456, 'time_cost' => 2, 'threads' => 1];
            if (array_diff(array_keys($options), ['memory_cost', 'time_cost', 'threads'])
                || !is_int($options['memory_cost']) || $options['memory_cost'] < 19456 || $options['memory_cost'] > 262144
                || !is_int($options['time_cost']) || $options['time_cost'] < 2 || $options['time_cost'] > 10
                || !is_int($options['threads']) || $options['threads'] < 1 || $options['threads'] > 4) {
                throw new \InvalidArgumentException('Invalid Argon2id resource settings.');
            }
            $this->algorithm = constant('PASSWORD_ARGON2ID');
            $this->options = $options;
        } else {
            throw new \InvalidArgumentException('Unknown or unavailable password profile.');
        }
    }

    public function hash(string $password): string
    {
        $this->validate($password);
        $hash = password_hash($password, $this->algorithm, $this->options);
        if (!is_string($hash)) {
            throw new \RuntimeException('Password hashing failed.');
        }
        return $hash;
    }

    public function verify(string $password, string $hash): bool
    {
        if ($password === '' || strlen($password) > 4096 || strpos($password, "\0") !== false) {
            return false;
        }
        // bcrypt truncates at 72 bytes; refuse inputs that would verify through truncation.
        if (substr($hash, 0, 2) === '$2' && strlen($password) > 72) {
            return false;
        }
        return password_verify($password, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        // Never automatically downgrade Argon2 to bcrypt when moving to an older runtime.
        if ($this->algorithm === PASSWORD_BCRYPT && substr($hash, 0, 7) === '$argon2') {
            return false;
        }
        $info = password_get_info($hash);
        if ($this->algorithm === PASSWORD_BCRYPT && $info['algoName'] === 'bcrypt'
            && ($info['options']['cost'] ?? 0) >= $this->options['cost']) {
            return false;
        }
        return password_needs_rehash($hash, $this->algorithm, $this->options);
    }

    /** Host supplies an exact legacy verifier. Save replacement with compare-and-swap against old hash. */
    public function verifyAndUpgrade(string $password, string $hash, ?callable $legacyVerifier = null): Verification
    {
        $valid = $this->verify($password, $hash);
        $modern = substr($hash, 0, 2) === '$2' || substr($hash, 0, 7) === '$argon2';
        if (!$valid && !$modern && $legacyVerifier !== null && $password !== ''
            && strlen($password) <= 4096 && strpos($password, "\0") === false) {
            $valid = $legacyVerifier($password, $hash) === true;
        }
        if (!$valid) {
            return new Verification(false);
        }
        // Some legacy passwords cannot be represented by the portable bcrypt profile safely.
        // Return an explicit error rather than silently truncating a migrated password.
        return new Verification(true, (!$modern || $this->needsRehash($hash)) ? $this->hash($password) : null);
    }

    private function validate(string $password): void
    {
        $max = $this->algorithm === PASSWORD_BCRYPT ? 72 : 4096;
        if ($password === '' || strlen($password) > $max || strpos($password, "\0") !== false) {
            throw new \InvalidArgumentException('Password contains NUL, is empty or exceeds the profile byte limit.');
        }
    }
}
