<?php
declare(strict_types=1);

namespace SoSecurity\Password;

final class PasswordPolicy
{
    private $minimum;
    private $maximumBytes;

    public function __construct(int $minimum = 15, int $maximumBytes = 72)
    {
        if ($minimum < 8 || $minimum > 128 || $maximumBytes < $minimum || $maximumBytes > 4096) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid password length policy.');
        }
        $this->minimum = $minimum;
        $this->maximumBytes = $maximumBytes;
    }

    /** Returns stable error codes for host localization. Optional breach checker returns true if compromised. */
    public function errors(string $password, ?callable $breachChecker = null): array
    {
        $errors = [];
        if (!preg_match('//u', $password) || strpos($password, "\0") !== false) {
            return ['password.encoding'];
        }
        $length = preg_match_all('/./us', $password);
        if ($length < $this->minimum) {
            $errors[] = 'password.too_short';
        }
        if (strlen($password) > $this->maximumBytes) {
            $errors[] = 'password.too_long';
        }
        if (!$errors && $breachChecker !== null) {
            $compromised = $breachChecker($password);
            if (!is_bool($compromised)) {
                throw new \RuntimeException('Breach checker must return bool; failures must throw.');
            }
            if ($compromised) {
                $errors[] = 'password.compromised';
            }
        }
        return $errors;
    }
}
