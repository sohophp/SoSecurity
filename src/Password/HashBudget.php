<?php
declare(strict_types=1);
namespace SoSecurity\Password;

/** Internal preflight before native password verification; never execute attacker-controlled work factors. */
final class HashBudget
{
    public static function allows(string $hash): bool
    {
        if (strlen($hash) > 512) { return false; }
        if (preg_match('/\A\$2[abxy]\$(0[4-9]|1[0-6])\$[.\/A-Za-z0-9]{53}\z/D', $hash)) { return true; }
        return preg_match('/\A\$argon2(?:i|id)\$v=(?:16|19)\$m=([1-9][0-9]{0,5}),t=([1-9][0-9]?),p=([1-9][0-9]?)\$[A-Za-z0-9+\/]{8,128}\$[A-Za-z0-9+\/]{16,128}\z/D', $hash, $parts) === 1
            && (int) $parts[1] <= 262144 && (int) $parts[2] <= 10 && (int) $parts[3] <= 4;
    }
}
