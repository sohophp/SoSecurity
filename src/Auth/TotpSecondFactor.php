<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

use SoSecurity\Mfa\TotpFactors;

final class TotpSecondFactor implements SecondFactor
{
    private $factors;
    public function __construct(TotpFactors $factors) { $this->factors = $factors; }
    public function binding(string $scope, string $subject): ?string { return $this->factors->status($scope, $subject)['factor_id']; }
    public function verify(string $scope, string $subject, string $expectedBinding, $proof): ?string
    {
        if (!is_array($proof) || count($proof) !== 2 || !isset($proof['type'], $proof['code'])
            || !in_array($proof['type'], ['totp', 'recovery'], true)) { return null; }
        return $this->factors->verifyBound($scope, $subject, $expectedBinding, $proof['code'], $proof['type'] === 'recovery') ? $proof['type'] : null;
    }
}
