<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

interface SecondFactor
{
    /** Current factor generation, or null when unconfigured. Changes must invalidate old binding values. */
    public function binding(string $scope, string $subject): ?string;
    /** Atomically check the expected generation and consume proof; return a trusted method name or null. */
    public function verify(string $scope, string $subject, string $expectedBinding, $proof): ?string;
}
