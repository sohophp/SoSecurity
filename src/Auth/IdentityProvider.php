<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

interface IdentityProvider
{
    /** Unknown, disabled and incorrect credentials return null with the same public failure semantics. */
    public function authenticate(string $scope, string $identifier, string $password): ?Account;
    /** Fetch current authority, credential/permission version and policy; outage MUST throw, never reuse stale identity. */
    public function find(string $scope, string $subject): ?Account;
}
