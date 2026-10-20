<?php
declare(strict_types=1);
namespace SoSecurity\Authorization;
use SoSecurity\Auth\Account;

interface PolicyProvider
{
    /** Read-only current policy evaluation. Null is unsupported, never permission; failures MUST throw. */
    public function decide(Account $actor, string $action, Resource $resource, array $requestedFields = []): ?Decision;
}
