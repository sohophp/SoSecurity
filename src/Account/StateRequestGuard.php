<?php
declare(strict_types=1);
namespace SoSecurity\Account;
/** Public CSRF checks precede locking; current admission is read-only under the lock before pending. */
interface StateRequestGuard
{
    public function __invoke(string $action,string $scope):bool;
    public function current(string $action,string $scope):bool;
}
