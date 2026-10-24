<?php
declare(strict_types=1);
namespace SoSecurity\Authorization;
use SoSecurity\Auth\Account;
/** Trusted pure evaluator: no I/O; persistent authority comes only from captured facts. */
interface SnapshotEvaluator
{
    public function selectors(Account $actor,string $action,Resource $resource,array $requestedFields):array;
    public function decide(Account $actor,string $action,Resource $resource,array $requestedFields,array $facts):?Decision;
}
