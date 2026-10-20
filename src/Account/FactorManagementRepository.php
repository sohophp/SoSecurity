<?php
declare(strict_types=1);
namespace SoSecurity\Account;

/** Optional normal-management capability; existing FactorRepository implementations remain compatible. */
interface FactorManagementRepository extends FactorRepository
{
    /** Same-PDO full-snapshot CAS. Advance credentials even if the MFA flag is unchanged; preserve password/address/roles/status. */
    public function setMfa(AccountRecord $expected,bool $required):?AccountRecord;
}
