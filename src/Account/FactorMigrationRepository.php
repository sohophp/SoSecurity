<?php
declare(strict_types=1);
namespace SoSecurity\Account;

/** Optional migration CAS capability. Existing repositories remain compatible. */
interface FactorMigrationRepository extends FactorManagementRepository
{
    /** Same-PDO stable digest of actual password/address/roles/status; excludes credential version and MFA flag. */
    public function migrationMaterialBinding(AccountRecord $expected):?string;
}
