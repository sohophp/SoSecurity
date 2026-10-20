<?php
declare(strict_types=1);
namespace SoSecurity\Account;

/** Optional managed-factor host capability; existing Repository implementations remain valid. */
interface FactorRepository extends IdentityRepository
{
    /** Same-PDO current credential-state digest, including inactive records and actual host credential bytes. Never an authentication identity. */
    public function credentialBinding(AccountRecord $expected):?string;
    /** Compare the full snapshot, require MFA and advance credentials. Preserve password, address/version and roles/status. */
    public function requireMfa(AccountRecord $expected):?AccountRecord;
}
