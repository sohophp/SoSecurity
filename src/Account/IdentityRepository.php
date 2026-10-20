<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Auth\Account;

/** Current effective authentication identity, read from the same PDO. A snapshot alone is not caller authentication. */
interface IdentityRepository extends Repository
{
    /** Bind actual credentials as well as raw versions; preserve scope, subject, enabled, roles and MFA requirements. */
    public function identity(AccountRecord $expected):?Account;
}
