<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use PDO;

/** Host-owned current reads and conditional mutations on exactly the declared connection. No transaction control or network I/O. */
interface Repository
{
    public function connection():PDO;
    public function find(string $scope,string $subject):?AccountRecord;
    public function findAddress(string $scope,Address $address):?AccountRecord;
    /** Create a non-login-capable reservation. No attacker-selected password is installed before ownership proof. */
    public function createPending(string $scope,string $subject,Address $address):?AccountRecord;
    /** Compare both credential/address versions, install the owner's chosen password, verify and activate, then advance credential version. */
    public function activate(AccountRecord $expected,string $passwordHash):?AccountRecord;
    /** Compare both versions, replace the verified address and advance both credential/address versions. */
    public function changeAddress(AccountRecord $expected,Address $address):?AccountRecord;
    /** Never remove MFA. Compare both versions and advance the credential version after replacement. */
    public function replacePassword(AccountRecord $expected,string $passwordHash):?AccountRecord;
}
