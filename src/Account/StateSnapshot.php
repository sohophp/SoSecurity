<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use PDO;

/** Trusted complete state source; no implicit adoption or transaction control by callers. */
interface StateSnapshot
{
    public function connection():PDO;
    public function fingerprint():string;
    public function digest():string;
}
