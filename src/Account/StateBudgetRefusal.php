<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Support\SqlTransaction;

/** @internal Evidence of this execution's confirmed rollback, never permission or a recover-current capability. */
final class StateBudgetRefusal extends SecurityException
{
    private $connection;private $proof;
    private function __construct(PDO $connection,\Closure $proof)
    {
        parent::__construct('Account request budget refused.','account.budget');$this->connection=$connection;$this->proof=$proof;
    }
    public static function fromTransaction(SqlTransaction $unit):?self
    {
        $proof=$unit->refusalGuard();return $proof===null?null:new self($unit->connection(),$proof);
    }
    public function confirmed(PDO $connection):bool{return $this->connection===$connection&&($this->proof)()===true;}
    public function __debugInfo():array{return ['reason'=>'account.budget'];}
    public function __sleep():array{throw new ConfigurationException('Do not export rollback evidence.','configuration.state_refusal');}
    public function __wakeup():void{throw new ConfigurationException('Do not restore rollback evidence.','configuration.state_refusal');}
}
