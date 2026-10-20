<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlTransactionGuard;

/** Current SQL registration plus host object/purpose authorization; never provisions a worker authority. */
final class FactorWorkerAuthority
{
    private $dependencies;
    public function __construct(PDO $connection,string $site,string $scope,string $epoch,HmacKeys $keys,LocalEpochFence $fence,callable $permission,Policy $policy,Clock $clock)
    {
        foreach([$site,$scope] as $label){Guard::label($label);if(preg_match('//u',$label)!==1){throw new ConfigurationException('Use UTF-8 worker context.','configuration.factor_workers');}}
        if(!$fence->matches($site,$scope,$epoch)){throw new ConfigurationException('Use the matching registered worker context.','configuration.factor_workers');}
        new SqlTransaction($connection,$clock,$policy->ioMilliseconds());
        $this->dependencies=static function()use($connection,$site,$scope,$epoch,$keys,$fence,$permission,$policy,$clock):array{return [$connection,$site,$scope,$epoch,$keys,$fence,$permission,$policy,$clock];};
    }
    public function matchesConnection(PDO $connection):bool {return ($this->dependencies)()[0]===$connection;}
    public function boundTo(LocalEpochFence $fence):bool {return ($this->dependencies)()[5]->binding()===$fence->binding();}
    public function ioMilliseconds():int {return ($this->dependencies)()[7]->ioMilliseconds();}
    /** Acquire the registered root BEFORE directory/account locks, on the exact host PDO. No caller authorization is granted here. */
    public function assertCurrent(PDO $connection):void
    {
        $d=($this->dependencies)();if($d[0]!==$connection){throw new ConfigurationException('Registered workers must use the exact host connection.','configuration.factor_workers');}
        $this->read(null);
    }
    public function __invoke(string $action,string $phase,string $scope,string $subject,array $metadata):bool
    {
        if(!in_array($phase,['before','return'],true)){throw new ConfigurationException('Use an explicit physical worker phase.','configuration.factor_workers');}
        // The physical FactorAuthority owns the complete SH/closed-EX context. This
        // read also works when a second object for the same authority owns that EX.
        try{return $this->read([$action,$phase,$scope,$subject,$metadata]);}
        catch(SecurityException $error){if($error->reason()!=='account.worker_denied'){throw $error;}return false;}
    }
    private function read(?array $request):bool
    {
        $d=($this->dependencies)();$u=new SqlTransaction($d[0],$d[8],$d[7]->ioMilliseconds());$deadline=new Deadline($d[7]->ioMilliseconds());$active=true;
        try{SqlTransactionGuard::assertActive($d[0],$u->driver(),$deadline);}catch(ConfigurationException $error){if($error->reason()!=='configuration.transaction'){throw $error;}$active=false;}
        $body=function()use($u,$d,$request):bool{
            $ledger=new Ledger($u,'account-factor-recovery:'.hash('sha256',$d[1]),$d[2],$d[3],$d[4],$d[7],2,$d[5]->binding());
            $root=$ledger->checkpoint();
            $allowed=$request===null||$u->invoke($d[6],$request,'account.worker_permission')===true;
            if($ledger->checkpoint()!==$root){throw new StorageException('Registered worker state changed during permission checks.','account.worker_changed');}
            if(!$allowed){throw new SecurityException('Current physical factor authority required.','account.worker_denied');}
            return true;
        };
        return $active?$u->enlist($body,null,null,$deadline):$u->run($body,null,null,null,$deadline);
    }
    public function __debugInfo():array {return ['registered_factor_workers'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload current registered worker authority.','configuration.factor_workers');}
    public function __wakeup():void {throw new ConfigurationException('Reload current registered worker authority.','configuration.factor_workers');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Worker authorities are immutable.','configuration.immutable');}
}
