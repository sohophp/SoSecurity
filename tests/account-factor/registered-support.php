<?php
declare(strict_types=1);
require __DIR__.'/closed-support.php';
function registeredProvider(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,?callable $permission=null):SoSecurity\Account\FactorWorkerAuthority
{
    return new SoSecurity\Account\FactorWorkerAuthority($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$f,$permission??static function():bool{return true;},new SoSecurity\Account\Policy(),$e->clock);
}
function registeredSetup(ManagedEnvironment $e,?callable $permission=null):array
{
    $id=$e->factors->status('tenant','user')['factor_id'];$f=purgeFence($e);
    // Test provisioning only: formal migration approval/intent is a separate stage.
    purgeLedger($e,$f,static function($l):void{$l->initialize();});
    $p=registeredProvider($e,$f,$permission);$m=$e->factors->managedRegistered('managed-test','tenant',str_repeat('e',64),$e->keys,$f,$p);
    $m->adoptManaged('tenant','user',$id);$e->factors=$m;
    $e->registry=new SoSecurity\Account\FactorRegistry($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->accounts,$m,static function():bool{return true;},static function():bool{return true;},null,$e->clock,$f);$e->registry->initialize('user');return [$f,$m,$p];
}
