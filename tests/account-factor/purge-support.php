<?php
declare(strict_types=1);
require __DIR__.'/switch-support.php';require __DIR__.'/fence-support.php';
function purgeFence(ManagedEnvironment $e,string $name='authority'):SoSecurity\Account\LocalEpochFence
{
    mkdir($e->directory.'/'.$name,0700);
    $f=new SoSecurity\Account\LocalEpochFence($e->directory.'/'.$name,'managed-test','tenant',str_repeat('e',64),$e->keys,'fencePersist',100);$f->initialize();return $f;
}
function purgeLedger(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,callable $op)
{
    $u=new SoSecurity\Support\SqlTransaction($e->pdo,$e->clock,10000);$l=new SoSecurity\Account\Ledger($u,'account-factor-recovery:'.hash('sha256','managed-test'),'tenant',str_repeat('e',64),$e->keys,new SoSecurity\Account\Policy(),2,$f->binding());return $u->run(static function()use($l,$op){return $op($l);});
}
function purgeFlow(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,string $id):?array
{
    return purgeLedger($e,$f,static function($l)use($id){return $l->read($id);});
}
function purgeEntries(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f):int
{
    return purgeLedger($e,$f,static function($l):int{return $l->checkpoint()['entries'];});
}
