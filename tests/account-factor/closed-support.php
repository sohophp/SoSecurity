<?php
declare(strict_types=1);
require __DIR__.'/mode-support.php';
function closedSetup(ManagedEnvironment $e,?callable $guard=null):array {
    $id=$e->factors->status('tenant','user')['factor_id'];$f=purgeFence($e);$m=managedFactors($e,$f,$guard);$m->adoptManaged('tenant','user',$id);$e->factors=$m;$e->registry=new SoSecurity\Account\FactorRegistry($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->accounts,$m,static function():bool{return true;},static function():bool{return true;},null,$e->clock,$f);$e->registry->initialize('user');$receipt=[];$s=switchService($e,switchApproval($receipt));$s->initialize();return [$f,$m,$s];
}
