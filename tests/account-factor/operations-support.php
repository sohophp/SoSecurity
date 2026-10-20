<?php
declare(strict_types=1);
require __DIR__.'/receipts-support.php';
function normalOperations(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,?callable $approval=null,?callable $authority=null,?callable $budget=null,?callable $event=null,bool $provision=true):SoSecurity\Account\FactorOperations
{
    // Provision the same actual Outbox used by recovery notifications.
    $receipt=[];if($provision){switchService($e,switchApproval($receipt),null,null,null,$f);}
    $queue=new SoSecurity\Outbox\SqlOutbox($e->pdo,'managed-test',str_repeat('e',64),$e->keys,static function():bool{return true;},new SoSecurity\Outbox\Policy(),$e->clock,static function():bool{return true;});
    return $e->registry->operations($f,$authority??static function():bool{return true;},$budget??static function():bool{return true;},$approval??static function():bool{return true;},static function(string $type,string $scope,$before,$after,string $operation,array $review)use($queue,$e,$event):bool{
        $queue->enqueue(new SoSecurity\Outbox\Message($scope,'factor-recovery',SoSecurity\Outbox\Message::identifier($type.':'.$operation,$e->clock->time),'mail',$type,$operation,$operation),'system');return $event===null||$event($type,$review)===true;
    });
}
function normalProof():array {return ['type'=>'approved','code'=>'owned-step-up-approval'];}
function normalFactor(ManagedEnvironment $e,bool $recovery=false):array
{
    if($recovery){return ['type'=>'recovery','code'=>$e->codes[0]];}$e->clock->time=(intdiv($e->clock->time,30)+1)*30;return ['type'=>'totp','code'=>(new SoSecurity\Mfa\Totp())->codeAt($e->secret,$e->clock->time)];
}
