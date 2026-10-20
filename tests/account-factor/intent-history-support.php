<?php
declare(strict_types=1);
require __DIR__.'/lifecycle-support.php';
function operationHistory(ManagedEnvironment $e,SoSecurity\Account\FactorOperations $ops,?callable $authority=null,?callable $budget=null,?callable $approval=null,?callable $auditHook=null,?callable $eventHook=null,bool $provision=true):SoSecurity\Account\FactorIntentMaintenance
{
    if($provision){$e->pdo->exec('DROP TABLE IF EXISTS factor_operation_history_audit');$e->pdo->exec('CREATE TABLE factor_operation_history_audit(operation VARCHAR(64) NOT NULL PRIMARY KEY,mode VARCHAR(16) NOT NULL)'.((($GLOBALS['argv'][1]??'')==='mysql')?' ENGINE=InnoDB':''));}$queue=lifecycleQueue($e,'factor-operation-history');
    return $ops->maintenance($authority??static function():bool{return true;},$budget??static function():bool{return true;},$approval??static function():bool{return true;},static function(array $v,array $counts,string $id)use($e,$auditHook):bool{$q=$e->pdo->prepare('INSERT INTO factor_operation_history_audit VALUES(?,?)');$q->execute([$id,$v['mode']]);$q->closeCursor();return $auditHook===null||$auditHook($v,$counts,$id)===true;},static function(string $type,array $v,array $counts,string $id)use($e,$queue,$eventHook):bool{$queue->enqueue(new SoSecurity\Outbox\Message('tenant','factor-operation-history',SoSecurity\Outbox\Message::identifier($type.':'.$id,$e->clock->time),'mail',$type,$id,$id),'system');return $eventHook===null||$eventHook($type,$v,$counts,$id)===true;});
}
