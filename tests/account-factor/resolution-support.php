<?php
declare(strict_types=1);
require dirname(__DIR__,2).'/vendor/autoload.php';
require __DIR__.'/intent-history-support.php';
function unresolvedOperation(ManagedEnvironment $e,string $action,string $fault='reservation',?SoSecurity\Account\Policy $policy=null):array
{
    list($f,$legacy)=$policy===null?migrationSetup($e):migrationPolicySetup($e,$policy);$core=migrationService($e,$legacy,$f);$migration=$core->review('user','owned-migration',migrationStop());$core->execute($migration,'owned-migrate',migrationProof());$armed=true;
    lifecycleQueue($e,'factor-recovery');$ops=normalOperations($e,$f,static function(string $phase)use($e,$fault,&$armed):bool{if($fault==='reservation'&&$armed&&$phase==='reserve_commit'){$armed=false;$e->pdo->afterCommit=static function()use($e):void{$e->pdo->afterCommit=null;throw new RuntimeException('owned reservation acknowledgement loss');};}return true;},null,null,static function(string $type)use($fault):bool{return !($fault==='physical'&&$type==='factor_management_completed');},false);$ops->initialize();$v=$ops->review($action,'user','owned-unknown-review');$factor=$action==='reencrypt'?[]:normalFactor($e);
    migrationReason('account.completion_unknown',static function()use($ops,$v,$factor):void{$ops->execute($v,'owned-unknown',normalProof(),$factor);});Check::same('prepared',$ops->inspect($v['operation'],'owned-unresolved')['state']);return [$f,$legacy,$ops,$v];
}
function resolutionService(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,?callable $authority=null,?callable $budget=null,?callable $approval=null,?callable $audit=null,?callable $event=null,bool $provision=true):SoSecurity\Account\FactorOperationResolution
{
    if($provision){$e->pdo->exec('DROP TABLE IF EXISTS factor_resolution_audit');$e->pdo->exec('CREATE TABLE factor_resolution_audit(decision VARCHAR(64) NOT NULL PRIMARY KEY,operation VARCHAR(64) NOT NULL)'.((($GLOBALS['argv'][1]??'')==='mysql')?' ENGINE=InnoDB':''));}$queue=lifecycleQueue($e,'factor-operation-resolution');
    return $e->registry->operationResolution($f,$authority??static function():bool{return true;},$budget??static function():bool{return true;},$approval??static function():bool{return true;},static function(array $v,array $before,array $after)use($e,$audit):bool{$q=$e->pdo->prepare('INSERT INTO factor_resolution_audit VALUES(?,?)');$q->execute([$v['nonce'],$v['operation']]);$q->closeCursor();return $audit===null||$audit($v,$before,$after)===true;},static function(string $type,array $v,array $before,array $after)use($e,$queue,$event):bool{$queue->enqueue(new SoSecurity\Outbox\Message('tenant','factor-operation-resolution',SoSecurity\Outbox\Message::identifier($type.':'.$v['nonce'],$e->clock->time),'mail',$type,$v['operation'],$v['operation']),'system');return $event===null||$event($type,$v,$before,$after)===true;});
}
