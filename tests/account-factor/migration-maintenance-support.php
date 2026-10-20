<?php
declare(strict_types=1);
require __DIR__.'/migration-support.php';
function migrationHistory(ManagedEnvironment $e,SoSecurity\Account\FactorMigration $core,?callable $authority=null,?callable $budget=null,?callable $approval=null,?callable $auditHook=null,?callable $eventHook=null,bool $provision=true):SoSecurity\Account\FactorMigrationMaintenance
{
    if($provision){$e->pdo->exec('DROP TABLE IF EXISTS factor_migration_history_audit');$e->pdo->exec('CREATE TABLE factor_migration_history_audit(operation VARCHAR(64) NOT NULL PRIMARY KEY,mode VARCHAR(16) NOT NULL)'.((($GLOBALS['argv'][1]??'')==='mysql')?' ENGINE=InnoDB':''));}
    $queue=new SoSecurity\Outbox\SqlOutbox($e->pdo,'managed-test',str_repeat('e',64),$e->keys,static function():bool{return true;},null,$e->clock,static function():bool{return true;});if($provision){$queue->initialize('tenant','factor-migration-history','system');}
    return $core->maintenance($authority??static function():bool{return true;},$budget??static function():bool{return true;},$approval??static function():bool{return true;},static function(array $v,array $counts,string $op)use($e,$auditHook):bool{$q=$e->pdo->prepare('INSERT INTO factor_migration_history_audit(operation,mode) VALUES(?,?)');$q->execute([$op,$v['mode']]);$q->closeCursor();return $auditHook===null||$auditHook($v,$counts,$op)===true;},static function(string $type,array $v,array $counts,string $op)use($e,$queue,$eventHook):bool{$queue->enqueue(new SoSecurity\Outbox\Message('tenant','factor-migration-history',SoSecurity\Outbox\Message::identifier($type.':'.$op,$e->clock->time),'mail',$type,$op,$op),'system');return $eventHook===null||$eventHook($type,$v,$counts,$op)===true;});
}
function migrationHistoryCount(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f):int{return purgeLedger($e,$f,static function($l):int{return $l->checkpoint()['entries'];});}
function migrationHistoryRotate(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $old):SoSecurity\Account\LocalEpochFence
{
    $queue=new SoSecurity\Outbox\SqlOutbox($e->pdo,'managed-test',str_repeat('e',64),$e->keys,static function():bool{return true;},null,$e->clock,static function():bool{return true;});$queue->initialize('tenant','factor-recovery','system');$receipt=[];$workers=workerService($e,$old,$receipt);$next=purgeFence($e,'authority-after-history');Check::same(true,$workers->rotateWorkers($next,workerWitness($e,$old),'owned-history-worker-switch',static function():bool{return true;},workerAudit($e))['changed']);return $next;
}
function migrationPolicyLedger(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,SoSecurity\Account\Policy $policy,callable $body)
{
    $u=new SoSecurity\Support\SqlTransaction($e->pdo,$e->clock,10000);$l=new SoSecurity\Account\Ledger($u,'account-factor-recovery:'.hash('sha256','managed-test'),'tenant',str_repeat('e',64),$e->keys,$policy,2,$f->binding());return $u->run(static function()use($l,$body){return $body($l);});
}
function migrationPolicySetup(ManagedEnvironment $e,SoSecurity\Account\Policy $policy):array
{
    $legacy=$e->factors;$f=purgeFence($e);migrationPolicyLedger($e,$f,$policy,static function($l):void{$l->initialize();});$provider=new SoSecurity\Account\FactorWorkerAuthority($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$f,static function():bool{return true;},$policy,$e->clock);$m=$legacy->managedRegistered('managed-test','tenant',str_repeat('e',64),$e->keys,$f,$provider);$e->factors=$m;$e->registry=new SoSecurity\Account\FactorRegistry($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->accounts,$m,static function():bool{return true;},static function():bool{return true;},$policy,$e->clock,$f);return [$f,$legacy,$m];
}
