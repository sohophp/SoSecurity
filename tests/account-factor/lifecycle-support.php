<?php
declare(strict_types=1);
require __DIR__.'/migration-maintenance-support.php';
/** Preserve already committed migration/history notices when adding another workflow. */
function lifecycleQueue(ManagedEnvironment $e,string $producer):SoSecurity\Outbox\SqlOutbox
{
    $q=new SoSecurity\Outbox\SqlOutbox($e->pdo,'managed-test',str_repeat('e',64),$e->keys,static function():bool{return true;},null,$e->clock,static function():bool{return true;});$q->initialize('tenant',$producer,'system');return $q;
}
function lifecycleOperations(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,?callable $approval=null):SoSecurity\Account\FactorOperations
{
    lifecycleQueue($e,'factor-recovery');$s=normalOperations($e,$f,$approval,null,null,null,false);$s->initialize();return $s;
}
function lifecycleRecovery(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,array &$receipt):SoSecurity\Account\FactorRecovery
{
    $queue=lifecycleQueue($e,'factor-recovery');$s=$e->registry->recovery(static function():bool{return true;},static function():bool{return true;},switchApproval($receipt),static function(string $type,string $scope,$before,$after,string $operation)use($e,$queue):bool{$queue->enqueue(new SoSecurity\Outbox\Message($scope,'factor-recovery',SoSecurity\Outbox\Message::identifier($type.':'.$operation,$e->clock->time),'mail',$type,$operation,$operation),'system');return true;},$f);$s->initialize();return $s;
}
function lifecycleRebind(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,SoSecurity\Mfa\TotpFactors $raw):SoSecurity\Account\FactorMigration
{
    $e->factors=$raw->managedRegistered('managed-test','tenant',str_repeat('e',64),$e->keys,$f,registeredProvider($e,$f));$e->registry=new SoSecurity\Account\FactorRegistry($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->accounts,$e->factors,static function():bool{return true;},static function():bool{return true;},null,$e->clock,$f);return migrationService($e,$raw,$f,null,null,null,null,null,null,false);
}
function lifecycleRaw(ManagedEnvironment $e):SoSecurity\Mfa\TotpFactors{return new SoSecurity\Mfa\TotpFactors(modeStore($e),new SoSecurity\Crypto\Cipher('test',['test'=>str_repeat('t',32)],'managed-test'),'Managed test',$e->clock);}
function lifecycleRetirementAudit(ManagedEnvironment $e):callable
{
    $e->pdo->exec('DROP TABLE IF EXISTS lifecycle_retirement_audit');$e->pdo->exec('CREATE TABLE lifecycle_retirement_audit(operation VARCHAR(32) NOT NULL PRIMARY KEY,subject VARCHAR(256) NOT NULL,status VARCHAR(16) NOT NULL)'.((($GLOBALS['argv'][1]??'')==='mysql')?' ENGINE=InnoDB':''));return static function(string $scope,string $subject,$record,$slot,string $operation,string $stamp)use($e):bool{Check::same('tenant',$scope);$q=$e->pdo->prepare('INSERT INTO lifecycle_retirement_audit VALUES(?,?,?)');$q->execute([$operation,$subject,$record===null?'missing':$record->status()]);$q->closeCursor();return true;};
}
