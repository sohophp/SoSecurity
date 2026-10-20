<?php
declare(strict_types=1);
require dirname(__DIR__,2).'/vendor/autoload.php';
require __DIR__.'/resolution-support.php';
function revocationSetup(ManagedEnvironment $e):SoSecurity\Account\LocalEpochFence
{
    list($f,$legacy)=migrationSetup($e);$migration=migrationService($e,$legacy,$f);$v=$migration->review('user','owned-review',migrationStop());$migration->execute($v,'owned-migrate',migrationProof());return $f;
}
function revocationService(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,?callable $authority=null,?callable $budget=null,?callable $approval=null,?callable $audit=null,?callable $event=null,bool $provision=true):SoSecurity\Account\FactorRevocation
{
    if($provision){$e->pdo->exec('DROP TABLE IF EXISTS factor_privileged_audit');$e->pdo->exec('CREATE TABLE factor_privileged_audit(operation VARCHAR(64) NOT NULL PRIMARY KEY,subject VARCHAR(256) NOT NULL)'.((($GLOBALS['argv'][1]??'')==='mysql')?' ENGINE=InnoDB':''));}$queue=lifecycleQueue($e,'factor-privileged-revocation');
    return $e->registry->privilegedRevocation($f,$authority??static function():bool{return true;},$budget??static function():bool{return true;},$approval??static function():bool{return true;},static function(array $v,array $before,array $after)use($e,$audit):bool{$q=$e->pdo->prepare('INSERT INTO factor_privileged_audit VALUES(?,?)');$q->execute([$v['operation'],$v['subject']]);$q->closeCursor();return $audit===null||$audit($v,$before,$after)===true;},static function(string $type,array $v,array $before,array $after)use($e,$queue,$event):bool{$queue->enqueue(new SoSecurity\Outbox\Message('tenant','factor-privileged-revocation',SoSecurity\Outbox\Message::identifier($type.':'.$v['operation'],$e->clock->time),'mail',$type,$v['subject'],$v['operation']),'system');return $event===null||$event($type,$v,$before,$after)===true;});
}
function revocationState(ManagedEnvironment $e):array
{
    $s=[];foreach(['account_example','sosecurity_account_roots','sosecurity_account_records','sosecurity_outbox_roots','sosecurity_outbox_records','factor_privileged_audit'] as $table){$s[$table]=$e->observer->query('SELECT * FROM '.$table)->fetchAll(PDO::FETCH_ASSOC);}return $s;
}

function revocationReason(string $reason,callable $work):void
{
    ++Check::$assertions;try{$work();}catch(SoSecurity\Exception\ValidationException $error){Check::same($reason,$error->reason());return;}throw new RuntimeException('Expected '.$reason);
}
