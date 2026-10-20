<?php
declare(strict_types=1);
require __DIR__.'/registered-support.php';
function migrationSetup(ManagedEnvironment $e,bool $directory=false,?callable $permission=null):array
{
    $legacy=$e->factors;if($directory){$e->registry->initialize('user');}$f=purgeFence($e);purgeLedger($e,$f,static function($l):void{$l->initialize();});
    $m=$legacy->managedRegistered('managed-test','tenant',str_repeat('e',64),$e->keys,$f,registeredProvider($e,$f,$permission));
    $r=new SoSecurity\Account\FactorRegistry($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->accounts,$m,static function():bool{return true;},static function():bool{return true;},null,$e->clock,$f);$e->factors=$m;$e->registry=$r;return [$f,$legacy,$m,$r];
}
function migrationProof():array {return ['type'=>'approved','code'=>'owned-independent-migration-approval'];}
function migrationService(ManagedEnvironment $e,SoSecurity\Mfa\TotpFactors $legacy,SoSecurity\Account\LocalEpochFence $f,?callable $authority=null,?callable $budget=null,?callable $approval=null,?callable $stopped=null,?callable $auditHook=null,?callable $eventHook=null,bool $provision=true):SoSecurity\Account\FactorMigration
{
    $mysql=($GLOBALS['argv'][1]??'')==='mysql';
    if($provision){
        foreach(['sosecurity_outbox_records','sosecurity_outbox_roots','factor_migration_audit'] as $table){$e->pdo->exec('DROP TABLE IF EXISTS '.$table);}
        $ddl=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__,2).'/resources/sql/outbox-'.($mysql?'mysql':'sqlite').'.sql'));foreach(explode(';',$ddl) as $sql){if(trim($sql)!==''){$e->pdo->exec($sql);}}
        $e->pdo->exec('CREATE TABLE factor_migration_audit(operation VARCHAR(64) NOT NULL,phase VARCHAR(32) NOT NULL,context_digest VARCHAR(64) NOT NULL,PRIMARY KEY(operation,phase,context_digest))'.($mysql?' ENGINE=InnoDB':''));
    }
    $queue=new SoSecurity\Outbox\SqlOutbox($e->pdo,'managed-test',str_repeat('e',64),$e->keys,static function():bool{return true;},null,$e->clock,static function():bool{return true;});if($provision){$queue->initialize('tenant','factor-migration','system');}
    return $e->registry->migration($legacy,$f,$authority??static function():bool{return true;},$budget??static function():bool{return true;},$approval??static function():bool{return true;},$stopped??static function():bool{return true;},static function(string $phase,array $review,$before,$after,string $op)use($e,$auditHook):bool{
        $q=$e->pdo->prepare('INSERT INTO factor_migration_audit(operation,phase,context_digest) VALUES(?,?,?)');$q->execute([$op,$phase,hash('sha256',json_encode($review))]);$q->closeCursor();return $auditHook===null||$auditHook($phase,$review,$before,$after)===true;
    },static function(string $type,string $scope,$before,$after,string $op,array $review)use($e,$queue,$eventHook):bool{$queue->enqueue(new SoSecurity\Outbox\Message($scope,'factor-migration',SoSecurity\Outbox\Message::identifier($type.':'.$op.':'.$review['nonce'],$e->clock->time),'mail',$type,$op,$op),'system');return $eventHook===null||$eventHook($type,$review,$before,$after)===true;});
}
function migrationStop():string {return hash('sha256','owned local old-deployment stop evidence');}
function migrationReason(string $reason,callable $work):void
{
    ++Check::$assertions;try{$work();}catch(SoSecurity\Exception\SecurityException $error){Check::same($reason,$error->reason());return;}throw new RuntimeException('Expected '.$reason);
}
