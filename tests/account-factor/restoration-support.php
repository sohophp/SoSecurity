<?php
declare(strict_types=1);
require dirname(__DIR__,2).'/vendor/autoload.php';
require __DIR__.'/revocation-support.php';
function restorationSetup(ManagedEnvironment $e,string $origin='revoked'):SoSecurity\Account\LocalEpochFence
{
    $f=revocationSetup($e);
    if($origin==='revoked'){$r=revocationService($e,$f);$v=$r->review('user','owned-revoke-before-restoration');$r->execute($v['context'],'owned-lost-factor',normalProof());$f=migrationHistoryRotate($e,$f);lifecycleRebind($e,$f,lifecycleRaw($e));}
    else{$e->pdo->exec("UPDATE account_example SET status='disabled' WHERE scope='tenant' AND subject='user'");$e->registry->retire('user',lifecycleRetirementAudit($e));$e->pdo->exec("UPDATE account_example SET status='active',credential_version='owned-reactivated-version' WHERE scope='tenant' AND subject='user'");}
    return $f;
}
function restorationService(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,?callable $authority=null,?callable $budget=null,?callable $approval=null,?callable $audit=null,?callable $event=null,bool $provision=true):SoSecurity\Account\FactorRestoration
{
    if($provision){$e->pdo->exec('DROP TABLE IF EXISTS factor_restoration_audit');$e->pdo->exec('CREATE TABLE factor_restoration_audit(operation VARCHAR(64) NOT NULL,phase VARCHAR(32) NOT NULL,nonce VARCHAR(64) NOT NULL,PRIMARY KEY(operation,phase,nonce))'.((($GLOBALS['argv'][1]??'')==='mysql')?' ENGINE=InnoDB':''));}$q=lifecycleQueue($e,'factor-restoration');
    return $e->registry->restoration($f,$authority??static function():bool{return true;},$budget??static function():bool{return true;},$approval??static function():bool{return true;},static function(string $phase,array $v,array $before,array $after)use($e,$audit):bool{$q=$e->pdo->prepare('INSERT INTO factor_restoration_audit VALUES(?,?,?)');$q->execute([$v['operation'],$phase,$v['nonce']]);$q->closeCursor();return $audit===null||$audit($phase,$v,$before,$after)===true;},static function(string $type,array $v,array $before,array $after)use($e,$q,$event):bool{$q->enqueue(new SoSecurity\Outbox\Message('tenant','factor-restoration',SoSecurity\Outbox\Message::identifier($type.':'.$v['nonce'],$e->clock->time),'mail',$type,$v['operation'],$v['operation']),'system');return $event===null||$event($type,$v,$before,$after)===true;});
}
function restorationPrepared(ManagedEnvironment $e,SoSecurity\Account\FactorRestoration $r):array
{
    $v=$r->review('user','owned-new-factor-review');$en=$r->begin($v,'owned-prepare-new-factor',normalProof());parse_str(parse_url($en->enrollment()->provisioningUri(),PHP_URL_QUERY),$parts);return [$v,$en,$parts['secret']];
}
function restorationProven(ManagedEnvironment $e,SoSecurity\Account\FactorRestoration $r):array
{
    list($v,$en,$secret)=restorationPrepared($e,$r);$e->clock->time=(intdiv($e->clock->time,30)+1)*30;$codes=$r->prove($v['operation'],(new SoSecurity\Mfa\Totp())->codeAt($secret,$e->clock->time),'owned-new-factor-proof');Check::same(true,is_array($codes)&&count($codes)>0);return [$v,$secret,$codes];
}

function restorationRotate(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $old):SoSecurity\Account\LocalEpochFence
{
    lifecycleQueue($e,'factor-recovery');$receipt=[];$workers=workerService($e,$old,$receipt);$next=purgeFence($e,'authority-restoration-'.bin2hex(random_bytes(8)));Check::same(true,$workers->rotateWorkers($next,workerWitness($e,$old),'owned-restoration-worker-switch',static function():bool{return true;},workerAudit($e))['changed']);return $next;
}

function restorationPhysical(ManagedEnvironment $e,array $v):?array
{
    return modeStore($e)->transact(SoSecurity\Support\Guard::key('mfa-totp',$v['slot_scope'],$v['slot_subject']),static function($value):SoSecurity\Storage\Change{return new SoSecurity\Storage\Change($value,0,$value);});
}

function restorationHistory(ManagedEnvironment $e,SoSecurity\Account\FactorRestoration $r):SoSecurity\Account\FactorIntentMaintenance
{
    $e->pdo->exec('DROP TABLE IF EXISTS restoration_history_audit');$e->pdo->exec('CREATE TABLE restoration_history_audit(operation VARCHAR(64) NOT NULL PRIMARY KEY,mode VARCHAR(16) NOT NULL)'.((($GLOBALS['argv'][1]??'')==='mysql')?' ENGINE=InnoDB':''));$queue=lifecycleQueue($e,'factor-restoration-history');
    return $r->maintenance(static function():bool{return true;},static function():bool{return true;},static function():bool{return true;},static function(array $v,array $counts,string $id)use($e):bool{$q=$e->pdo->prepare('INSERT INTO restoration_history_audit VALUES(?,?)');$q->execute([$id,$v['mode']]);$q->closeCursor();return true;},static function(string $type,array $v,array $counts,string $id)use($e,$queue):bool{$queue->enqueue(new SoSecurity\Outbox\Message('tenant','factor-restoration-history',SoSecurity\Outbox\Message::identifier($type.':'.$id,$e->clock->time),'mail',$type,$id,$id),'system');return true;});
}

function restorationState(ManagedEnvironment $e):array
{
    $s=[];foreach(['account_example','sosecurity_account_roots','sosecurity_account_records','sosecurity_outbox_roots','sosecurity_outbox_records','factor_restoration_audit'] as $table){$s[$table]=$e->observer->query('SELECT * FROM '.$table)->fetchAll(PDO::FETCH_ASSOC);}return $s;
}
