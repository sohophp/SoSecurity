<?php
declare(strict_types=1);
require __DIR__.'/rollover-support.php';
function receiptChain(ManagedEnvironment $e,int $count=3):array
{
    $e->registry->initialize('user');$receipt=[];$first=purgeFence($e);$service=switchService($e,switchApproval($receipt),null,null,null,$first);$service->initialize();$audit=workerAudit($e);$authorities=[$first];$services=[$service];$witnesses=[];$results=[];
    for($i=0;$i<$count;++$i){$next=purgeFence($e,'authority-next-'.$i);$witness=workerWitness($e,$authorities[$i]);$result=$services[$i]->rotateWorkers($next,$witness,'owned-manager',static function():bool{return true;},$audit);$authorities[]=$next;$services[]=workerService($e,$next,$receipt);$witnesses[]=$witness;$results[]=$result;}
    return ['service'=>$services[$count],'fence'=>$authorities[$count],'authorities'=>$authorities,'services'=>$services,'witnesses'=>$witnesses,'results'=>$results];
}
function receiptAudit(ManagedEnvironment $e):callable
{
    $e->pdo->exec('DROP TABLE IF EXISTS factor_receipt_audit');$e->pdo->exec('CREATE TABLE factor_receipt_audit(operation VARCHAR(64) NOT NULL PRIMARY KEY,purpose VARCHAR(64) NOT NULL,affected INT NOT NULL)'.(($GLOBALS['argv'][1]??'')==='mysql'?' ENGINE=InnoDB':''));
    $queue=new SoSecurity\Outbox\SqlOutbox($e->pdo,'managed-test',str_repeat('e',64),$e->keys,static function():bool{return true;},new SoSecurity\Outbox\Policy(),$e->clock,static function():bool{return true;});
    return static function(array $context,string $operation,array $counts)use($e,$queue):bool{
        $q=$e->pdo->prepare('INSERT INTO factor_receipt_audit VALUES(?,?,?)');$q->execute([$operation,$context['purpose'],$counts['removed']+$counts['resealed']+(int)$counts['root_rotated']]);$q->closeCursor();
        $queue->enqueue(new SoSecurity\Outbox\Message('tenant','factor-recovery',SoSecurity\Outbox\Message::identifier('factor_worker_receipts:'.$operation,$e->clock->time),'mail','factor_worker_receipts',$operation,$operation),'system');return true;
    };
}
function receiptAuditCount(ManagedEnvironment $e):int {return (int)$e->observer->query('SELECT COUNT(*) FROM factor_receipt_audit')->fetchColumn();}
function receiptRows(ManagedEnvironment $e):array {return workerHistory($e,static function($l):array{return $l->bodyPage(50);});}
function receiptDualService(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,SoSecurity\Support\HmacKeys $keys):SoSecurity\Account\FactorRecovery
{
    $registry=$e->build($keys);return $registry->recovery(static function():bool{return true;},static function():bool{return true;},static function():bool{return false;},static function():bool{return true;},$f);
}
/** Signed synthetic history for fault injection; receipts.php separately creates actual authority transitions. */
function receiptFixture(ManagedEnvironment $e,int $count=3):array
{
    $e->registry->initialize('user');$f=purgeFence($e);$receipt=[];$s=switchService($e,switchApproval($receipt),null,null,null,$f);$s->initialize();
    workerHistory($e,static function($l)use($e,$f,$count):void{
        $l->initialize();$owner=hash('sha256',json_encode(['SoSecurity.Account.WorkerRotation.Owner.1','managed-test','tenant'],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        for($i=0;$i<$count;++$i){$c=['format'=>1,'purpose'=>'factor_worker_rotation','site'=>'managed-test','scope'=>'tenant','epoch'=>str_repeat('e',64),'from'=>hash('sha256','owned-source-'.$i),'to'=>$i===$count-1?$f->binding():hash('sha256','owned-old-target-'.$i),'root'=>hash('sha256','owned-external-root-'.$i)];$payload=json_encode($c,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);$id=hash('sha256','SoSecurity.Account.WorkerRotation.1.'.$payload);$l->put($id,$owner,'budget',$payload,$e->clock->time+10);}
    });$e->clock->time+=10;return ['service'=>$s,'fence'=>$f];
}

function receiptRowsWithKeys(ManagedEnvironment $e,SoSecurity\Support\HmacKeys $keys):array
{
    $u=new SoSecurity\Support\SqlTransaction($e->pdo,$e->clock,10000);$l=new SoSecurity\Account\Ledger($u,'account-factor-worker-receipts:'.hash('sha256','managed-test'),'tenant',str_repeat('e',64),$keys,new SoSecurity\Account\Policy());return $u->run(static function()use($l):array{return $l->bodyPage(50);});
}
