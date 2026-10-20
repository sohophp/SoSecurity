<?php
declare(strict_types=1);
require __DIR__.'/purge-support.php';
function workerWitness(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f):string
{
    return purgeLedger($e,$f,static function($l):string{return SoSecurity\Account\Ledger::digest($l->checkpoint());});
}
function workerService(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,array &$receipt):SoSecurity\Account\FactorRecovery
{
    $queue=new SoSecurity\Outbox\SqlOutbox($e->pdo,'managed-test',str_repeat('e',64),$e->keys,static function():bool{return true;},new SoSecurity\Outbox\Policy(),$e->clock,static function():bool{return true;});
    return $e->registry->recovery(static function():bool{return true;},static function():bool{return true;},switchApproval($receipt),static function(string $type,string $scope,$before,$after,string $selector)use($queue,$e):bool{$queue->enqueue(new SoSecurity\Outbox\Message($scope,'factor-recovery',SoSecurity\Outbox\Message::identifier($type.':'.$selector,$e->clock->time),'mail',$type,$selector,$selector),'system');return true;},$f);
}
function workerAudit(ManagedEnvironment $e):callable
{
    $e->pdo->exec('DROP TABLE IF EXISTS factor_worker_audit');
    $e->pdo->exec('CREATE TABLE factor_worker_audit(operation VARCHAR(64) NOT NULL PRIMARY KEY,context_digest VARCHAR(64) NOT NULL,before_digest VARCHAR(64) NOT NULL,after_digest VARCHAR(64) NOT NULL)'.(($GLOBALS['argv'][1]??'')==='mysql'?' ENGINE=InnoDB':''));
    $queue=new SoSecurity\Outbox\SqlOutbox($e->pdo,'managed-test',str_repeat('e',64),$e->keys,static function():bool{return true;},new SoSecurity\Outbox\Policy(),$e->clock,static function():bool{return true;});
    return static function(array $context,string $operation,array $before,array $after)use($e,$queue):bool{
        $q=$e->pdo->prepare('INSERT INTO factor_worker_audit VALUES(?,?,?,?)');$q->execute([$operation,hash('sha256',json_encode($context)),SoSecurity\Account\Ledger::digest($before),SoSecurity\Account\Ledger::digest($after)]);$q->closeCursor();
        $queue->enqueue(new SoSecurity\Outbox\Message('tenant','factor-recovery',SoSecurity\Outbox\Message::identifier('factor_workers_rotated:'.$operation,$e->clock->time),'mail','factor_workers_rotated',$operation,$operation),'system');return true;
    };
}
function workerAuditCount(ManagedEnvironment $e):int {return (int)$e->observer->query('SELECT COUNT(*) FROM factor_worker_audit')->fetchColumn();}
function workerHistory(ManagedEnvironment $e,callable $op)
{
    $u=new SoSecurity\Support\SqlTransaction($e->pdo,$e->clock,10000);$l=new SoSecurity\Account\Ledger($u,'account-factor-worker-receipts:'.hash('sha256','managed-test'),'tenant',str_repeat('e',64),$e->keys,new SoSecurity\Account\Policy());return $u->run(static function()use($l,$op){return $op($l);});
}

function workerOldReader(ManagedEnvironment $e):void
{
    $before=$e->observer->query('SELECT namespace,format,revision,entries,history_digest FROM sosecurity_account_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC);$owner=bin2hex(random_bytes(16));file_put_contents($e->directory.'/old-reader-owner',$owner);chmod($e->directory.'/old-reader-owner',0600);$pipes=[];$p=proc_open('exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/purge-old-reader.php'),[['pipe','r'],['pipe','w'],['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned legacy reader did not start.');}
    fwrite($pipes[0],json_encode(['directory'=>$e->directory,'owner'=>$owner,'time'=>$e->clock->time,'mysql'=>($GLOBALS['argv'][1]??'')==='mysql']));fclose($pipes[0]);$out=stream_get_contents($pipes[1]);$error=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$exit=proc_close($p);if($exit!==0){throw new RuntimeException('Actual legacy reader failed: '.$error);}Check::same(0,$exit);Check::same('',$error);Check::same("PASS actual legacy Ledger format refusal: 2 assertions\n",$out);Check::same($before,$e->observer->query('SELECT namespace,format,revision,entries,history_digest FROM sosecurity_account_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC));
}
