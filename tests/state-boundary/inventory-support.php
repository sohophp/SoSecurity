<?php
declare(strict_types=1);
require_once __DIR__.'/entry-support.php';
function inventoryServices(ManagedEnvironment $e,bool $restore=false):array
{
    list($f,$legacy)=migrationSetup($e);$migration=migrationService($e,$legacy,$f);$v=$migration->review('user','owned-review',migrationStop());$migration->execute($v,'owned-migrate',migrationProof());
    if($restore){$r=revocationService($e,$f);$v=$r->review('user','owned-revoke-before-restoration');$r->execute($v['context'],'owned-lost-factor',normalProof());$f=migrationHistoryRotate($e,$f);$migration=lifecycleRebind($e,$f,lifecycleRaw($e));}
    $ops=lifecycleOperations($e,$f);$receipt=[];$rec=lifecycleRecovery($e,$f,$receipt);$r=restorationService($e,$f);return [$f,$ops,$r,$rec,$migration];
}
function inventoryBuild(ManagedEnvironment $e,array $s,?array &$parts=null,?SoSecurity\Account\FactorRecovery $other=null):SoSecurity\Account\StateFactorInventory
{
    $extra=['factor_restoration_audit'=>['columns'=>['operation'=>'bytes:64','phase'=>'bytes:32','nonce'=>'bytes:64'],'primary'=>['operation','phase','nonce']]];
    if($e->pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite'){$extra['factor_restoration_audit']['sqlite_declarations']=['operation'=>'VARCHAR(64)','phase'=>'VARCHAR(32)','nonce'=>'VARCHAR(64)'];}
    $source=ownedAuthenticationSource($e,$extra,null,$sources);$w=new SoSecurity\Account\LocalStateWitness($e->pdo,$e->directory.'/independent-witness','managed-test','tenant',str_repeat('e',64),$e->keys,$source,static function():bool{return true;},30000,3,str_repeat('7',64));$parts=['witness'=>$w,'source'=>$source,'sql'=>$sources['sql'],'files'=>$sources['files']];
    return new SoSecurity\Account\StateFactorInventory($w,$source,$sources['sql'],$sources['files'],'complete-sql','sessions-and-factors',$e->registry,$e->factors,$s[1],$s[2],$other??$s[3],$s[4],'managed-test','tenant',str_repeat('e',64),$e->keys,$e->clock);
}
function inventoryState(ManagedEnvironment $e):array
{
    $rows=[];foreach(['account_example','sosecurity_account_roots','sosecurity_account_records','sosecurity_outbox_roots','sosecurity_outbox_records','factor_migration_audit','factor_restoration_audit'] as $table){$rows[$table]=$e->observer->query('SELECT * FROM '.$table)->fetchAll(PDO::FETCH_ASSOC);}$rows['files']=[];foreach(new DirectoryIterator($e->directory.'/factors') as $f){if($f->isFile()){$rows['files'][$f->getFilename()]=hash_file('sha256',$f->getPathname());}}ksort($rows['files']);return $rows;
}
function inventoryLedger(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,callable $work):void
{
    $p=$e->registry->ledgerPolicy($e->keys);$u=new SoSecurity\Support\SqlTransaction($e->pdo,$e->clock,$p->ioMilliseconds());$l=new SoSecurity\Account\Ledger($u,'account-factor-recovery:'.hash('sha256','managed-test'),'tenant',str_repeat('e',64),$e->keys,$p,2,$f->binding());$u->run(static function()use($l,$work):void{$work($l);});
}

function inventoryReason(string $reason,callable $work):void{++Check::$assertions;try{$work();}catch(SoSecurity\Exception\SecurityException $e){Check::same($reason,$e->reason());return;}throw new RuntimeException('Expected '.$reason);}
