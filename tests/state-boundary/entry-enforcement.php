<?php
declare(strict_types=1);
require __DIR__.'/entry-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $called=false;$error=null;$before=entryFiles($x);try{$x->boundary->protect($x->store)->transact('must-not-write',static function()use(&$called):SoSecurity\Storage\Change{$called=true;return new SoSecurity\Storage\Change(['unexpected'=>'write'],0,true);});}catch(Throwable $caught){$error=$caught;}
    if($called){throw new RuntimeException('UNSAFE_PROTECTED_STORE_ENTERED_WITHOUT_WITNESS');}Check::same(true,$error instanceof SoSecurity\Storage\StorageException);Check::same($before,entryFiles($x));
});
entryCase(static function(EntryEnvironment $x):void{
    $x->currentAllowed=false;$result=null;$error=null;try{$result=$x->auth->password('tenant','browser','owned@example.test',$x->e->password);}catch(Throwable $caught){$error=$caught;}
    if($result!==null&&$result->status()==='mfa_required'){throw new RuntimeException('UNSAFE_AUTHENTICATION_CURRENT_AUTHORITY_SKIPPED');}Check::same(true,$error instanceof SoSecurity\Exception\SecurityException);Check::same('auth.request_denied',$error->reason());Check::same(0,$x->lookups);Check::same('current',$x->inspect()['status']);
});
entryCase(static function(EntryEnvironment $x):void{
    $e=$x->e;$bound=entryPromote($x);$receipts=[];$service=workerService($e,$bound,$receipts);$trusted=$x->boundary->run('workers.review',static function()use($e,$bound):string{return workerWitness($e,$bound);});
    $dir=$e->directory.'/entry-unsafe-unbound';mkdir($dir,0700);$unbound=new SoSecurity\Account\LocalEpochFence($dir,'managed-test','tenant',str_repeat('e',64),$e->keys,static function($h)use($dir):bool{return witnessPersist($h,$dir);});$unbound->initialize();
    $before=$e->observer->query('SELECT namespace,policy,revision,history_digest FROM sosecurity_account_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC);$rotated=null;$error=null;
    try{$rotated=$x->boundary->run('workers.refuse-downgrade',static function()use($service,$unbound,$trusted):array{return $service->rotateWorkers($unbound,$trusted,'owned-attempt',static function():bool{return true;},static function():bool{return true;});});}catch(Throwable $caught){$error=$caught;}
    if($rotated!==null&&$rotated['changed']){lifecycleRebind($e,$unbound,lifecycleRaw($e));if($e->registry->current('user')->enabled()){throw new RuntimeException('UNSAFE_WORKER_ROTATION_REMOVED_REQUIRED_STATE_BOUNDARY');}}
    Check::same(true,$error instanceof SoSecurity\Storage\StorageException);Check::same('account.completion_unknown',$error->reason());Check::same($before,$e->observer->query('SELECT namespace,policy,revision,history_digest FROM sosecurity_account_roots ORDER BY namespace')->fetchAll(PDO::FETCH_ASSOC));Check::same(false,$x->boundary->active());
});
echo 'PASS entry enforcement: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; no unguarded store I/O, mandatory current request authority and live registered worker downgrade refusal\n";
