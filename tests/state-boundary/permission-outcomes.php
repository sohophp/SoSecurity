<?php
declare(strict_types=1);
require __DIR__.'/permission-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $login=$x->login();$r=permissionRequest($login->credential()->token());$policy=permissionPolicy($x);$error=null;
    try{permissionRun($x,$policy,$r,static function()use($x):void{$q=$x->e->pdo->prepare('INSERT INTO entry_worker_audit VALUES(?,?)');$q->execute([hash('sha256','effect-before-error'),hash('sha256','written')]);$q->closeCursor();throw new RuntimeException('Owned failure after actual SQL effect.');});}catch(Throwable $caught){$error=$caught;}
    Check::same(true,$error instanceof SoSecurity\Storage\StorageException);Check::same('account.completion_unknown',$error->reason());Check::same('pending',$x->inspect()['status']);Check::same(1,(int)$x->e->observer->query('SELECT COUNT(*) FROM entry_worker_audit')->fetchColumn());Check::same(false,$x->boundary->active());
    $called=false;witnessReason('account.witness_pending',static function()use($x,$policy,$r,&$called):void{permissionRun($x,$policy,$r,static function()use(&$called):void{$called=true;});});Check::same(false,$called);
});
entryCase(static function(EntryEnvironment $x):void{
    $login=$x->login();$r=permissionRequest($login->credential()->token());$policy=permissionPolicy($x);$called=false;$error=null;$x->persistHook=static function():bool{return false;};
    try{permissionRun($x,$policy,$r,static function()use(&$called):void{$called=true;});}catch(Throwable $caught){$error=$caught;}finally{$x->persistHook=null;}
    Check::same(true,$error instanceof SoSecurity\Storage\StorageException);Check::same('account.completion_unknown',$error->reason());Check::same(false,$called);Check::same('pending',$x->inspect()['status']);Check::same(false,$x->boundary->active());
});
echo 'PASS approved permission effect outcomes: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; durable pending before effects, real SQL write then exception remains unknown, no automatic replay and lost pending receipt remains blocked\n";
