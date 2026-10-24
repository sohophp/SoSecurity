<?php
declare(strict_types=1);
require __DIR__.'/permission-support.php';$mode=$argv[2]??'roles';
entryCase(static function(EntryEnvironment $x)use($mode):void{
    $login=$x->login();$token=$login->credential()->token();$policy=permissionPolicy($x);$roles=$mode==='roles'?['missing_role']:[];
    if($mode==='credential'){$x->boundary->run('owned.credential-version',static function()use($x):void{$x->e->pdo->exec("UPDATE account_example SET credential_version='owned-new-credential-version' WHERE scope='tenant' AND subject='user'");});}
    $r=permissionRequest($token,$roles);$before=permissionState($x);$error=null;$calls=0;
    try{permissionRun($x,$policy,$r,static function()use($x,&$calls):void{++$calls;$q=$x->e->pdo->prepare('INSERT INTO entry_worker_audit VALUES(?,?)');$q->execute([hash('sha256','unsafe-permission-effect'),hash('sha256','effect-performed')]);$q->closeCursor();});}catch(Throwable $caught){$error=$caught;}
    if($calls!==0){Check::same(1,(int)$x->e->observer->query('SELECT COUNT(*) FROM entry_worker_audit')->fetchColumn());throw new RuntimeException($mode==='roles'?'UNSAFE_STATE_PERMISSION_ALLOWED_MISSING_CURRENT_ROLE':'UNSAFE_STATE_PERMISSION_ACCEPTED_REVOKED_CREDENTIAL_IDENTITY');}
    $after=$x->inspect();if($after['status']==='pending'&&$error instanceof SoSecurity\Storage\StorageException&&$error->reason()==='account.completion_unknown'){throw new RuntimeException('UNSAFE_PERMISSION_DENIAL_POISONED_WITNESS');}
    Check::same(true,$error instanceof SoSecurity\Exception\SecurityException);Check::same('account.state_denied',$error->reason());Check::same($before,permissionState($x));Check::same('current',$after['status']);Check::same(false,$x->boundary->active());
});
echo 'PASS fixed permission enforcement: '.Check::$assertions.' assertions '.$mode.' PHP '.PHP_VERSION."; actual unauthorized SQL effect refused, normal denial preserves current authority\n";
