<?php
declare(strict_types=1);
require __DIR__.'/permission-support.php';
entryCase(static function(EntryEnvironment $x):void{
    // A new genuine login sees the current server roles/version, not a cached actor.
    $x->boundary->run('owned.operator-role',static function()use($x):void{$x->e->pdo->exec("UPDATE account_example SET roles='[\"operator\"]',credential_version='owned-role-version' WHERE scope='tenant' AND subject='user'");});
    $login=$x->login();$token=$login->credential()->token();$policy=permissionPolicy($x);$r=permissionRequest($token,['operator'],'another-subject',false);
    Check::same('operator-allowed',permissionRun($x,$policy,$r,static function():string{return 'operator-allowed';}));
    $x->boundary->run('owned.remove-role',static function()use($x):void{$x->e->pdo->exec("UPDATE account_example SET roles='[]',credential_version='owned-role-revocation' WHERE scope='tenant' AND subject='user'");});permissionRefuse($x,$policy,$r);
    // Definitive account disablement is also a read-only denial, without session pruning.
    $fresh=$x->login();$r=permissionRequest($fresh->credential()->token());$x->boundary->run('owned.disable-account',static function()use($x):void{$x->e->pdo->exec("UPDATE account_example SET status='disabled' WHERE scope='tenant' AND subject='user'");});permissionRefuse($x,$policy,$r);
});
entryCase(static function(EntryEnvironment $x):void{
    $login=$x->login();$grant=$x->remember->issue('tenant','user',$login->credential()->token(),'Owned permission device');$resumed=$x->remember->resume('tenant',$grant->token());Check::same('authenticated',$resumed->status());$token=$resumed->session()->token();$policy=permissionPolicy($x);
    permissionRefuse($x,$policy,permissionRequest($token));
    $explicit=new SoSecurity\Account\StatePermission('account.review','tenant','user','user',$token,[],2,300,false,true);
    $before=entryFiles($x);Check::same('explicit-recent-resume',permissionRun($x,$policy,$explicit,static function():string{return 'explicit-recent-resume';}));Check::same($before,entryFiles($x));
    Check::same(true,$x->sessions->revoke('tenant','user',$resumed->session()->id()));permissionRefuse($x,$policy,$explicit);
});
entryCase(static function(EntryEnvironment $x):void{
    $login=$x->login();$token=$login->credential()->token();$policy=permissionPolicy($x);$slot=$x->boundary->run('owned.read-slot',static function()use($x){return $x->e->registry->current('user');});
    // An owned test mutation commits an authenticated physical tombstone while
    // leaving the directory/session as-is. The fixed evaluator must reject it.
    $x->boundary->run('owned.physical-tombstone',static function()use($x,$slot):void{$x->e->factors->revoke($slot->slotScope(),$slot->slotSubject());});permissionRefuse($x,$policy,permissionRequest($token));
});
echo 'PASS current actor permission state: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; live operator roles, disabled account, explicit resumed-session exception, session revocation and current physical factor tombstone before pending\n";
