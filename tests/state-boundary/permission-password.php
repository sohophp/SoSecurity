<?php
declare(strict_types=1);
require __DIR__.'/permission-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $old=$x->login();$policy=permissionPolicy($x);
    $x->boundary->run('owned.normal-disable',static function()use($x):void{$review=$x->operations->review('disable','user','owned-policy-review');$done=$x->operations->execute($review,'owned-policy-disable',normalProof(),normalFactor($x->e));Check::same(true,$done['completed']);});
    permissionRefuse($x,$policy,permissionRequest($old->credential()->token()));
    $login=$x->auth->password('tenant','owned-password-policy-browser','owned@example.test',$x->e->password,'Owned password-only device');Check::same('authenticated',$login->status());$token=$login->credential()->token();
    permissionRefuse($x,$policy,permissionRequest($token));
    $explicit=new SoSecurity\Account\StatePermission('account.review','tenant','user','user',$token,[],1,300,true,true);
    $before=entryFiles($x);Check::same('explicit-password-strength',permissionRun($x,$policy,$explicit,static function():string{return 'explicit-password-strength';}));Check::same($before,entryFiles($x));
});
echo 'PASS explicit password permission profile: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; actual approved MFA disable, old strong identity refused, new password-only login denied by default and admitted only at explicit strength1\n";
