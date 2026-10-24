<?php
declare(strict_types=1);
require __DIR__.'/permission-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $login=$x->login();$token=$login->credential()->token();$queries=$x->e->pdo->queries;$policy=permissionPolicy($x);Check::same($queries,$x->e->pdo->queries);$r=permissionRequest($token);
    $lookups=$x->lookups;$seen=entryFiles($x);$revision=$x->inspect()['revision'];$persists=0;$x->persistHook=static function()use(&$persists):bool{++$persists;return true;};
    try{$value=permissionRun($x,$policy,$r,static function()use($x):string{Check::same(true,$x->boundary->active());return $x->e->registry->current('user')->factorId();});}finally{$x->persistHook=null;}
    Check::same(32,strlen($value));Check::same(2,$persists);Check::same($revision+1,$x->inspect()['revision']);Check::same('current',$x->inspect()['status']);Check::same($lookups,$x->lookups);Check::same($seen,entryFiles($x));
    $x->e->clock->time+=5;
    permissionRefuse($x,$policy,permissionRequest($token,['missing_role']));
    $bad=substr($token,0,-1).(substr($token,-1)==='a'?'b':'a');permissionRefuse($x,$policy,permissionRequest($bad));
    permissionRefuse($x,$policy,permissionRequest($token,[],'different-subject'));
    // An ordinary denial leaves this authority available for the next valid operation.
    Check::same('allowed',permissionRun($x,$policy,$r,static function():string{return 'allowed';}));
    $before=permissionState($x);$queries=$x->e->pdo->queries;
    foreach([['other.action','tenant','user'],['account.review','tenant','other-target'],['account.review','foreign','user']] as $wrong){Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($x,$policy,$r,$wrong):void{$x->boundary->authorized($wrong[0],$wrong[1],$wrong[2],$policy,$r,static function():void{throw new RuntimeException('Must not enter mismatched permission effects.');});});Check::same($queries,$x->e->pdo->queries);}
    Check::same($before,permissionState($x));
    foreach([$policy,$r] as $sensitive){foreach([var_export($sensitive,true),print_r($sensitive,true),json_encode($sensitive)] as $dump){Check::same(false,strpos($dump,$token)!==false);Check::same(false,strpos($dump,$x->e->directory)!==false);}Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($sensitive):void{serialize($sensitive);});}
    $x->e->clock->time+=301;permissionRefuse($x,$policy,$r);
});
echo 'PASS witnessed read-only account permissions: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; real password/MFA registry, exact action/scope/target, roles and token denial before pending, unchanged seen/factor/proofs, no provider callbacks and immediate valid retry\n";
