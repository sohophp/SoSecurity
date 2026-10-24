<?php
declare(strict_types=1);
require __DIR__.'/entry-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $protected=$x->boundary->protect($x->store);Check::same($protected,$x->boundary->protect($protected));Check::same(true,$protected->boundTo($x->boundary));$before=entryFiles($x);$queries=$x->e->pdo->queries;$called=false;
    witnessReason('account.state_required',static function()use($protected,&$called):void{$protected->transact('forbidden',static function()use(&$called):SoSecurity\Storage\Change{$called=true;return new SoSecurity\Storage\Change(null,0,true);});});Check::same(false,$called);Check::same($before,entryFiles($x));Check::same($queries,$x->e->pdo->queries);
    $foreign=new SoSecurity\Storage\FileStore($x->e->directory.'/snapshot-scratch','foreign');Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($x,$foreign):void{$x->boundary->protect($foreign);});
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($x,$protected):void{new SoSecurity\Auth\SessionRegistry($protected,$x->provider);});
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($x):void{new SoSecurity\Auth\AuthenticationFlow($x->store,$x->provider,$x->sessions,static function():bool{return true;},null,$x->e->clock,300,10,5,$x->boundary);});
    $root=$x->inspect();$login=$x->login();Check::same($root['revision']+2,$x->inspect()['revision']);Check::same(false,$x->boundary->active());
    Check::same([['public',false,'password','tenant'],['current',false,'password','tenant'],['public',false,'second_factor','tenant'],['current',false,'second_factor','tenant']],$x->guards);
    Check::same([['public','authentication.password'],['final','authentication.password'],['public','authentication.second_factor'],['final','authentication.second_factor']],$x->budgets);
    $oldToken=$login->credential()->token();$review=$x->auth->password('tenant','owned-entry-browser','owned@example.test',$x->e->password,'',$oldToken);Check::same('mfa_required',$review->status());
    $reauth=$x->auth->secondFactor('tenant','owned-entry-browser',$review->challenge(),normalFactor($x->e));Check::same('authenticated',$reauth->status());Check::same($login->credential()->id(),$reauth->credential()->id());Check::same(null,$x->sessions->verify('tenant','user',$oldToken));$login=$reauth;
    $token=$login->credential()->token();Check::same(true,$x->sessions->verify('tenant','user',$token,2)!==null);Check::same(1,count($x->sessions->all('tenant','user')));
    $remember=$x->remember->issue('tenant','user',$token,'Owned persistent device');Check::same(true,$remember instanceof SoSecurity\Auth\RememberCredential);Check::same(1,count($x->remember->all('tenant','user')));
    $resumed=$x->remember->resume('tenant',$remember->token());Check::same('authenticated',$resumed->status());Check::same(true,$resumed->session() instanceof SoSecurity\Auth\SessionCredential);
    Check::same(true,$x->remember->forget('tenant',$resumed->nextCredential()->token()));Check::same([], $x->remember->all('tenant','user'));
    $fresh=$x->login();$grant=$x->remember->issue('tenant','user',$fresh->credential()->token(),'revocation');Check::same(true,$x->remember->revoke('tenant','user',$grant->id()));Check::same('invalid',$x->remember->resume('tenant',$grant->token())->status());
    $x->auth->cancel('tenant','owned-entry-browser');$x->sessions->revokeAll('tenant','user');Check::same([], $x->sessions->all('tenant','user'));Check::same('current',$x->inspect()['status']);
    foreach([var_export($protected,true),print_r($protected,true),json_encode($protected)] as $dump){Check::same(false,strpos($dump,$x->e->directory)!==false);}Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($protected):void{serialize($protected);});
});
entryCase(static function(EntryEnvironment $x):void{
    $login=$x->login();$old=entryFiles($x);$token=$login->credential()->token();Check::same(true,$x->sessions->revoke('tenant','user',$login->credential()->id()));Check::same(null,$x->sessions->verify('tenant','user',$token,2));
    entryRestore($x,$old);$lookups=$x->lookups;$error=null;$authenticated=false;
    try{$authenticated=$x->sessions->verify('tenant','user',$token,2)!==null;}catch(Throwable $caught){$error=$caught;}
    if($authenticated){throw new RuntimeException('UNSAFE_AUTOMATIC_ENTRY_REAUTHENTICATED_REVOKED_SESSION');}
    Check::same(true,$error instanceof SoSecurity\Storage\StorageException);Check::same('account.witness_stale',$error->reason());Check::same($lookups,$x->lookups);Check::same(false,$x->boundary->active());
});
echo 'PASS automatic authentication entries: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; real password/MFA/session/remembered login, one outer checkpoint, live authority, guarded store/coverage and automatic old-state refusal before provider\n";
