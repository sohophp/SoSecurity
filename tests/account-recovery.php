<?php
declare(strict_types=1);
require __DIR__.'/recovery-support.php';
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
recoveryCase(static function(RecoveryEnvironment $r):void{
    $before=$r->e->account();$oldSession=$r->t->credential->token();$d=$r->begin();Check::same($before,$r->e->account());Check::same('recover_account',$d->notice()->type());Check::same('recover',$r->flow($d->selector())['purpose']);Check::same(true,$r->confirm($d));$after=$r->e->account();
    foreach(['scope','subject','address','address_version','roles','mfa_required','verified','status'] as $name){Check::same($before[$name],$after[$name]);}Check::same(true,$before['credential_version']!==$after['credential_version']);Check::same(true,$r->e->hasher->verify($r->password,$after['password']));Check::same(false,$r->e->hasher->verify($r->t->password,$after['password']));Check::same(null,$r->t->sessions->verify('tenant',$r->t->subject,$oldSession));Check::same('consumed',$r->flow($d->selector())['state']);Check::same(2,count($r->ids()));Check::same(null,$r->service->notification($d->notice()->id()));Check::same(false,$r->confirm($d));Check::same(1,$r->policyCalls);
    $success=$r->service->notification($r->ids()[1]);Check::same('password_changed',$success->notice()->type());Check::same('',$success->notice()->token());Check::same('',$success->selector());
    // Committed security notices retain their intended recipient after later credential/address changes.
    $r->e->pdo->exec("UPDATE account_example SET credential_version='later',address='later@example.com',address_version='later-address'");Check::same('owner@example.com',$r->service->notification($success->notice()->id())->notice()->recipient()->value());
});
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();$before=$r->e->account();$factor=$r->t->factors->status('tenant',$r->t->subject);Check::same(false,$r->confirm($d));Check::same($before,$r->e->account());Check::same(0,$r->policyCalls);Check::same(1,$r->flow($d->selector())['attempts']);
    Check::throws(SoSecurity\Exception\ValidationException::class,static function()use($r,$d):void{$r->confirm($d,['type'=>'totp','code'=>'123456']);});
    Check::same(true,$r->confirm($d,['type'=>'recovery','code'=>$r->codes[0]]));$after=$r->t->factors->status('tenant',$r->t->subject);Check::same(true,$after['enabled']);Check::same($factor['factor_id'],$after['factor_id']);Check::same($factor['recovery_remaining']-1,$after['recovery_remaining']);Check::same('1',(string)$r->e->account()['mfa_required']);Check::same(false,$r->t->factors->verifyRecovery('tenant',$r->t->subject,$r->codes[0]));
    $login=$r->t->authentication->password('tenant','after-recovery','owner@example.com',$r->password);Check::same('mfa_required',$login->status());Check::same(null,$login->credential());
},true);
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();$before=$r->e->account();Check::same(false,$r->confirm($d,['type'=>'recovery','code'=>'invalid-recovery']));Check::same($before,$r->e->account());Check::same(0,$r->policyCalls);Check::same(1,$r->flow($d->selector())['attempts']);
    $r->t->factors->revoke('tenant',$r->t->subject);Check::same(false,$r->confirm($d,['type'=>'recovery','code'=>$r->codes[0]]));Check::same(0,$r->policyCalls);Check::same($before,$r->e->account());
},true);
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();$r->onStrong=static function(string $phase,string $scope,string $subject,string $context,array $proof):bool{return $proof===['type'=>'approved','code'=>'owned-approval'];};Check::same(true,$r->confirm($d,['type'=>'approved','code'=>'owned-approval']));Check::same(['verify','current','commit','complete'],array_column($r->strongCalls,0));Check::same(1,count(array_unique(array_column($r->strongCalls,3))));Check::same('tenant',$r->strongCalls[0][1]);Check::same($r->t->subject,$r->strongCalls[0][2]);Check::same('1',(string)$r->e->account()['mfa_required']);Check::same(true,$r->t->factors->status('tenant',$r->t->subject)['enabled']);
},true,true);
foreach(['verify','current','commit'] as $phase){recoveryCase(static function(RecoveryEnvironment $r)use($phase):void{
    $d=$r->begin();$before=$r->e->account();$r->onStrong=static function(string $current)use($phase):bool{return $current!==$phase;};
    if($phase==='verify'){Check::same(false,$r->confirm($d,['type'=>'approved','code'=>'owned-approval']));}else{Check::throws(SecurityException::class,static function()use($r,$d):void{$r->confirm($d,['type'=>'approved','code'=>'owned-approval']);});}
    Check::same($before,$r->e->account());Check::same(1,count($r->ids()));Check::same(1,$r->flow($d->selector())['attempts']);
},true,true);}
recoveryCase(static function(RecoveryEnvironment $r):void{$d=$r->begin();$r->onStrong=static function(string $phase):bool{return $phase!=='complete';};try{$r->confirm($d,['type'=>'approved','code'=>'owned-approval']);throw new RuntimeException('Expected postcommit uncertainty');}catch(StorageException $error){Check::same('account.completion_unknown',$error->reason());}Check::same(true,$r->e->hasher->verify($r->password,$r->e->account()['password']));Check::same('consumed',$r->flow($d->selector())['state']);Check::same(2,count($r->ids()));},true,true);
foreach(['password','address','role','disabled'] as $change){recoveryCase(static function(RecoveryEnvironment $r)use($change):void{
    $d=$r->begin();if($change==='password'){$q=$r->e->pdo->prepare('UPDATE account_example SET password=?');$q->execute([$r->e->hasher->hash('Raw hash replacement without version 49!')]);}
    elseif($change==='address'){$r->e->pdo->exec("UPDATE account_example SET address='changed@example.com',address_version='changed'");}
    elseif($change==='role'){$r->e->pdo->exec("UPDATE account_example SET roles='[]'");}else{$r->e->pdo->exec("UPDATE account_example SET status='disabled'");}
    $before=$r->e->account();Check::same(false,$r->confirm($d));Check::same($before,$r->e->account());Check::same(0,$r->policyCalls);Check::same(null,$r->service->notification($d->notice()->id()));
});}
recoveryCase(static function(RecoveryEnvironment $r):void{
    $before=$r->e->account();$r->service->request('unknown@example.com','owned-source');Check::same([],$r->ids());Check::same($before,$r->e->account());$d=$r->begin();$r->service->request('owner@example.com','owned-source');Check::same(1,count($r->ids()));$until=$r->flow($d->selector())['valid_until'];$r->e->clock->time+=60;$r->service->request('owner@example.com','owned-source');$next=$r->delivery();Check::same($d->selector(),$next->selector());Check::same($until,$r->flow($next->selector())['valid_until']);Check::same(false,$r->confirm($d));Check::same(true,$r->confirm($next));
});
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();$before=$r->e->account();for($i=0;$i<5;++$i){Check::same(false,$r->service->confirm($d->selector(),str_repeat('0',64),$r->password,'owned-source'));}Check::same('locked',$r->flow($d->selector())['state']);Check::same(false,$r->confirm($d));Check::same($before,$r->e->account());Check::same(0,$r->policyCalls);
});
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();$before=$r->e->account();Check::same(true,$r->service->cancel($d->selector(),$d->notice()->token(),'owned-source'));Check::same(false,$r->confirm($d));Check::same(false,$r->service->cancel($d->selector(),$d->notice()->token(),'owned-source'));Check::same($before,$r->e->account());Check::same(null,$r->service->notification($d->notice()->id()));
});
recoveryCase(static function(RecoveryEnvironment $r):void{$d=$r->begin();$before=$r->e->account();$r->e->clock->time+=900;Check::same(false,$r->confirm($d));Check::same($before,$r->e->account());Check::same(0,$r->policyCalls);});
foreach(['refuse','expire','throw'] as $failure){recoveryCase(static function(RecoveryEnvironment $r)use($failure):void{
    $d=$r->begin();$before=$r->e->account();$r->onBudget=static function(string $action,string $phase)use($r,$failure):bool{if($action==='confirm'&&$phase==='final'){if($failure==='throw'){throw new RuntimeException('Owned budget outage');}if($failure==='expire'){$r->e->clock->time+=60;}return $failure!=='refuse';}return true;};
    Check::throws(Throwable::class,static function()use($r,$d):void{$r->confirm($d);});Check::same($before,$r->e->account());Check::same('pending',$r->flow($d->selector())['state']);Check::same(1,count($r->ids()));
});}
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();$before=$r->e->account();$r->onPolicy=static function()use($r):bool{$r->e->clock->time+=900;return false;};Check::throws(SecurityException::class,static function()use($r,$d):void{$r->confirm($d);});Check::same($before,$r->e->account());Check::same(1,count($r->ids()));
});
// A denied queue operation after the password UPDATE rolls back both password and private intent.
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();$before=$r->e->account();$sawReplacement=false;$r->onAuthority=static function(string $action)use($r,&$sawReplacement):bool{
        if($action==='outbox.enqueue'){$q=$r->e->pdo->query('SELECT password FROM account_example');$sawReplacement=$r->e->hasher->verify($r->password,$q->fetchColumn());return false;}return true;
    };Check::throws(SecurityException::class,static function()use($r,$d):void{$r->confirm($d);});Check::same(true,$sawReplacement);Check::same($before,$r->e->account());Check::same(1,count($r->ids()));Check::same('pending',$r->flow($d->selector())['state']);
});
recoveryCase(static function(RecoveryEnvironment $r):void{
    $before=$r->e->account();$r->onStrong=static function():bool{return true;};
    // Create the challenge without a factor adapter; a host approval must not silently bypass that missing dependency.
    $r->factor=null;$r->service=$r->build(true);$d=$r->begin();Check::same(false,$r->confirm($d,['type'=>'approved','code'=>'owned-approval']));Check::same($before,$r->e->account());Check::same(0,$r->policyCalls);Check::same([], $r->strongCalls);
},true,true);
recoveryCase(static function(RecoveryEnvironment $r):void{
    $store=new SoSecurity\Storage\FileStore($r->e->directory.'/budgets','recovery-remember',$r->e->clock);$sessions=new SoSecurity\Auth\SessionRegistry($store,$r->t->provider,null,$r->e->clock);$auth=new SoSecurity\Auth\AuthenticationFlow($store,$r->t->provider,$sessions,static function():bool{return true;},null,$r->e->clock);$login=$auth->password('tenant','owned-remember','owner@example.com',$r->t->password);
    $remember=new SoSecurity\Auth\RememberedLogin($store,$r->t->provider,$sessions,new SoSecurity\Support\HmacKeys('remember',['remember'=>str_repeat('k',32)]),static function():bool{return true;},null,$r->e->clock);
    $persistent=$remember->issue('tenant',$r->t->subject,$login->credential()->token(),'Owned recovery test');Check::same(true,$persistent!==null);$d=$r->begin();Check::same(true,$r->confirm($d));Check::same('invalid',$remember->resume('tenant',$persistent->token())->status());
});
recoveryCase(static function(RecoveryEnvironment $r):void{
    $change=$r->t->request();$mail=$change['verify_address_old'];$d=$r->begin();Check::same(false,$r->service->confirm($mail->selector(),$mail->notice()->token(),$r->password,'owned-source'));Check::same(0,$r->policyCalls);Check::same(false,$r->t->service->confirm($d->selector(),'old',$d->notice()->token(),'owned-source'));Check::same('pending',$r->flow($d->selector())['state']);Check::same(true,$r->confirm($d));
});
recoveryCase(static function(RecoveryEnvironment $r):void{
    $d=$r->begin();$phases=[];$r->onStrong=static function(string &$phase,string &$scope,string &$subject,string &$context,array &$proof)use(&$phases):bool{$phases[]=$phase;$scope='untrusted';$subject='other';$context='replacement';$proof=[];$phase='changed';return true;};Check::same(true,$r->confirm($d,['type'=>'approved','code'=>'owned-copy-check']));Check::same(['verify','current','commit','complete'],$phases);Check::same('tenant',$r->e->account()['scope']);
},true,true);
foreach(['late','backward','failure'] as $failure){recoveryCase(static function(RecoveryEnvironment $r)use($failure):void{
    $d=$r->begin();$before=$r->e->account();$r->onStrong=static function(string $phase)use($r,$failure):bool{if($phase==='verify'){if($failure==='failure'){throw new RuntimeException('Owned approval outage');}$r->e->clock->time+=$failure==='late'?900:-1;}return true;};Check::throws(SecurityException::class,static function()use($r,$d):void{$r->confirm($d,['type'=>'approved','code'=>'owned-clock-test']);});Check::same(0,$r->policyCalls);Check::same($before,$r->e->account());Check::same(1,count($r->ids()));
},true,true);}
recoveryCase(static function(RecoveryEnvironment $r):void{
    $queries=$r->e->pdo->queries;
    foreach([['type'=>'recovery','code'=>str_repeat('x',513)],['type'=>'unknown','code'=>'x'],['type'=>'approved','code'=>"a\0b"],['type'=>'approved','code'=>'x','extra'=>1]] as $proof){Check::throws(SoSecurity\Exception\ValidationException::class,static function()use($r,$proof):void{$r->service->confirm(str_repeat('a',64),str_repeat('b',64),$r->password,'owned-source',$proof);});}
    foreach(["ab\0cd",str_repeat('x',73)] as $password){Check::throws(SoSecurity\Exception\ValidationException::class,static function()use($r,$password):void{$r->service->confirm(str_repeat('a',64),str_repeat('b',64),$password,'owned-source');});}Check::same($queries,$r->e->pdo->queries);Check::same(0,$r->policyCalls);
});
echo 'PASS isolated recovery: '.Check::$assertions.' assertions on '.(($argv[1] ?? '')==='mysql'?'MySQL':'SQLite').' PHP '.PHP_VERSION."; real password/MFA recovery, strong approval, purpose/identity/attempt/expiry binding, atomic replacement and no implicit login; no SMTP/browser acceptance\n";
