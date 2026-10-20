<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/address-change-support.php';
$socket=(($argv[1] ?? '')==='mysql'?(getenv('SOSECURITY_TEST_MYSQL_SOCKET') ?: ''):($argv[1] ?? ''));if($socket!==''){if(!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Expected owned local test MySQL.');}$GLOBALS['registrationMySQLSocket']=$socket;}
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

changeCase(static function(ChangeEnvironment $t):void{
    $s=$t->service;$e=$t->e;$before=$e->account();$d=$t->request();Check::same(['verify_address_old','verify_address_new','cancel_change'],array_keys($d));Check::same(3,$t->count());
    Check::same('owner@example.com',$d['verify_address_old']->notice()->recipient()->value());Check::same('new@example.com',$d['verify_address_new']->notice()->recipient()->value());Check::same('owner@example.com',$d['cancel_change']->notice()->recipient()->value());
    $selector=$d['verify_address_old']->selector();Check::same($selector,$d['verify_address_new']->selector());Check::same($selector,$d['cancel_change']->selector());Check::same($before,$e->account());
    $payloads=$e->pdo->query('SELECT payload FROM sosecurity_account_records')->fetchAll(PDO::FETCH_COLUMN);foreach($payloads as $payload){foreach($d as $delivery){Check::same(false,strpos($payload,$delivery->notice()->token())!==false);}Check::same(false,strpos($payload,'new@example.com')!==false);}
    Check::same(false,$s->confirm($selector,'new',$d['verify_address_old']->notice()->token(),'ip'));Check::same(1,$t->flow($selector)['proofs']['new']['attempts']);
    Check::same(true,$s->confirm($selector,'new',$d['verify_address_new']->notice()->token(),'ip'));Check::same('pending',$t->flow($selector)['state']);Check::same('owner@example.com',$e->account()['address']);
    Check::throws(SecurityException::class,static function()use($t,$selector):void{$t->service->completionProposal($t->subject,$selector,$t->credential->token(),'ip');});
    Check::same(true,$s->confirm($selector,'old',$d['verify_address_old']->notice()->token(),'ip'));Check::same('ready',$t->flow($selector)['state']);Check::same('owner@example.com',$e->account()['address']);
    $intent=$s->completionProposal($t->subject,$selector,$t->credential->token(),'ip');$grant=$t->approve($intent);$oldSession=$t->credential->token();Check::same(true,$s->complete($t->subject,$selector,$oldSession,$grant,'ip'));
    $after=$e->account();Check::same('new@example.com',$after['address']);Check::same($before['password'],$after['password']);Check::same($before['roles'],$after['roles']);Check::same($before['mfa_required'],$after['mfa_required']);Check::same(false,$before['credential_version']===$after['credential_version']);Check::same(false,$before['address_version']===$after['address_version']);Check::same('consumed',$t->flow($selector)['state']);Check::same(5,$t->count());Check::same(null,$t->sessions->verify('tenant',$t->subject,$oldSession));
    Check::same(false,$s->confirm($selector,'old',$d['verify_address_old']->notice()->token(),'ip'));Check::same(false,$s->cancel($selector,$d['cancel_change']->notice()->token(),'ip'));Check::same(null,$s->notification($d['verify_address_new']->notice()->id()));
    $flow=$t->flow($selector);$old=$s->notification($flow['success']['old']['notice_id']);$new=$s->notification($flow['success']['new']['notice_id']);Check::same('owner@example.com',$old->notice()->recipient()->value());Check::same('new@example.com',$new->notice()->recipient()->value());Check::same('',$old->notice()->token());Check::same('',$new->selector());
    // A later credential change must not suppress an already committed security alert.
    $e->pdo->exec("UPDATE account_example SET credential_version='later-security-change'");Check::same('owner@example.com',$s->notification($flow['success']['old']['notice_id'])->notice()->recipient()->value());
});
changeCase(static function(ChangeEnvironment $t):void{
    $s=$t->build(false,false);$queries=$t->e->pdo->queries;Check::throws(SecurityException::class,static function()use($s):void{$s->initialize();});Check::throws(SecurityException::class,static function()use($s):void{$s->notification(str_repeat('a',64));});Check::same($queries,$t->e->pdo->queries);Check::same(0,$t->count());
});
changeCase(static function(ChangeEnvironment $t):void{
    $s=$t->service;$account=$t->e->account();Check::throws(SecurityException::class,static function()use($s,$t):void{$s->proposal('other','new@example.com',$t->credential->token(),'ip');});
    Check::throws(SecurityException::class,static function()use($s,$t):void{$s->request($t->subject,'new@example.com',$t->credential->token(),'og1.'.str_repeat('a',32).'.'.str_repeat('b',64),'ip');});Check::same(0,$t->count());Check::same($account,$t->e->account());
});
changeCase(static function(ChangeEnvironment $t):void{
    $s=$t->service;$intent=$s->proposal($t->subject,'new@example.com',$t->credential->token(),'ip');$grant=$t->approve($intent);
    Check::throws(SecurityException::class,static function()use($s,$t,$grant):void{$s->request($t->subject,'tampered@example.com',$t->credential->token(),$grant,'ip');});Check::same(0,$t->count());
    Check::throws(SecurityException::class,static function()use($s,$t,$grant):void{$s->request($t->subject,'new@example.com',$t->credential->token(),$grant,'ip');});Check::same(0,$t->count());
});
changeCase(static function(ChangeEnvironment $t):void{
    $s=$t->service;$before=$t->e->account();$d=$t->request();$selector=$d['cancel_change']->selector();$until=$t->flow($selector)['valid_until'];
    Check::same(false,$s->cancel($selector,$d['verify_address_new']->notice()->token(),'ip'));Check::same(true,$s->cancel($selector,$d['cancel_change']->notice()->token(),'ip'));Check::same('cancelled',$t->flow($selector)['state']);Check::same($before,$t->e->account());Check::same(false,$s->confirm($selector,'old',$d['verify_address_old']->notice()->token(),'ip'));Check::same(null,$s->notification($d['verify_address_new']->notice()->id()));
    $t->request();Check::same(3,$t->count());$t->e->clock->time+=60;$next=$t->request('next@example.com');$newSelector=$next['verify_address_new']->selector();Check::same(false,$selector===$newSelector);Check::same($until,$t->flow($newSelector)['valid_until']);Check::same(1,$t->flow($newSelector)['resends']);Check::same(false,$s->confirm($newSelector,'old',$d['verify_address_old']->notice()->token(),'ip'));Check::same('owner@example.com',$t->e->account()['address']);Check::same(6,$t->count());
});
changeCase(static function(ChangeEnvironment $t):void{
    $first=$t->request();$selector=$first['verify_address_old']->selector();$until=$t->flow($selector)['valid_until'];$last=$first;
    for($i=0;$i<4;++$i){$t->e->clock->time+=60;$last=$t->request();Check::same($until,$t->flow($last['verify_address_old']->selector())['valid_until']);}
    Check::same(12,$t->count());Check::same(3,$t->flow($last['verify_address_old']->selector())['resends']);Check::same(false,$t->service->confirm($selector,'new',$first['verify_address_new']->notice()->token(),'ip'));
});
foreach(['old','new'] as $side){changeCase(static function(ChangeEnvironment $t)use($side):void{
    $d=$t->request();$selector=$d['verify_address_old']->selector();for($i=0;$i<2;++$i){Check::same(false,$t->service->confirm($selector,$side,str_repeat('f',64),'ip'));}
    Check::same('locked',$t->flow($selector)['state']);Check::same(false,$t->service->confirm($selector,$side,$d['verify_address_'.$side]->notice()->token(),'ip'));Check::same(true,$t->service->cancel($selector,$d['cancel_change']->notice()->token(),'ip'));Check::same('cancelled',$t->flow($selector)['state']);Check::same('owner@example.com',$t->e->account()['address']);
},['maximum_attempts'=>2]);}
changeCase(static function(ChangeEnvironment $t):void{
    $d=$t->request();$selector=$d['verify_address_old']->selector();$version=$t->e->account()['credential_version'];$hash=$t->e->hasher->hash('different-owner-password');$q=$t->e->pdo->prepare('UPDATE account_example SET password=:password');$q->execute(['password'=>$hash]);
    Check::same($version,$t->e->account()['credential_version']);Check::same(false,$t->service->confirm($selector,'old',$d['verify_address_old']->notice()->token(),'ip'));Check::same(null,$t->service->notification($d['verify_address_new']->notice()->id()));Check::same(null,$t->sessions->verify('tenant',$t->subject,$t->credential->token()));Check::same('pending',$t->flow($selector)['state']);Check::same(0,$t->flow($selector)['proofs']['old']['attempts']);
});
changeCase(static function(ChangeEnvironment $t):void{
    $before=$t->e->account();$intent=$t->service->proposal($t->subject,'new@example.com',$t->credential->token(),'ip');$grant=$t->approve($intent);$t->onGuard=static function(string $action,string $phase):bool{return $action!=='request'||$phase!=='commit';};
    Check::throws(SecurityException::class,static function()use($t,$grant):void{$t->service->request($t->subject,'new@example.com',$t->credential->token(),$grant,'ip');});Check::same(0,$t->count());Check::same($before,$t->e->account());$t->onGuard=null;
    Check::throws(SecurityException::class,static function()use($t,$grant):void{$t->service->request($t->subject,'new@example.com',$t->credential->token(),$grant,'ip');});Check::same(0,$t->count());
});
changeCase(static function(ChangeEnvironment $t):void{
    $d=$t->ready();$selector=$d['verify_address_old']->selector();$before=$t->e->account();$flow=$t->flow($selector);$intent=$t->service->completionProposal($t->subject,$selector,$t->credential->token(),'ip');$grant=$t->approve($intent);
    $t->onGuard=static function(string $action,string $phase):bool{return $action!=='complete'||$phase!=='commit';};Check::throws(SecurityException::class,static function()use($t,$selector,$grant):void{$t->service->complete($t->subject,$selector,$t->credential->token(),$grant,'ip');});Check::same($before,$t->e->account());Check::same($flow,$t->flow($selector));Check::same(3,$t->count());$t->onGuard=null;Check::same(true,$t->sessions->verify('tenant',$t->subject,$t->credential->token())!==null);
});
changeCase(static function(ChangeEnvironment $t):void{
    $d=$t->ready();$selector=$d['verify_address_old']->selector();$intent=$t->service->completionProposal($t->subject,$selector,$t->credential->token(),'ip');$grant=$t->approve($intent);$before=$t->e->account();
    $t->onGuard=static function(string $action,string $phase)use($t):bool{if($action==='complete'&&$phase==='commit'){$t->e->clock->time+=1800;}return true;};
    Check::throws(SecurityException::class,static function()use($t,$selector,$grant):void{$t->service->complete($t->subject,$selector,$t->credential->token(),$grant,'ip');});Check::same($before,$t->e->account());Check::same('ready',$t->flow($selector)['state']);Check::same(3,$t->count());
});
foreach(['clock','guard'] as $fault){changeCase(static function(ChangeEnvironment $t)use($fault):void{
    $d=$t->ready();$selector=$d['verify_address_old']->selector();$intent=$t->service->completionProposal($t->subject,$selector,$t->credential->token(),'ip');$grant=$t->approve($intent);
    if($fault==='clock'){$t->e->pdo->afterCommit=static function()use($t):void{if($t->e->pdo->query('SELECT address FROM account_example')->fetchColumn()==='new@example.com'){$t->e->clock->time+=1800;}};}
    else{$t->onGuard=static function(string $action,string $phase):bool{return $action!=='complete'||$phase!=='complete';};}
    try{$t->service->complete($t->subject,$selector,$t->credential->token(),$grant,'ip');throw new RuntimeException('Expected unknown committed result.');}catch(SoSecurity\Storage\StorageException $error){Check::same('account.completion_unknown',$error->reason());}
    $t->e->pdo->afterCommit=null;Check::same('new@example.com',$t->e->account()['address']);Check::same('consumed',$t->flow($selector)['state']);Check::same(5,$t->count());Check::same(false,$t->service->confirm($selector,'old',$d['verify_address_old']->notice()->token(),'ip'));
});}
changeCase(static function(ChangeEnvironment $t):void{
    Check::throws(SecurityException::class,static function()use($t):void{$t->request();});Check::same(0,$t->count());Check::same('owner@example.com',$t->e->account()['address']);
},['maximum_entries'=>4]);
changeCase(static function(ChangeEnvironment $t):void{
    $d=$t->ready();$selector=$d['verify_address_old']->selector();$intent=$t->service->completionProposal($t->subject,$selector,$t->credential->token(),'ip');$grant=$t->approve($intent);$before=$t->e->account();
    Check::throws(SecurityException::class,static function()use($t,$selector,$grant):void{$t->service->complete($t->subject,$selector,$t->credential->token(),$grant,'ip');});Check::same($before,$t->e->account());Check::same('ready',$t->flow($selector)['state']);Check::same(3,$t->count());
},['maximum_entries'=>6]);
changeCase(static function(ChangeEnvironment $t):void{
    $t->e->pdo->exec("INSERT INTO account_example SELECT scope,'other',credential_version,address_version,'taken@example.com',password,status,verified,mfa_required,roles FROM account_example");$t->request('taken@example.com');Check::same(0,$t->count());Check::same('owner@example.com',$t->e->account()['address']);$t->request('owner@example.com');Check::same(0,$t->count());
});
changeCase(static function(ChangeEnvironment $t):void{
    $d=$t->request();$selector=$d['verify_address_old']->selector();$queries=$t->e->pdo->queries;
    Check::throws(ValidationException::class,static function()use($t,$selector):void{$t->service->confirm($selector,'cancel',str_repeat('a',64),'ip');});Check::throws(ValidationException::class,static function()use($t):void{$t->service->cancel('bad',str_repeat('a',64),'ip');});Check::same($queries,$t->e->pdo->queries);
    $t->onBudget=static function():bool{return false;};Check::throws(SecurityException::class,static function()use($t,$selector,$d):void{$t->service->confirm($selector,'old',$d['verify_address_old']->notice()->token(),'ip');});Check::same(0,$t->flow($selector)['proofs']['old']['attempts']);Check::same(3,$t->count());
});
if($socket===''){changeCase(static function(ChangeEnvironment $t):void{
    $d=$t->request();$selector=$d['verify_address_old']->selector();$account=$t->e->account();$t->e->pdo->exec("UPDATE sosecurity_account_records SET payload=CAST('x'||x'00'||zeroblob(16777216) AS TEXT) WHERE kind='change'");
    Check::throws(SoSecurity\Storage\StorageException::class,static function()use($t,$selector,$d):void{$t->service->confirm($selector,'old',$d['verify_address_old']->notice()->token(),'ip');});Check::same($account,$t->e->account());Check::same(3,$t->count());Check::same(true,memory_get_peak_usage(true)<8388608);
});}
changeCase(static function(ChangeEnvironment $t):void{
    $binding=$t->factors->status('tenant',$t->subject)['factor_id'];$d=$t->ready();$selector=$d['verify_address_old']->selector();$intent=$t->service->completionProposal($t->subject,$selector,$t->credential->token(),'ip');$grant=$t->approve($intent);
    Check::same('totp',$t->sessions->verify('tenant',$t->subject,$t->credential->token())->method());Check::same(true,$t->service->complete($t->subject,$selector,$t->credential->token(),$grant,'ip'));Check::same(1,(int)$t->e->account()['mfa_required']);Check::same($binding,$t->factors->status('tenant',$t->subject)['factor_id']);Check::same('new@example.com',$t->e->account()['address']);
},[],true);
changeCase(static function(ChangeEnvironment $t):void{
    $d=$t->ready();$selector=$d['verify_address_old']->selector();$intent=$t->service->completionProposal($t->subject,$selector,$t->credential->token(),'ip');$grant=$t->approve($intent);
    Check::same(true,$t->service->complete($t->subject,$selector,$t->credential->token(),$grant,'ip'));Check::same(5,$t->count());Check::same('new@example.com',$t->e->account()['address']);
},['maximum_entries'=>7]);
changeCase(static function(ChangeEnvironment $t):void{
    $d=$t->ready();$selector=$d['verify_address_old']->selector();$intent=$t->service->completionProposal($t->subject,$selector,$t->credential->token(),'ip');$grant=$t->approve($intent);
    $t->e->pdo->exec("INSERT INTO account_example SELECT scope,'other',credential_version,address_version,'new@example.com',password,status,verified,mfa_required,roles FROM account_example");Check::same(false,$t->service->complete($t->subject,$selector,$t->credential->token(),$grant,'ip'));Check::same('owner@example.com',$t->e->account()['address']);Check::same('ready',$t->flow($selector)['state']);Check::same(3,$t->count());
});
foreach(['read','commit','complete'] as $phase){changeCase(static function(ChangeEnvironment $t)use($phase):void{
    $d=$t->request();$id=$d['verify_address_new']->notice()->id();$before=$t->e->account();$t->onWorker=static function(string $action,string $current)use($t,$phase):bool{if($current===$phase){$t->e->pdo->exec("UPDATE account_example SET status='disabled'");}return true;};$returned=null;
    Check::throws(SecurityException::class,static function()use($t,$id,&$returned):void{$returned=$t->service->notification($id);});Check::same(null,$returned);Check::same($phase==='complete'?'disabled':$before['status'],$t->e->account()['status']);Check::same(3,$t->count());
});}
changeCase(static function(ChangeEnvironment $t):void{
    Check::same(null,$t->service->notification(str_repeat('a',64)));$d=$t->request();$selector=$d['verify_address_new']->selector();$until=$t->flow($selector)['valid_until'];$t->e->clock->time=$until;
    Check::same(false,$t->service->confirm($selector,'new',$d['verify_address_new']->notice()->token(),'ip'));Check::same(0,$t->flow($selector)['proofs']['new']['attempts']);Check::same(null,$t->service->notification($d['verify_address_new']->notice()->id()));Check::same('owner@example.com',$t->e->account()['address']);
});
changeCase(static function(ChangeEnvironment $t):void{
    $d=$t->request();$selector=$d['verify_address_new']->selector();$flow=$t->flow($selector);$count=$t->e->count('sosecurity_account_records');$t->e->clock->time+=172800;
    $registration=$t->e->service();$removed=$registration->maintain()['removed'];Check::same(4,$removed);Check::same($count-4,$t->e->count('sosecurity_account_records'));Check::same($flow,$t->flow($selector));Check::same(3,$t->count());Check::same('owner@example.com',$t->e->account()['address']);
});
changeCase(static function(ChangeEnvironment $t):void{
    foreach([print_r($t->service,true),var_export($t->service,true),json_encode($t->service)] as $dump){foreach([str_repeat('a',32),str_repeat('m',32),str_repeat('o',32),$t->password] as $secret){Check::same(false,strpos($dump,$secret)!==false);}}
    Check::throws(ConfigurationException::class,static function()use($t):void{serialize($t->service);});
});
echo 'PASS address change: '.Check::$assertions.' assertions on '.($socket===''?'SQLite':'MySQL').' PHP '.PHP_VERSION."; actual password/TOTP/session/operation protocol, two mailbox proofs; no SMTP/browser acceptance\n";
