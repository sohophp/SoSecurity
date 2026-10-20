<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/registration-support.php';

$registrationSocket=(($argv[1] ?? '')==='mysql'?(getenv('SOSECURITY_TEST_MYSQL_SOCKET') ?: ''):($argv[1] ?? ''));
if($registrationSocket!==''){
    if(!preg_match('~\A/tmp/sosecurity-mysql-[a-zA-Z0-9_-]+/mysql\.sock\z~D',$registrationSocket)||!is_file(dirname($registrationSocket).'/account-test-owner')){throw new RuntimeException('Expected an owned disposable no-TCP local MySQL instance.');}
    $GLOBALS['registrationMySQLSocket']=$registrationSocket;
}

use SoSecurity\Account\Address;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;

$password='correct horse account password';
registrationCase(static function(RegistrationEnvironment $e)use($password):void{
    $before=$e->pdo->queries;$s=$e->service();Check::same($before,$e->pdo->queries);Check::same(0,$e->authorityCalls);Check::same(0,$e->budgetCalls);
    Check::throws(ConfigurationException::class,static function()use($e):void{$e->service($e->observer);});
    $s->initialize();$s->initialize();Check::same(1,$e->count('sosecurity_account_roots'));Check::same(1,$e->count('sosecurity_outbox_roots'));
    Check::same(null,$s->request('Owner+tag@EXAMPLE.COM','ip-1'));$pending=$e->account();Check::same('pending',$pending['status']);Check::same(null,$pending['password']);Check::same(0,(int)$pending['verified']);Check::same(1,$e->count('account_example'));Check::same(1,count($e->notices()));
    $noticeId=$e->notices()[0];$delivery=$s->notification($noticeId);Check::same(64,strlen($noticeId));Check::same(64,strlen($delivery->selector()));Check::same(64,strlen($delivery->notice()->token()));Check::same('Owner+tag@example.com',$delivery->notice()->recipient()->value());
    $selector=$delivery->selector();$token=$delivery->notice()->token();$payloads=$e->pdo->query('SELECT payload FROM sosecurity_account_records')->fetchAll(PDO::FETCH_COLUMN);
    foreach($payloads as $payload){Check::same(false,strpos($payload,$token)!==false);Check::same(false,strpos($payload,'Owner+tag@example.com')!==false);Check::same(false,strpos($payload,$password)!==false);}
    $s->request('Owner+tag@example.com','ip-1');Check::same(1,count($e->notices()));
    $queries=$e->pdo->queries;$budgets=$e->budgetCalls;
    foreach([['bad',$token,$password],[$selector,"bad\0token",$password],[$selector,$token,str_repeat('x',73)],[$selector,$token,"a\0password"]] as $arguments){Check::throws(ValidationException::class,static function()use($s,$arguments):void{$s->confirm($arguments[0],$arguments[1],$arguments[2],'ip-1');});}
    Check::same($queries,$e->pdo->queries);Check::same($budgets,$e->budgetCalls);
    Check::same(false,$s->confirm($selector,str_repeat('f',64),$password,'ip-1'));Check::same(1,$e->flow($selector)['attempts']);Check::same(0,$e->hashCalls);
    Check::same(false,$s->confirm($selector,$token,'short','ip-1'));Check::same(2,$e->flow($selector)['attempts']);Check::same(0,$e->hashCalls);
    $e->onHash=static function()use($e):void{$e->pdo->beginTransaction();$e->pdo->rollBack();};
    Check::same(true,$s->confirm($selector,$token,$password,'ip-1'));$active=$e->account();Check::same('active',$active['status']);Check::same(1,(int)$active['verified']);Check::same(true,$e->hasher->verify($password,$active['password']));Check::same(false,$active['credential_version']===$pending['credential_version']);Check::same($pending['address_version'],$active['address_version']);Check::same('consumed',$e->flow($selector)['state']);Check::same(2,count($e->notices()));
    Check::same(false,$s->confirm($selector,$token,'different owner password','ip-1'));Check::same($active,$e->account());Check::same(null,$s->notification($noticeId));
    $security=$s->notification($e->notices()[1]);Check::same('account_activated',$security->notice()->type());Check::same('',$security->notice()->token());Check::same('',$security->selector());
    foreach([$s,$delivery,$security] as $object){foreach([var_export($object,true),print_r($object,true),json_encode($object)] as $dump){foreach([$token,'Owner+tag@example.com',str_repeat('m',32),$password] as $secret){Check::same(false,strpos($dump,$secret)!==false);}}Check::throws(ConfigurationException::class,static function()use($object):void{serialize($object);});}
    Check::same(null,$s->request('Owner+tag@example.com','ip-2'));Check::same(2,count($e->notices()));Check::same($active,$e->account());
});
registrationCase(static function(RegistrationEnvironment $e)use($password):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$first=$s->notification($e->notices()[0]);
    $e->clock->time+=59;$s->request('owner@example.com','ip');Check::same(1,count($e->notices()));++$e->clock->time;$s->request('owner@example.com','ip');Check::same(2,count($e->notices()));$second=$s->notification($e->notices()[1]);
    Check::same($first->selector(),$second->selector());Check::same($first->notice()->expiresAt(),$second->notice()->expiresAt());Check::same(false,$first->notice()->token()===$second->notice()->token());Check::same(null,$s->notification($e->notices()[0]));Check::same(false,$s->confirm($first->selector(),$first->notice()->token(),$password,'ip'));
    Check::same(true,$s->confirm($second->selector(),$second->notice()->token(),$password,'ip'));
});
registrationCase(static function(RegistrationEnvironment $e)use($password):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$first=$s->notification($e->notices()[0]);
    for($n=0;$n<5;++$n){$e->clock->time+=60;$s->request('owner@example.com','ip');}Check::same(4,count($e->notices()));Check::same(3,$e->flow($first->selector())['resends']);
    $e->clock->time=100000+86400;$s->request('owner@example.com','ip');$next=$s->notification($e->notices()[4]);Check::same(false,$first->selector()===$next->selector());Check::same(false,$s->confirm($first->selector(),$first->notice()->token(),$password,'ip'));Check::same(true,$s->confirm($next->selector(),$next->notice()->token(),$password,'ip'));
});
registrationCase(static function(RegistrationEnvironment $e)use($password):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$d=$s->notification($e->notices()[0]);
    for($n=0;$n<5;++$n){Check::same(false,$s->confirm($d->selector(),str_repeat('f',64),$password,'ip'));}Check::same('locked',$e->flow($d->selector())['state']);Check::same(false,$s->confirm($d->selector(),$d->notice()->token(),$password,'ip'));Check::same(0,$e->hashCalls);Check::same(null,$e->account()['password']);
});
foreach(['before','during_hash'] as $when){registrationCase(static function(RegistrationEnvironment $e)use($password,$when):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$d=$s->notification($e->notices()[0]);
    if($when==='before'){$e->clock->time+=2;}else{$e->onHash=static function()use($e):void{$e->clock->time+=2;};}
    Check::same(false,$s->confirm($d->selector(),$d->notice()->token(),$password,'ip'));Check::same(null,$e->account()['password']);Check::same('pending',$e->account()['status']);Check::same(1,count($e->notices()));
},['registration_seconds'=>2]);}
foreach(["credential_version='new-version'","address_version='new-address-version'","status='disabled'","address='other@example.com'","roles='[\"admin\"]'","mfa_required=1"] as $assignment){registrationCase(static function(RegistrationEnvironment $e)use($password,$assignment):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$d=$s->notification($e->notices()[0]);$e->onHash=static function()use($e,$assignment):void{$e->pdo->exec('UPDATE account_example SET '.$assignment);};
    Check::same(false,$s->confirm($d->selector(),$d->notice()->token(),$password,'ip'));Check::same(null,$e->account()['password']);Check::same('pending',$e->flow($d->selector())['state']);Check::same(1,count($e->notices()));
});}
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$e->onAuthority=static function(string $action):bool{return $action!=='outbox.enqueue';};Check::throws(SecurityException::class,static function()use($s):void{$s->request('owner@example.com','ip');});
    Check::same(0,$e->count('account_example'));Check::same(0,$e->count('sosecurity_account_records'));Check::same(0,count($e->notices()));Check::same(0,(int)$e->observer->query('SELECT entries FROM sosecurity_account_roots')->fetchColumn());
});
registrationCase(static function(RegistrationEnvironment $e)use($password):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$d=$s->notification($e->notices()[0]);$e->onAuthority=static function(string $action,string $phase):bool{return $action!=='confirm'||$phase!=='commit';};
    Check::throws(SecurityException::class,static function()use($s,$d,$password):void{$s->confirm($d->selector(),$d->notice()->token(),$password,'ip');});Check::same(null,$e->account()['password']);Check::same('pending',$e->flow($d->selector())['state']);Check::same(1,$e->flow($d->selector())['attempts']);Check::same(1,count($e->notices()));
    $e->onAuthority=null;Check::same(true,$s->confirm($d->selector(),$d->notice()->token(),$password,'ip'));
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$queries=$e->pdo->queries;$e->onBudget=static function():bool{return false;};Check::throws(SecurityException::class,static function()use($s):void{$s->request('owner@example.com','ip');});Check::same($queries,$e->pdo->queries);Check::same(0,$e->count('account_example'));
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('first@example.com','ip');$queries=$e->pdo->queries;Check::throws(SecurityException::class,static function()use($s):void{$s->request('unknown@example.com','ip');});Check::same($queries,$e->pdo->queries);Check::same(1,$e->count('account_example'));Check::same(1,count($e->notices()));
},[],1);
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();Check::throws(StorageException::class,static function()use($s):void{$s->request('owner@example.com','ip');});Check::same(0,$e->count('account_example'));Check::same(0,$e->count('sosecurity_account_records'));Check::same(0,count($e->notices()));
},['maximum_entries'=>2]);
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('User@example.com','ip');$s->request('user@example.com','ip');Check::same(2,$e->count('account_example'));Check::same(2,count($e->notices()));
});
registrationCase(static function(RegistrationEnvironment $e)use($password):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$d=$s->notification($e->notices()[0]);$other=$e->service(null,null,'other-tenant');$other->initialize();
    Check::same(false,$other->confirm($d->selector(),$d->notice()->token(),$password,'ip'));Check::same(false,$s->confirm($e->notices()[0],$d->notice()->token(),$password,'ip'));Check::same(0,$e->hashCalls);Check::same(null,$e->account()['password']);
    $e->onDelivery=static function(string $action):bool{return $action!=='notification';};Check::throws(SecurityException::class,static function()use($s,$d):void{$s->notification($d->notice()->id());});
});
registrationCase(static function(RegistrationEnvironment $e)use($password):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$d=$s->notification($e->notices()[0]);$pending=$e->account();
    $e->onAuthority=static function(string $action,string $phase)use($e):bool{if($action==='confirm'&&$phase==='activate'){$e->pdo->exec("UPDATE account_example SET credential_version='changed-in-guard'");}return true;};
    Check::throws(StorageException::class,static function()use($s,$d,$password):void{$s->confirm($d->selector(),$d->notice()->token(),$password,'ip');});Check::same($pending,$e->account());Check::same(1,count($e->notices()));Check::same(1,$e->flow($d->selector())['attempts']);
});
registrationCase(static function(RegistrationEnvironment $e)use($password):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$d=$s->notification($e->notices()[0]);
    $e->pdo->exec($e->mysql?"UPDATE account_example SET address=REPEAT('x',254)":"UPDATE account_example SET address=CAST(x'6100'||zeroblob(16777216) AS TEXT)");
    Check::throws(SecurityException::class,static function()use($s,$d,$password):void{$s->confirm($d->selector(),$d->notice()->token(),$password,'ip');});Check::same(0,$e->hashCalls);Check::same(null,$e->observer->query('SELECT password FROM account_example')->fetchColumn());Check::same(1,count($e->notices()));
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$e->pdo->exec($e->mysql?"CREATE TRIGGER host_reject BEFORE INSERT ON account_example FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic account denial'":"CREATE TRIGGER host_reject BEFORE INSERT ON account_example BEGIN SELECT RAISE(FAIL,'synthetic account denial'); END");
    Check::throws(SecurityException::class,static function()use($s):void{$s->request('owner@example.com','ip');});Check::same(0,$e->count('account_example'));Check::same(0,$e->count('sosecurity_account_records'));Check::same(0,count($e->notices()));
});
foreach(['statement','commit'] as $when){registrationCase(static function(RegistrationEnvironment $e)use($password,$when):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$d=$s->notification($e->notices()[0]);
    if($when==='statement'){$e->pdo->afterStatement=static function(string $sql)use($e):void{if(strpos($sql,'UPDATE account_example SET credential_version=')===0){$e->clock->time+=2;}};}
    else{$e->pdo->beforeCommit=static function()use($e):void{if($e->pdo->query("SELECT status FROM account_example")->fetchColumn()==='active'){$e->clock->time+=2;}};}
    Check::throws(StorageException::class,static function()use($s,$d,$password):void{$s->confirm($d->selector(),$d->notice()->token(),$password,'ip');});
    $e->pdo->afterStatement=null;$e->pdo->beforeCommit=null;
    Check::same($when==='statement'?'pending':'active',$e->account()['status']);Check::same($when==='statement'?1:2,count($e->notices()));
    if($when==='commit'){Check::same(false,$s->confirm($d->selector(),$d->notice()->token(),$password,'ip'));Check::same(2,count($e->notices()));}
},['registration_seconds'=>2]);}
// Long-lived pending reservations must still be renewable after the old challenge has expired.
registrationCase(static function(RegistrationEnvironment $e):void{
    $s=$e->service();$s->initialize();$s->request('owner@example.com','ip');$e->clock->time+=15*86400;$s->request('owner@example.com','ip');Check::same(2,count($e->notices()));Check::same('verify_registration',$s->notification($e->notices()[1])->notice()->type());
});
echo 'PASS isolated registration: '.Check::$assertions.' assertions on '.($registrationSocket===''?'SQLite':'MySQL').' PHP '.PHP_VERSION."; private account/challenge/Outbox atomicity, owner-chosen password, budgets, resends and stale proof refusal; no SMTP/browser acceptance\n";
