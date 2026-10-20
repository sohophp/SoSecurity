<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/address-change-support.php';
$mysql=($argv[1] ?? '')==='mysql';if($mysql){$GLOBALS['registrationMySQLSocket']=getenv('SOSECURITY_TEST_MYSQL_SOCKET');}
use SoSecurity\Account\RequestBudgets;
use SoSecurity\Account\Registration;
use SoSecurity\Account\AddressChange;
use SoSecurity\Account\Notifications;
use SoSecurity\RateLimit\BudgetPolicy;
use SoSecurity\Storage\FileStore;
use SoSecurity\Support\HmacKeys;
function formalPolicies(array $limits=[]):array {$policies=[];foreach(['site','source','target','subject'] as $name){$policies[$name]=new BudgetPolicy('fixed_window',$limits[$name] ?? 1000,60);}return $policies;}
function formalBudget(RegistrationEnvironment $e,array &$trace,array $limits=[]):callable {
    $guard=new RequestBudgets(new FileStore($e->directory.'/budgets','formal-account-budgets',$e->clock,5000),'account-test',str_repeat('p',32),formalPolicies($limits),$e->clock);
    return static function(...$args)use($guard,&$trace):bool{$trace[]=[$args[0],$args[1],$args[6]];return $guard(...$args);};
}
function formalRegistration(RegistrationEnvironment $e,callable $budget):Registration {
    $authority=static function(string $action,string $phase,string $scope,?SoSecurity\Account\AccountRecord $record)use($e):bool{return $e->onAuthority===null?true:($e->onAuthority)($action,$phase,$scope,$record);};$manager=static function():bool{return true;};
    return new Registration($e->pdo,'account-test','tenant',str_repeat('e',64),new HmacKeys('account',['account'=>str_repeat('a',32)]),new HmacKeys('outbox',['outbox'=>str_repeat('o',32)]),$e->accounts,new Notifications('mail',['mail'=>str_repeat('m',32)],$e->clock),$e->hasher,SoSecurity\Password\PasswordPolicy::forHasher($e->hasher,15),$authority,$budget,$e->policy,$e->clock,$manager,$manager);
}
function formalTrace(array $trace):void {
    $groups=[];$previews=0;foreach($trace as $entry){list($action,$phase,$id)=$entry;if($id===''){Check::same('public',$phase);++$previews;continue;}Check::same(1,preg_match('/\A[a-f0-9]{32}\z/D',$id));$groups[$id][]=$action.':'.$phase;}
    foreach($groups as $entries){Check::same('public',explode(':',$entries[0])[1]);$action=explode(':',$entries[0])[0];foreach($entries as $entry){Check::same($action,explode(':',$entry)[0]);}Check::same(count($entries),count(array_unique($entries)));}Check::same(true,count($groups)>0);
}
registrationCase(static function(RegistrationEnvironment $e):void{
    $trace=[];$s=formalRegistration($e,formalBudget($e,$trace));$s->initialize();Check::same([],$trace);$s->request('owner@example.com','formal-source');$row=$e->account();Check::same('pending',$row['status']);Check::same(null,$row['password']);Check::same(['request:public','request:subject','request:final'],array_map(static function(array $v):string{return $v[0].':'.$v[1];},$trace));Check::same(1,count(array_unique(array_column($trace,2))));
    $delivery=$s->notification($e->notices()[0]);Check::same(true,$s->confirm($delivery->selector(),$delivery->notice()->token(),'Actual owner-selected password. 49!','formal-source'));Check::same('active',$e->account()['status']);Check::same(2,count($e->notices()));Check::same(false,$s->confirm($delivery->selector(),$delivery->notice()->token(),'Actual owner-selected password. 49!','formal-source'));formalTrace($trace);
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $trace=[];$s=formalRegistration($e,formalBudget($e,$trace,['source'=>1]));$s->initialize();$s->request('owner@example.com','formal-source');$queries=$e->pdo->queries;Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($s):void{$s->request('unknown@example.com','formal-source');});Check::same($queries,$e->pdo->queries);Check::same(1,$e->count('account_example'));Check::same(1,count($e->notices()));
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $trace=[];$s=formalRegistration($e,formalBudget($e,$trace,['target'=>1]));$s->initialize();$s->request('owner@example.com','formal-source');$delivery=$s->notification($e->notices()[0]);Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($s,$delivery):void{$s->confirm($delivery->selector(),$delivery->notice()->token(),'Actual owner-selected password. 49!','formal-source');});Check::same('pending',$e->account()['status']);Check::same(null,$e->account()['password']);Check::same(0,$e->flow($delivery->selector())['attempts']);Check::same(1,count($e->notices()));
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $trace=[];$s=formalRegistration($e,formalBudget($e,$trace));$s->initialize();$roots=$e->observer->query('SELECT * FROM sosecurity_account_roots')->fetchAll(PDO::FETCH_ASSOC);$e->onAuthority=static function(string $action,string $phase)use($e):bool{if($action==='request'&&$phase==='after'){$e->clock->time+=60;}return true;};Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($s):void{$s->request('owner@example.com','formal-source');});Check::same(0,$e->count('account_example'));Check::same(0,count($e->notices()));Check::same(0,$e->count('sosecurity_account_records'));Check::same($roots,$e->observer->query('SELECT * FROM sosecurity_account_roots')->fetchAll(PDO::FETCH_ASSOC));
});
foreach([false,true] as $mfa){changeCase(static function(ChangeEnvironment $t)use($mfa):void{
    $e=$t->e;$trace=[];$budget=formalBudget($e,$trace);$guard=static function():bool{return true;};
    $t->service=new AddressChange($e->pdo,'account-test','tenant',str_repeat('e',64),new HmacKeys('account',['account'=>str_repeat('a',32)]),new HmacKeys('outbox',['outbox'=>str_repeat('o',32)]),$e->accounts,new Notifications('mail',['mail'=>str_repeat('m',32)],$e->clock),$t->sessions,$t->grants,$guard,$budget,$e->policy,$e->clock,$guard,$guard);
    $before=$e->account();$d=$t->ready();$selector=$d['verify_address_old']->selector();$intent=$t->service->completionProposal($t->subject,$selector,$t->credential->token(),'ip');$grant=$t->approve($intent);$oldToken=$t->credential->token();Check::same(true,$t->service->complete($t->subject,$selector,$oldToken,$grant,'ip'));$after=$e->account();Check::same('new@example.com',$after['address']);foreach(['password','roles','mfa_required'] as $field){Check::same($before[$field],$after[$field]);}Check::same(true,$before['credential_version']!==$after['credential_version']);Check::same(null,$t->sessions->verify('tenant',$t->subject,$oldToken));Check::same(5,$t->count());formalTrace($trace);$nonempty=array_values(array_unique(array_filter(array_column($trace,2))));Check::same(4,count($nonempty));Check::same($mfa?'1':'0',(string)$after['mfa_required']);
},[],$mfa);}
echo 'PASS account formal request-budget SQL composition: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; actual password/TOTP/grants, per-call binding and quota/expiry rollback; no SMTP\n";
