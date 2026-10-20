<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/registration-support.php';
$socket=(($argv[1] ?? '')==='mysql'?(getenv('SOSECURITY_TEST_MYSQL_SOCKET') ?: ''):($argv[1] ?? ''));if($socket!==''){if(!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Expected an owned disposable local test database.');}$GLOBALS['registrationMySQLSocket']=$socket;}
use SoSecurity\Account\Registration;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Password\PasswordPolicy;
use SoSecurity\Support\HmacKeys;
function scopedRegistration(RegistrationEnvironment $e,?callable $management=null,?callable $delivery=null,?callable $public=null):Registration
{
    return new Registration($e->pdo,'account-test','tenant',str_repeat('e',64),new HmacKeys('account',['account'=>str_repeat('a',32)]),new HmacKeys('outbox',['outbox'=>str_repeat('o',32)]),$e->accounts,new SoSecurity\Account\Notifications('mail',['mail'=>str_repeat('m',32)],$e->clock),$e->hasher,PasswordPolicy::forHasher($e->hasher,15),$public ?? static function():bool{return true;},static function():bool{return true;},$e->policy,$e->clock,$management,$delivery);
}
registrationCase(static function(RegistrationEnvironment $e):void{
    // A permissive public registration guard must not initialize privileged storage.
    $s=scopedRegistration($e);$queries=$e->pdo->queries;
    Check::throws(SecurityException::class,static function()use($s):void{$s->initialize();});
    Check::same($queries,$e->pdo->queries);Check::same(0,$e->count('sosecurity_account_roots'));Check::same(0,$e->count('sosecurity_outbox_roots'));
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $trusted=$e->service();$trusted->initialize();$s=scopedRegistration($e);$s->request('owner@example.com','ip');$id=$e->notices()[0];$queries=$e->pdo->queries;
    foreach([static function()use($s):void{$s->maintain();},static function()use($s):void{$s->rotate();},static function()use($s,$id):void{$s->notification($id);},static function()use($s):void{$s->initialize();}] as $operation){Check::throws(SecurityException::class,$operation);Check::same($queries,$e->pdo->queries);}
    Check::same(1,$e->count('account_example'));Check::same('pending',$e->account()['status']);Check::same(null,$e->account()['password']);Check::same(3,$e->count('sosecurity_account_records'));Check::same(1,count($e->notices()));
    $delivery=$trusted->notification($id);Check::same(true,$s->confirm($delivery->selector(),$delivery->notice()->token(),'owner-confirmation-password','ip'));Check::same('active',$e->account()['status']);
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $actions=[];$s=scopedRegistration($e,static function(string $action,string $phase,string $scope)use(&$actions):bool{$actions[]=[$action,$phase,$scope];return true;},null,static function():bool{return false;});
    $s->initialize();$s->initialize();Check::same(1,$e->count('sosecurity_account_roots'));Check::same(1,$e->count('sosecurity_outbox_roots'));Check::same(0,$e->count('account_example'));
    Check::same(0,$s->maintain()['removed']);Check::same(0,$s->rotate()['resealed']);
    Check::throws(SecurityException::class,static function()use($s):void{$s->notification(str_repeat('a',64));});
    Check::throws(SecurityException::class,static function()use($s):void{$s->request('owner@example.com','ip');});
    Check::same(0,$e->count('account_example'));Check::same(0,$e->count('sosecurity_account_records'));Check::same(0,count($e->notices()));
    foreach($actions as $call){Check::same(true,in_array($call[0],['outbox.initialize','initialize','maintain','rotate'],true));Check::same('tenant',$call[2]);}
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $trusted=$e->service();$trusted->initialize();$trusted->request('owner@example.com','ip');$id=$e->notices()[0];$publicCalls=0;$calls=[];
    $s=scopedRegistration($e,null,static function(string $action,string $phase,string $scope,?SoSecurity\Account\AccountRecord $record)use(&$calls):bool{$calls[]=[$action,$phase,$scope,$record===null?null:$record->account()->subject()];return true;},static function()use(&$publicCalls):bool{++$publicCalls;return false;});
    $delivery=$s->notification($id);Check::same($id,$delivery->notice()->id());Check::same('owner@example.com',$delivery->notice()->recipient()->value());Check::same(64,strlen($delivery->notice()->token()));Check::same(0,$publicCalls);
    Check::same(['before','read','commit','complete'],array_column($calls,1));foreach($calls as $call){Check::same('notification',$call[0]);Check::same('tenant',$call[2]);}Check::same($e->account()['subject'],$calls[1][3]);
    Check::throws(SecurityException::class,static function()use($s):void{$s->maintain();});Check::throws(SecurityException::class,static function()use($s):void{$s->rotate();});Check::throws(SecurityException::class,static function()use($s):void{$s->initialize();});
    Check::same(0,$publicCalls);Check::throws(SecurityException::class,static function()use($s):void{$s->request('other@example.com','ip');});Check::same(1,$publicCalls);Check::same(1,$e->count('account_example'));Check::same(1,count($e->notices()));
});
// A denied queue setup must not fall through into initializing the account ledger.
foreach([false,1,'1',[]] as $answer){registrationCase(static function(RegistrationEnvironment $e)use($answer):void{
    $s=scopedRegistration($e,static function(string $action)use($answer){return $action==='outbox.initialize'?$answer:true;});
    Check::throws(SecurityException::class,static function()use($s):void{$s->initialize();});Check::same(0,$e->count('sosecurity_account_roots'));Check::same(0,$e->count('sosecurity_outbox_roots'));Check::same(0,$e->count('account_example'));
});}
// Before/read/commit/complete are independent current checks. No Delivery escapes on denial.
foreach(['before','read','commit','complete'] as $deniedPhase){registrationCase(static function(RegistrationEnvironment $e)use($deniedPhase):void{
    $trusted=$e->service();$trusted->initialize();$trusted->request('owner@example.com','ip');$id=$e->notices()[0];$calls=[];$before=$e->account();$root=$e->pdo->query('SELECT revision,entries,history_digest FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC);
    $s=scopedRegistration($e,null,static function(string $action,string $phase)use($deniedPhase,&$calls):bool{$calls[]=$phase;return $phase!==$deniedPhase;});$result=null;
    Check::throws(SecurityException::class,static function()use($s,$id,&$result):void{$result=$s->notification($id);});Check::same(null,$result);Check::same($deniedPhase,$calls[count($calls)-1]);Check::same($before,$e->account());Check::same($root,$e->pdo->query('SELECT revision,entries,history_digest FROM sosecurity_account_roots')->fetch(PDO::FETCH_ASSOC));Check::same(1,count($e->notices()));Check::same(3,$e->count('sosecurity_account_records'));
});}
foreach([false,1,'yes',[]] as $answer){registrationCase(static function(RegistrationEnvironment $e)use($answer):void{
    $trusted=$e->service();$trusted->initialize();$trusted->request('owner@example.com','ip');$id=$e->notices()[0];$s=scopedRegistration($e,null,static function()use($answer){return $answer;});
    Check::throws(SecurityException::class,static function()use($s,$id):void{$s->notification($id);});Check::same(1,count($e->notices()));Check::same('pending',$e->account()['status']);
});}
registrationCase(static function(RegistrationEnvironment $e):void{
    $trusted=$e->service();$trusted->initialize();$trusted->request('owner@example.com','ip');$id=$e->notices()[0];$allowed=true;$calls=[];
    $s=scopedRegistration($e,null,static function(string $action,string $phase)use(&$allowed,&$calls):bool{$calls[]=$phase;return $allowed;});$e->pdo->afterCommit=static function()use(&$allowed):void{$allowed=false;};$result=null;
    Check::throws(SecurityException::class,static function()use($s,$id,&$result):void{$result=$s->notification($id);});Check::same(null,$result);Check::same(['before','read','commit','complete'],$calls);$e->pdo->afterCommit=null;Check::same('pending',$e->account()['status']);Check::same(1,count($e->notices()));
});
foreach(['read','commit','complete'] as $changePhase){registrationCase(static function(RegistrationEnvironment $e)use($changePhase):void{
    $trusted=$e->service();$trusted->initialize();$trusted->request('owner@example.com','ip');$id=$e->notices()[0];
    $s=scopedRegistration($e,null,static function(string $action,string $phase)use($e,$changePhase):bool{if($phase===$changePhase){$e->pdo->exec("UPDATE account_example SET status='disabled',credential_version='revoked-in-delivery-guard'");}return true;});$result=null;
    Check::throws(SecurityException::class,static function()use($s,$id,&$result):void{$result=$s->notification($id);});Check::same(null,$result);Check::same($changePhase==='complete'?'disabled':'pending',$e->account()['status']);Check::same(1,count($e->notices()));
});}
registrationCase(static function(RegistrationEnvironment $e):void{
    $trusted=$e->service();$trusted->initialize();$trusted->request('owner@example.com','ip');$id=$e->notices()[0];$expires=$trusted->notification($id)->notice()->expiresAt();$s=scopedRegistration($e,null,static function():bool{return true;});
    $e->pdo->afterCommit=static function()use($e,$expires):void{$e->clock->time=$expires;};$result=null;Check::throws(SecurityException::class,static function()use($s,$id,&$result):void{$result=$s->notification($id);});Check::same(null,$result);$e->pdo->afterCommit=null;Check::same('pending',$e->account()['status']);Check::same(1,count($e->notices()));
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $scopes=[];$manager=static function(string &$action,string &$phase,string &$scope,?SoSecurity\Account\AccountRecord &$record)use(&$scopes):bool{$scopes[]=$scope;$action='changed';$phase='changed';$scope='other';return true;};$s=scopedRegistration($e,$manager);$s->initialize();$s->maintain();$s->rotate();
    Check::same(['tenant'],array_values(array_unique($scopes)));$s->request('owner@example.com','ip');$trusted=$e->service();$id=$e->notices()[0];Check::same('owner@example.com',$trusted->notification($id)->notice()->recipient()->value());Check::same(1,$e->count('account_example'));
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $calls=0;$s=scopedRegistration($e,static function()use(&$calls):bool{++$calls;return true;},static function()use(&$calls):bool{++$calls;return true;});$queries=$e->pdo->queries;
    Check::throws(ValidationException::class,static function()use($s):void{$s->notification('bad');});Check::throws(ConfigurationException::class,static function()use($s):void{$s->maintain(51);});Check::throws(ConfigurationException::class,static function()use($s):void{$s->rotate(1,'bad');});Check::same($queries,$e->pdo->queries);Check::same(0,$calls);
});
registrationCase(static function(RegistrationEnvironment $e):void{
    $trusted=$e->service();$trusted->initialize();$trusted->request('owner@example.com','ip');$id=$e->notices()[0];$secret='authority-callback-private-value';$s=scopedRegistration($e,null,static function()use($secret):bool{throw new RuntimeException($secret);});
    try{$s->notification($id);throw new RuntimeException('Expected callback failure.');}catch(SecurityException $error){Check::same(false,strpos($error->getMessage(),$secret)!==false);Check::same('account.authority',$error->reason());}
    foreach([print_r($s,true),var_export($s,true),json_encode($s)] as $dump){Check::same(false,strpos($dump,$secret)!==false);}Check::same(1,count($e->notices()));
});
echo 'PASS account authority separation: '.Check::$assertions.' assertions on '.($socket===''?'SQLite':'MySQL').' PHP '.PHP_VERSION."\n";
