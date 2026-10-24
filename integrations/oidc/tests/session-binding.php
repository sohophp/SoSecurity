<?php
declare(strict_types=1);
require dirname(__DIR__,3).'/tests/bootstrap.php';
if(isset($argv[1])){require $argv[1];}
spl_autoload_register(static function(string $name):void{
    $prefix='SoSecurity\\Oidc\\';
    if(strpos($name,$prefix)===0){require dirname(__DIR__).'/src/'.substr($name,strlen($prefix)).'.php';}
});
use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Oidc\FederatedSessions;
use SoSecurity\Oidc\LinkRegistry;
use SoSecurity\Oidc\LogoutFence;
use SoSecurity\Oidc\VerifiedSubject;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\Change;
use SoSecurity\Support\Guard;

$clock=new TestClock();$store=new MemoryStore($clock);$account=new Account('tenant','alice','1');
$afterFind=null;
$provider=new CallbackIdentityProvider(static function()use($account){return $account;},static function()use($account,&$afterFind){
    if($afterFind!==null){$callback=$afterFind;$afterFind=null;$callback();}return $account;
});
$guard=static function():bool{return true;};$localSessions=new SessionRegistry($store,$provider,null,$clock);
$flow=new AuthenticationFlow($store,$provider,$localSessions,$guard,null,$clock);
$local=$flow->password('tenant','browser','alice','synthetic')->credential();
$fence=new LogoutFence($store,$clock);$links=new LinkRegistry($store,$provider,$localSessions,$guard,$clock,$fence);
$class=new ReflectionClass(VerifiedSubject::class);$remote=$class->newInstanceWithoutConstructor();
$read=$class->getProperty('read');if(PHP_VERSION_ID<80100){$read->setAccessible(true);}
$time=$clock->time;$read->setValue($remote,static function()use($time):array{return ['https://issuer.example.test','external-alice',$time,'sid'];});
Check::same(true,$links->link('tenant','alice',$local->token(),$remote));
$sessions=new FederatedSessions($store,$provider,$links,$fence,$guard,null,$clock);
$issued=$sessions->issue('tenant',$remote);Check::same(true,$issued!==null);
// Repeating an existing binding must not invalidate an otherwise current session.
Check::same(true,$links->link('tenant','alice',$local->token(),$remote));
Check::same(true,$sessions->verify('tenant','alice',$issued->token())!==null);
// Do not verify while unlinked: the old session must fail even when its first next request is after relinking.
Check::same(true,$links->unlink('tenant','alice',$local->token(),$remote));
Check::same(true,$links->link('tenant','alice',$local->token(),$remote));
Check::same(null,$sessions->verify('tenant','alice',$issued->token()));
$fresh=$sessions->issue('tenant',$remote);Check::same(true,$fresh!==null);
Check::same(true,$sessions->verify('tenant','alice',$fresh->token())!==null);
Check::same(true,$localSessions->verify('tenant','alice',$local->token())!==null);
// Legacy sessions have no exact binding evidence. Never attach today's binding to them.
$key=Guard::key('oidc-sessions','tenant','alice');
$store->transact($key,static function($state){
    $state['v']=1;foreach($state['sessions'] as &$entry){unset($entry['link'], $entry['mfa']);}unset($entry);
    return new Change($state,0,null);
});
Check::same(null,$sessions->verify('tenant','alice',$fresh->token()));
Check::same(null,$store->transact($key,static function($state){return new Change($state,0,$state);}));
$fresh=$sessions->issue('tenant',$remote);Check::same(true,$fresh!==null);
Check::same(2,$store->transact($key,static function($state){return new Change($state,0,$state['v']);}));
// Exact metadata must also reject relinking during the identity read itself.
$before=$links->currentBinding('tenant',$remote->issuer(),$remote->subject(),$account);
Check::same(64,strlen($before));
$afterFind=static function()use($links,$local,$remote):void{
    $links->unlink('tenant','alice',$local->token(),$remote);$links->link('tenant','alice',$local->token(),$remote);
};
Check::same(null,$links->currentBinding('tenant',$remote->issuer(),$remote->subject(),$account));
Check::same(false,$before===$links->currentBinding('tenant',$remote->issuer(),$remote->subject(),$account));
Check::same(null,$sessions->verify('tenant','alice',$fresh->token()));
$plain=$sessions->begin('tenant','plain-browser',$remote);Check::same('authenticated',$plain->status());
Check::same(null,$sessions->verify('tenant','alice',$plain->credential()->token())->secondFactorMethod());
echo 'PASS OIDC exact session binding: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
