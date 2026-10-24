<?php
declare(strict_types=1);
require dirname(__DIR__,3).'/tests/bootstrap.php';
if(isset($argv[2])){require $argv[2];}
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
use SoSecurity\Exception\SecurityException;

$clock=new TestClock();$store=new MemoryStore($clock);$account=new Account('tenant','alice','1');
$hook=null;$reads=0;$injectAt=1;
$provider=new CallbackIdentityProvider(static function()use($account){return $account;},static function()use($account,&$hook,&$reads,&$injectAt){
    ++$reads;if($hook!==null && $reads===$injectAt){$next=$hook;$hook=null;$next();}return $account;
});
$guard=static function():bool{return true;};
$localSessions=new SessionRegistry($store,$provider,null,$clock);
$flow=new AuthenticationFlow($store,$provider,$localSessions,$guard,null,$clock);
$local=$flow->password('tenant','browser','alice','synthetic')->credential();
$fence=new LogoutFence($store,$clock);$links=new LinkRegistry($store,$provider,$localSessions,$guard,$clock,$fence);
// Synthetic, already verified identity only; this test makes no claim about an OIDC issuer.
$class=new ReflectionClass(VerifiedSubject::class);$remote=$class->newInstanceWithoutConstructor();
$read=$class->getProperty('read');if(PHP_VERSION_ID<80100){$read->setAccessible(true);}
$time=$clock->time;$read->setValue($remote,static function()use($time):array{return ['https://issuer.example.test','external-alice',$time,'sid'];});
Check::same(true,$links->link('tenant','alice',$local->token(),$remote));
$sessions=new FederatedSessions($store,$provider,$links,$fence,$guard,null,$clock,10,30);
$issued=$sessions->issue('tenant',$remote);Check::same(true,$issued!==null);
$mode=$argv[1] ?? 'absolute';
$reads=0;$injectAt=strpos($mode,'final')!==false?3:1;
$delta=strpos($mode,'live')!==false?9:(strpos($mode,'idle')!==false?10:($mode==='backwards'?-1:30));
$hook=static function()use($clock,$delta):void{$clock->time+=$delta;};
if($mode==='backwards'){
    Check::throws(SecurityException::class,static function()use($sessions,$issued):void{$sessions->verify('tenant','alice',$issued->token());});
}elseif(strpos($mode,'live')!==false){
    Check::same(true,$sessions->verify('tenant','alice',$issued->token())!==null);
}else{
    Check::same(null,$sessions->verify('tenant','alice',$issued->token()));
    Check::same(null,$sessions->verify('tenant','alice',$issued->token()));
}
echo 'PASS OIDC session I/O time '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
