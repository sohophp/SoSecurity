<?php
declare(strict_types=1);
require dirname(__DIR__,3).'/tests/bootstrap.php';
if(isset($argv[1])&&$argv[1]!=='-'){require $argv[1];}
spl_autoload_register(static function(string $name):void{$p='SoSecurity\\Oidc\\';if(strpos($name,$p)===0){require dirname(__DIR__).'/src/'.substr($name,strlen($p)).'.php';}});
use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Oidc\LinkRegistry;
use SoSecurity\Oidc\VerifiedSubject;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\FileStore;
$directory=privateDirectory();
try{
 foreach(['memory','file'] as $backend){
  foreach(isset($argv[2])?[$argv[2]]:['guard','exception','success'] as $mode){
    $clock=new TestClock();$store=$backend==='memory'?new MemoryStore($clock):new FileStore($directory,$backend.$mode,$clock);$account=new Account('tenant','alice','1');
    $provider=new CallbackIdentityProvider(static function()use($account){return $account;},static function()use($account){return $account;});
    $allowed=true;$phases=[];$guard=static function(string $phase)use(&$allowed,&$phases):bool{$phases[]=$phase;return $allowed;};
    $sessions=new SessionRegistry($store,$provider,null,$clock);$flow=new AuthenticationFlow($store,$provider,$sessions,$guard,null,$clock);$token=$flow->password('tenant','browser','alice','synthetic')->credential()->token();
    $links=new LinkRegistry($store,$provider,$sessions,$guard,$clock);$r=new ReflectionClass(VerifiedSubject::class);$remote=$r->newInstanceWithoutConstructor();$p=$r->getProperty('read');if(PHP_VERSION_ID<80100){$p->setAccessible(true);}$p->setValue($remote,static function():array{return ['https://issuer.example.test','one',100000,'sid'];});$links->link('tenant','alice',$token,$remote);$calls=0;
    $approval=static function()use(&$allowed,&$calls,$mode):bool{++$calls;if($mode==='guard'){$allowed=false;}if($mode==='exception'){throw new RuntimeException('PRIVATE-RECOVERY-APPROVAL');}return true;};
    try{$result=$links->recoverUnlink('tenant','alice',$token,'https://issuer.example.test','one',$approval);Check::same('success',$mode);Check::same(true,$result);}
    catch(SecurityException $error){Check::same(false,$mode==='success');Check::same(null,$error->getPrevious());Check::same(false,strpos((string)$error,'PRIVATE-RECOVERY-APPROVAL')!==false);}
    Check::same(1,$calls);Check::same($mode==='success',$links->currentBinding('tenant','https://issuer.example.test','one',$account)===null);
    if($mode!=='exception'){Check::same(true,in_array('federation_recovery_unlink_current',$phases,true));}
  }
 }
 echo 'PASS unlink current permission and approval privacy: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
}finally{cleanDirectory($directory);}
