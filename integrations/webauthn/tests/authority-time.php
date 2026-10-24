<?php
declare(strict_types=1);
require dirname(__DIR__,3).'/tests/bootstrap.php';
if(isset($argv[1])&&$argv[1]!=='-'){require $argv[1];}
spl_autoload_register(static function(string $name):void{$p='SoSecurity\\WebAuthn\\';if(strpos($name,$p)===0){require dirname(__DIR__).'/src/'.substr($name,strlen($p)).'.php';}});
use SoSecurity\Auth\Account;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\WebAuthn\SessionDeviceAuthority;
foreach(isset($argv[2])?[$argv[2]]:['issue','before','return','csrf_issue','csrf_verify','future','stale','csrf_issue_backwards','csrf_verify_backwards','live_issue','live_return','live'] as $mode){
 $clock=new TestClock();$clock->time=1000;$account=new Account('tenant','alice','1');$store=new MemoryStore($clock);
 $provider=new CallbackIdentityProvider(static function()use($account){return $account;},static function()use($account){return $account;});
 $sessions=new SessionRegistry($store,$provider,null,$clock,600,1200);$credential=$sessions->register('tenant','alice',hash('sha256',$account->fingerprint().':none'),$sessions->epoch('tenant','alice'),'webauthn');
 $delayReference=false;$delayCsrf=false;
 $csrfStore=new class($store,$clock,$delayCsrf) implements AtomicStore {
  private $store;private $clock;private $delay;
  public function __construct($store,$clock,&$delay){$this->store=$store;$this->clock=$clock;$this->delay=&$delay;}
  public function transact(string $key,callable $callback){$result=$this->store->transact($key,$callback);if($this->delay){$delta=$this->delay;$this->delay=false;$this->clock->time+=$delta;}return $result;}
 };
 $csrf=new CsrfTokens($csrfStore,600,16,$clock);
 $reference=static function()use(&$delayReference,$credential,$clock):array{if($delayReference){$delayReference=false;$clock->time+=2;}return ['subject'=>'alice','token'=>$credential->token(),'binding'=>'browser'];};
 $authority=new SessionDeviceAuthority('tenant',$sessions,$csrf,$reference,$clock);
 $proof=$authority->issueRemovalProof('alice','device');
 if($mode==='return'||$mode==='live_return'){Check::same(true,$authority->allow('before','tenant','alice','device',$proof,$clock->time));}
 $clock->time=1299;
 if(in_array($mode,['issue','before','return'],true)){$delayReference=true;}
 if(in_array($mode,['csrf_issue','csrf_verify'],true)){$delayCsrf=2;}
 if(in_array($mode,['csrf_issue_backwards','csrf_verify_backwards'],true)){$delayCsrf=-2;}
 if($mode==='live_issue'){Check::same(true,is_string($authority->issueRemovalProof('alice','device')));}
 elseif($mode==='issue'||$mode==='csrf_issue'||$mode==='csrf_issue_backwards'){
  Check::throws(SecurityException::class,static function()use($authority):void{$authority->issueRemovalProof('alice','device');});
 }else{
  $now=$clock->time;
  if($mode==='future'){$clock->time=1298;}
  if($mode==='stale'){$clock->time=1301;}
  if($mode==='csrf_verify_backwards'){
   try{$authority->allow('before','tenant','alice','device',$proof,$now);throw new RuntimeException('Backward CSRF clock accepted');}
   catch(SoSecurity\Storage\StorageException $error){Check::same('csrf.clock',$error->reason());Check::same(null,$error->getPrevious());}
   $clock->time=$now;
   Check::same(false,$authority->allow('before','tenant','alice','device',$proof,$now));
   Check::same(false,$authority->allow('current','tenant','alice','device',$proof,$now));
   Check::same(false,$authority->allow('return','tenant','alice','device',$proof,$now));
  }else{
  Check::same($mode==='live'||$mode==='live_return',$authority->allow($mode==='return'||$mode==='live_return'?'return':'before','tenant','alice','device',$proof,$now));
  }
 }
}
echo 'PASS WebAuthn removal authority timing: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; synthetic trusted session, no device ceremony\n";
