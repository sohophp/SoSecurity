<?php
declare(strict_types=1);
require dirname(__DIR__,3).'/tests/bootstrap.php';
if(isset($argv[1])&&$argv[1]!=='-'){require $argv[1];}
spl_autoload_register(static function(string $name):void{$prefix='SoSecurity\\WebAuthn\\';if(strpos($name,$prefix)===0){require dirname(__DIR__).'/src/'.substr($name,strlen($prefix)).'.php';}});
use SoSecurity\WebAuthn\SessionDeviceAuthority;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Storage\MemoryStore;
$mode=$argv[2]??'current-binding';$marker='private-authority-credential';$clock=new class implements SoSecurity\Support\Clock {public $time=1000;public $fault=false;public function now():int{if($this->fault){throw new RuntimeException('private-authority-credential');}return $this->time;}};
$account=new Account('tenant','alice','1');$providerFault=false;$referenceFault=false;
$provider=new CallbackIdentityProvider(static function()use($account){return $account;},static function()use($account,&$providerFault,$marker){if($providerFault){throw new RuntimeException($marker);}return $account;});
$store=new MemoryStore($clock);$sessions=new SessionRegistry($store,$provider,null,$clock,600,1200);$credential=$sessions->register('tenant','alice',hash('sha256',$account->fingerprint().':none'),$sessions->epoch('tenant','alice'),'webauthn');
$proofFault=false;$proofStore=new class($store,$proofFault) implements SoSecurity\Storage\AtomicStore {
 private $store;private $fault;public function __construct($store,&$fault){$this->store=$store;$this->fault=&$fault;}
 public function transact(string $key,callable $callback){if($this->fault){throw new RuntimeException('private-authority-credential');}return $this->store->transact($key,$callback);}
};
$binding='browser-one';$csrf=new CsrfTokens($proofStore,600,16,$clock);$authority=new SessionDeviceAuthority('tenant',$sessions,$csrf,static function()use($credential,&$binding,&$referenceFault,$marker):array{if($referenceFault){throw new RuntimeException($marker);}return ['subject'=>'alice','token'=>$credential->token(),'binding'=>$binding];},$clock);
$proof=$authority->issueRemovalProof('alice','device');
if(in_array($mode,['current-binding','return-binding','normal'],true)){
 Check::same(true,$authority->allow('before','tenant','alice','device',$proof,1000));
 if($mode==='return-binding'){Check::same(true,$authority->allow('current','tenant','alice','device',$proof,1000));}
 if($mode!=='normal'){$binding='browser-two';}
 Check::same($mode==='normal',$authority->allow($mode==='return-binding'?'return':'current','tenant','alice','device',$proof,1000));
 if($mode!=='normal'){$binding='browser-one';Check::same(false,$authority->allow('return','tenant','alice','device',$proof,1000));Check::same(false,$authority->allow('before','tenant','alice','device',$proof,1000));}
 else{Check::same(true,$authority->allow('return','tenant','alice','device',$proof,1000));}
}else{
 $proofFault=strpos($mode,'proof')!==false;
 $referenceFault=strpos($mode,'reference')!==false;$providerFault=strpos($mode,'provider')!==false;$clock->fault=strpos($mode,'clock')!==false;
 $caught=null;try{if(strpos($mode,'issue-')===0){$authority->issueRemovalProof('alice','device');}else{$authority->allow('before','tenant','alice','device',$proof,1000);}}catch(Throwable $error){$caught=$error;}
 Check::same(true,$caught instanceof SoSecurity\Exception\SecurityException);Check::same($proofFault?'webauthn.request_unavailable':($mode==='issue-clock'?'webauthn.clock':'webauthn.authority_unavailable'),$caught->reason());Check::same(null,$caught->getPrevious());Check::same(false,strpos($caught->getMessage(),$marker)!==false);
}
echo 'PASS WebAuthn authority binding '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
