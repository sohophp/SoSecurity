<?php
declare(strict_types=1);
use SoSecurity\Account as A;
use SoSecurity\Idempotency as I;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Storage\StorageException;
$mode=$argv[4]??'normal';$clockShift=false;$guardAllowed=true;$guardFault=false;$guardCalls=0;$guardNested=null;
$guard=static function(string &$action,string &$scope,string &$subject,string &$operation)use(&$guardAllowed,&$guardFault,&$guardCalls,&$clockShift,&$guardNested,$clock):bool{++$guardCalls;if($guardNested!==null){$run=$guardNested;$guardNested=null;$run();}if($clockShift){$clock->time+=$guardCalls===1?10:-10;}if($guardFault){throw new RuntimeException('private idempotency guard');}$valid=$guardAllowed&&$scope==='tenant'&&$subject==='fresh-user';$action='mutated';$scope='evil';$subject='evil';$operation='evil';return $valid;};
$queueConfig=$config;$queueConfig['idempotency']=['connection'=>'db','epoch'=>$epoch,'integrity_keys'=>'idem_keys','authority'=>'idem_allow','management_guard'=>'idem_manage','policy'=>['ttl'=>60,'maximum_entries'=>8,'io_milliseconds'=>30000]];
if($mode==='defaults'){unset($queueConfig['idempotency']['policy']['io_milliseconds']);}
$queueServices=$services+['idem_keys'=>$keys,'idem_allow'=>static function():bool{return true;},'idem_manage'=>$guard];
$factory=SoSecurity\Security::fromArray($queueConfig,$queueServices,$clock);Check::throws(ConfigurationException::class,static function()use($factory):void{$factory->idempotency();});$executor=$factory->idempotency($accountConnection);
$permission=static function(string $action,string $operation='orders.create')use($executor,&$token):A\StatePermission{$target=$action==='initialize'?$executor->initializationTarget('tenant','fresh-user',$operation):$executor->maintenanceTarget('tenant','fresh-user',$operation,1);return new A\StatePermission('idempotency.'.$action,'tenant','fresh-user',$target,$token,['maintainer'],1,300,true,false,['password']);};
$inspect=static function()use($witness):array{return $witness->inspect(static function():bool{return true;});};$before=$inspect();Check::same(false,$executor->initializeFor($policy,$permission('initialize'),'tenant','fresh-user','orders.create'));Check::same($before,$inspect());Check::same(0,$guardCalls);
$boundary->run('owned.idempotency.roles',static function()use($pdo):void{$pdo->prepare('UPDATE account_example SET roles=?')->execute(['["maintainer"]']);});$login=$auth->password('tenant','fresh-idempotency','fresh@example.test',$password);$token=$login->credential()->token();
$guardAllowed=false;$before=$inspect();Check::same(false,$executor->initializeFor($policy,$permission('initialize'),'tenant','fresh-user','orders.create'));Check::same($before,$inspect());$guardAllowed=true;
$guardFault=true;try{$executor->initializeFor($policy,$permission('initialize'),'tenant','fresh-user','orders.create');throw new RuntimeException('Guard fault accepted');}catch(DependencyException $e){Check::same(null,$e->getPrevious());Check::same(false,strpos($e->getMessage(),'private')!==false);}$guardFault=false;Check::same($before,$inspect());
if($mode==='backward'){$clockShift=true;$guardCalls=0;$before=$inspect();Check::throws(StorageException::class,static function()use($executor,$policy,$permission):void{$executor->initializeFor($policy,$permission('initialize'),'tenant','fresh-user','orders.create');});Check::same($before,$inspect());Check::same('0',(string)$pdo->query('SELECT COUNT(*) FROM sosecurity_idempotency_roots')->fetchColumn());echo 'PASS native idempotency backward admission '.Check::$assertions.PHP_EOL;return;}
if($mode==='final-reentry'){
 $nestedBlocked=false;$completedWitness=null;
 $nativeFinalHook=static function()use(&$guardNested,&$nestedBlocked,&$completedWitness,$inspect,$factory,$accountConnection,$policy,$permission):void{
  $guardNested=static function()use(&$completedWitness,$inspect,&$nestedBlocked,$factory,$accountConnection,$policy,$permission):void{
   $completedWitness=$inspect();
   $other=$factory->idempotency($accountConnection);
   try{$other->maintainFor($policy,$permission('maintain'),'tenant','fresh-user','orders.create',1);}catch(ConfigurationException $error){$nestedBlocked=true;}
  };
 };
 Check::same(true,$executor->initializeFor($policy,$permission('initialize'),'tenant','fresh-user','orders.create'));
 Check::same(true,$nestedBlocked);Check::same($completedWitness,$inspect());
 // The guard must be released after successful completion, allowing an independent next call.
 Check::same(0,$executor->maintainFor($policy,$permission('maintain'),'tenant','fresh-user','orders.create',1)['scanned']);
 echo 'PASS native idempotency final reentry '.Check::$assertions.PHP_EOL;return;
}
if(in_array($mode,['final-denial','final-expiry'],true)){$nativeFinalHook=static function()use(&$guardAllowed,$clock,$mode):void{if($mode==='final-expiry'){$clock->time+=301;}else{$guardAllowed=false;}};Check::throws(SecurityException::class,static function()use($executor,$policy,$permission):void{$executor->initializeFor($policy,$permission('initialize'),'tenant','fresh-user','orders.create');});Check::same('current',$inspect()['status']);Check::same('1',(string)$pdo->query('SELECT COUNT(*) FROM sosecurity_idempotency_roots')->fetchColumn());echo 'PASS native idempotency '.$mode.' '.Check::$assertions.PHP_EOL;return;}
$guardNested=static function()use($executor,$policy,$permission):void{Check::throws(ConfigurationException::class,static function()use($executor,$policy,$permission):void{$executor->initializeFor($policy,$permission('initialize'),'tenant','fresh-user','orders.create');});};
Check::same(true,$executor->initializeFor($policy,$permission('initialize'),'tenant','fresh-user','orders.create'));$before=$inspect();Check::same(false,$executor->initializeFor($policy,$permission('initialize'),'tenant','fresh-user','orders.create'));Check::same($before,$inspect());
Check::throws(StorageException::class,static function()use($executor):void{$executor->initialize('tenant','fresh-user','raw.attempt');});
$before=$inspect();Check::throws(SecurityException::class,static function()use($executor,$policy,$permission):void{$executor->initializeFor($policy,$permission('initialize','orders.other'),'tenant','fresh-user','orders.other');});Check::same($before,$inspect());Check::same('1',(string)$pdo->query('SELECT COUNT(*) FROM sosecurity_idempotency_roots')->fetchColumn());
$request=new I\Request('tenant','fresh-user','orders.create','owned-request-000001','POST','/orders','{}');$calls=0;
$boundary->run('owned.idempotency.known_seed',static function()use($executor,$request,&$calls):void{$result=$executor->execute($request,static function()use(&$calls):I\Response{++$calls;return new I\Response(201,'owned result');});Check::same(false,$result->replayed());});
$clock->time+=60;$maintenance=$executor->maintainFor($policy,$permission('maintain'),'tenant','fresh-user','orders.create',1);Check::same(1,$maintenance['compacted']);Check::same(1,$calls);Check::same('expired',$pdo->query('SELECT status FROM sosecurity_idempotency_records')->fetchColumn());Check::same('0',(string)$pdo->query('SELECT '.($mysql?'OCTET_LENGTH':'length').'(response_body) FROM sosecurity_idempotency_records')->fetchColumn());Check::same('1',(string)$pdo->query('SELECT COUNT(*) FROM sosecurity_idempotency_records')->fetchColumn());Check::same($source->digest(),$inspect()['digest']);
$rotationKeys=new SoSecurity\Support\HmacKeys('rotated',['fresh'=>str_repeat('k',32),'rotated'=>str_repeat('r',32)]);$queueServices['idem_keys']=$rotationKeys;$rotator=SoSecurity\Security::fromArray($queueConfig,$queueServices,$clock)->idempotency($accountConnection);
$before=$inspect();Check::throws(ConfigurationException::class,static function()use($rotator,$policy,$permission):void{$rotator->maintainFor($policy,$permission('maintain'),'tenant','fresh-user','orders.create',1);});Check::same($before,$inspect());
$permit=new A\StatePermission('idempotency.maintain','tenant','fresh-user',$rotator->maintenanceTarget('tenant','fresh-user','orders.create',1),$token,['maintainer'],1,300,true,false,['password']);$result=$rotator->maintainFor($policy,$permit,'tenant','fresh-user','orders.create',1);Check::same(1,$result['rekeyed']);Check::same('rotated',$pdo->query('SELECT seal_key FROM sosecurity_idempotency_records')->fetchColumn());Check::same(1,$calls);
echo 'PASS native idempotency initialization and maintenance '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
