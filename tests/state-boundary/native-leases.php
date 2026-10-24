<?php
declare(strict_types=1);
use SoSecurity\Account as A;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
$mode=$argv[4]??'normal';
Check::throws(ConfigurationException::class,static function()use($sdk):void{$sdk->leases();});Check::same($before,$source->digest());
$leaseStore=new SoSecurity\Storage\FileStore($directory.'/files','fresh-site:shared',$clock);
$actor='worker-one';$leaseAllowed=true;$leaseHook=null;$calls=0;
$guard=static function(string &$action,string &$authorityScope,string &$scope,string &$resource,?string &$owner)use(&$actor,&$leaseAllowed,&$leaseHook,&$calls){++$calls;if($leaseHook!==null){return $leaseHook($action,$authorityScope,$scope,$resource,$owner);}return $leaseAllowed&&$authorityScope==='tenant'&&$scope==='jobs'&&$resource==='owned-job'?$actor:null;};
$connection=new A\StateLeaseConnection($boundary,$witness,$source,$files,'files',$leaseStore,'fresh-site','tenant',$epoch,$clock,$guard,$mode==='defaults'?1000:30000);$leases=$sdk->leases($connection);
Check::same($before,$source->digest());
$unchanged=static function(array $before)use($witness,$source):void{Check::same($before,$witness->inspect(static function():bool{return true;}));Check::same($before['digest'],$source->digest());};
$snapshot=$witness->inspect(static function():bool{return true;});$leaseAllowed=false;Check::throws(SecurityException::class,static function()use($leases):void{$leases->initialize('jobs','owned-job');});$unchanged($snapshot);$leaseAllowed=true;
Check::throws(ConfigurationException::class,static function()use($connection,$clock,$directory):void{new SoSecurity\Concurrency\LeaseManager(new SoSecurity\Storage\FileStore($directory.'/budget','fresh-site:shared',$clock),null,$clock,$connection);});$unchanged($snapshot);
$ledgerEpoch=$leases->initialize('jobs','owned-job');Check::same(32,strlen($ledgerEpoch));Check::same('leases.initialize',$witness->inspect(static function():bool{return true;})['intent']['action']);Check::same(0,$leases->inspect('jobs','owned-job')->active());
$snapshot=$witness->inspect(static function():bool{return true;});
if($mode==='corrupt'){
 $key=SoSecurity\Support\Guard::key('leases','jobs','owned-job');$boundary->run('owned.lease.expiring',static function()use($leaseStore,$key,$clock):void{$leaseStore->transact($key,static function($old)use($clock){return new SoSecurity\Storage\Change($old,$clock->time+60,null);});});$snapshot=$witness->inspect(static function():bool{return true;});
 try{$leases->acquire('jobs','owned-job','worker-one');throw new RuntimeException('Expiring lease ledger accepted');}catch(SoSecurity\Storage\StorageException $error){Check::same('storage.corrupt',$error->reason());}$unchanged($snapshot);echo 'PASS native lease permanent ledger: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;
}
if($mode==='clock-error'){
 $clock->fail=true;try{$leases->acquire('jobs','owned-job','worker-one');throw new RuntimeException('Clock error escaped');}catch(SoSecurity\Storage\StorageException $error){Check::same('lease.clock',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'private-permission')!==false);}finally{$clock->fail=false;}$unchanged($snapshot);echo 'PASS native lease clock privacy: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;
}
if($mode==='guard-error'){
 $leaseHook=static function(){throw new RuntimeException('private-lease-guard-detail');};try{$leases->acquire('jobs','owned-job','worker-one');throw new RuntimeException('Guard error escaped');}catch(SoSecurity\Exception\DependencyException $error){Check::same('lease.authority_unavailable',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'private-lease')!==false);}$unchanged($snapshot);
 $leaseHook=null;Check::same(1,$leases->acquire('jobs','owned-job','worker-one')->fence());echo 'PASS native lease guard privacy: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;
}
if($mode==='expiry'){
 $calls=0;$leaseHook=static function()use(&$calls,$clock){if($calls===2){$clock->time+=31;}return 'worker-one';};try{$leases->acquire('jobs','owned-job','worker-one');throw new RuntimeException('Expired admission accepted');}catch(SecurityException $error){Check::same('lease.expired',$error->reason());}$unchanged($snapshot);echo 'PASS native lease admission expiry: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;
}
if(in_array($mode,['late','prewrite'],true)){
 $calls=0;$at=$mode==='late'?4:3;$leaseHook=static function()use(&$calls,$at){return $calls===$at?null:'worker-one';};try{$leases->acquire('jobs','owned-job','worker-one');throw new RuntimeException('Lost authority accepted');}catch(SoSecurity\Storage\StorageException $error){Check::same('account.completion_unknown',$error->reason());}
 Check::same('pending',$witness->inspect(static function():bool{return true;})['status']);$key=SoSecurity\Support\Guard::key('leases','jobs','owned-job');$raw=file_get_contents($directory.'/files/'.$leaseStore->snapshotFile($key));$state=SoSecurity\Storage\Codec::decode($raw,$clock->time);Check::same($mode==='late'?1:0,count($state['holders']));echo 'PASS native lease '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; pending retained, no continuation'.PHP_EOL;return;
}
$leaseHook=static function(string &$action,string &$authorityScope,string &$scope,string &$resource,?string &$owner)use($leases){Check::throws(ConfigurationException::class,static function()use($leases):void{$leases->inspect('jobs','owned-job');});$action='changed';$authorityScope='changed';$scope='changed';$resource='changed';$owner='changed';return 'worker-one';};
$lease=$leases->acquire('jobs','owned-job','worker-one');$leaseHook=null;Check::same(1,$lease->fence());Check::same('leases.acquire',$witness->inspect(static function():bool{return true;})['intent']['action']);
$snapshot=$witness->inspect(static function():bool{return true;});Check::same($lease->token(),$leases->verify('jobs','owned-job','worker-one',$lease->token())->token());$unchanged($snapshot);Check::same(null,$leases->acquire('jobs','owned-job','worker-one'));$unchanged($snapshot);
$actor='worker-two';Check::same(null,$leases->acquire('jobs','owned-job','worker-two'));$unchanged($snapshot);Check::throws(SecurityException::class,static function()use($leases,$lease):void{$leases->verify('jobs','owned-job','worker-one',$lease->token());});$unchanged($snapshot);$actor='worker-one';
$bad=substr($lease->token(),0,-1).(substr($lease->token(),-1)==='a'?'b':'a');Check::same(null,$leases->verify('jobs','owned-job','worker-one',$bad));Check::same(false,$leases->release('jobs','owned-job','worker-one',$bad));$unchanged($snapshot);
$clock->time+=2;$renewed=$leases->renew('jobs','owned-job','worker-one',$lease->token());Check::same($lease->token(),$renewed->token());Check::same($lease->expiresAt()+2,$renewed->expiresAt());Check::same(1,$leases->inspect('jobs','owned-job')->active());Check::same(false,$leases->remove('jobs','owned-job',$ledgerEpoch));
Check::same(true,$leases->release('jobs','owned-job','worker-one',$lease->token()));$snapshot=$witness->inspect(static function():bool{return true;});Check::same(false,$leases->release('jobs','owned-job','worker-one',$lease->token()));$unchanged($snapshot);Check::same(true,$leases->remove('jobs','owned-job',$ledgerEpoch));Check::same(false,$leases->inspect('jobs','owned-job')->initialized());Check::same($source->digest(),$witness->inspect(static function():bool{return true;})['digest']);
Check::throws(SoSecurity\Storage\StorageException::class,static function()use($leaseStore):void{$leaseStore->transact('raw-attempt',static function(){return new SoSecurity\Storage\Change(['bad'=>true],0,null);});});
echo 'PASS native leases: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; explicit caller and resource authority, exact ledger, original fencing preserved'.PHP_EOL;
