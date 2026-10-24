<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account as A;
use SoSecurity\Api\ApiKeys;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
$mysql=($argv[1]??'')==='mysql';$mode=$argv[2]??'normal';$directory=privateDirectory();$created=false;$pdo=null;
try{
 foreach(['files','scratch','witness','other'] as $part){mkdir($directory.'/'.$part,0700);}
 if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned private MySQL required.');}}
 $pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$directory.'/state.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
 if(!$mysql){$pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');}
 $pdo->exec('CREATE TABLE api_owned_permissions(id INTEGER NOT NULL PRIMARY KEY, enabled INTEGER NOT NULL)'.($mysql?' ENGINE=InnoDB':''));$created=true;$pdo->exec('INSERT INTO api_owned_permissions VALUES(1,1)');
 $clock=new TestClock();$store=new SoSecurity\Storage\FileStore($directory.'/files','api-state:shared',$clock);$old=new ApiKeys($store,$clock);
 $sql=new A\SqlStateSnapshot($pdo,'api-owned-permissions',['api_owned_permissions'=>['columns'=>['id'=>'int','enabled'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>1]],30000);
 $files=new A\FileStateSnapshot($pdo,'api-owned-files',$directory.'/files',$directory.'/scratch',2,30000);$source=new A\CompositeStateSnapshot($pdo,['permissions'=>$sql,'files'=>$files],30000);
 if($mode==='epoch'){$store->transact('api-key-epoch:'.hash('sha256','client'),static function(){return new SoSecurity\Storage\Change(['v'=>1,'subject'=>'client','epoch'=>str_repeat('a',64)],0,true);});}
 $keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('w',32)]);$witness=new A\LocalStateWitness($pdo,$directory.'/witness','api-state','tenant',str_repeat('e',64),$keys,$source,new A\LocalStatePersistence($directory.'/witness',30000),30000,2);$witness->initialize($source->digest());$boundary=new A\StateBoundary($witness,static function():bool{return true;});
 $calls=0;$guardMode='allow';$actor='operator';
 $guard=static function(string $action,string $scope,string $subject,array $metadata)use($pdo,$clock,&$calls,&$guardMode,&$actor,$mode){++$calls;if($guardMode==='error'){throw new RuntimeException('SYNTHETIC-PRIVATE-AUTHORITY');}if($guardMode==='boolean'){return true;}if($guardMode==='deny'){return null;}if($mode==='late-deny'&&$calls===3){return null;}if($mode==='late-expiry'&&$calls===3){$clock->time+=10;}if($mode==='budget'&&$calls===1){usleep(1100000);}return $scope==='tenant'&&$subject==='client'&&(int)$pdo->query('SELECT enabled FROM api_owned_permissions WHERE id=1')->fetchColumn()===1?$actor:null;};
 $inspect=static function()use($witness):array{return $witness->inspect(static function():bool{return true;});};$initial=$inspect();
 Check::throws(ConfigurationException::class,static function()use($boundary,$witness,$source,$files,$store,$clock,$guard):void{new A\StateApiKeyConnection($boundary,$witness,$source,$files,'files',$store,'api-state','other',str_repeat('e',64),$clock,$guard);});
 Check::throws(ConfigurationException::class,static function()use($boundary,$witness,$source,$files,$store,$guard):void{new A\StateApiKeyConnection($boundary,$witness,$source,$files,'files',$store,'api-state','tenant',str_repeat('e',64),new TestClock(),$guard);});
 $state=new A\StateApiKeyConnection($boundary,$witness,$source,$files,'files',$store,'api-state','tenant',str_repeat('e',64),$clock,$guard);Check::same(0,$calls);Check::same($initial,$inspect());
 $config=['site'=>'api-state','storage'=>['driver'=>'file','directory'=>$directory.'/files']];$sdk=SoSecurity\Security::fromArray($config,[],$clock);$api=$sdk->apiKeys($state);Check::same(0,$calls);Check::same($initial,$inspect());
 $bad=$config;$bad['site']='other';Check::throws(ConfigurationException::class,static function()use($bad,$clock,$state):void{SoSecurity\Security::fromArray($bad,[],$clock)->apiKeys($state);});
 $bad=$config;$bad['storage']['directory']=$directory.'/other';Check::same(true,SoSecurity\Security::fromArray($bad,[],$clock)->apiKeys($state) instanceof ApiKeys);Check::same([],glob($directory.'/other/*.json'));
 Check::throws(ConfigurationException::class,static function()use($state,$directory,$clock):void{new ApiKeys(new SoSecurity\Storage\FileStore($directory.'/files','other',$clock),$clock,$state);});
 $wrongStore=new SoSecurity\Storage\FileStore($directory.'/files','wrong-namespace',$clock);$wrongState=new A\StateApiKeyConnection($boundary,$witness,$source,$files,'files',$wrongStore,'api-state','tenant',str_repeat('e',64),$clock,$guard);
 Check::throws(ConfigurationException::class,static function()use($sdk,$wrongState):void{$sdk->apiKeys($wrongState);});
 Check::throws(ConfigurationException::class,static function()use($state,$api):void{$state->run('authenticate',static function()use($api){$api->issue('client');return false;},static function(){throw new LogicException('Nested operation must not enter effects');});});Check::same($initial,$inspect());

 $id=str_repeat('a',32);$token='sosk_'.$id.'.'.str_repeat('b',64);
 foreach([$old,new ApiKeys(new SoSecurity\Storage\FileStore($directory.'/files','api-state:shared',$clock),$clock),$sdk->apiKeys()] as $raw){
  foreach([static function()use($raw){$raw->issue('client');},static function()use($raw,$token){$raw->authenticate($token);},static function()use($raw,$id){$raw->rotate($id);},static function()use($raw,$id){$raw->revoke($id);}] as $call){try{$call();throw new LogicException('Raw API key bypassed its declared boundary');}catch(StorageException $error){Check::same('account.state_required',$error->reason());}}
 }
 Check::same(null,$api->authenticate($token));Check::same($initial,$inspect());
 if($mode==='race'){
  file_put_contents($directory.'/api-key-worker-owner','owned native API key workers');$jobs=[];$wins=0;$configuration=['directory'=>$directory,'mysql'=>$mysql,'socket'=>$mysql?getenv('SOSECURITY_TEST_MYSQL_SOCKET'):null];
  try{
   for($i=0;$i<4;++$i){$command='exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/api-key-state-worker.php');$process=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($process)){throw new RuntimeException('Cannot start owned key worker');}$jobs[]=[$process,$pipes];$data=json_encode($configuration);if(fwrite($pipes[0],$data)!==strlen($data)){throw new RuntimeException('Cannot send key worker configuration');}fclose($pipes[0]);}
   foreach($jobs as &$job){list($process,$pipes)=$job;$output=stream_get_contents($pipes[1]);$error=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$exit=proc_close($process);$job=null;if($exit!==0){throw new RuntimeException('Owned key worker failed: '.$error);}$value=json_decode($output,true);Check::same(true,is_array($value));if($value['issued']){++$wins;}else{Check::same('api.capacity',$value['reason']);}}unset($job);
   Check::same(2,$wins);Check::same(2,count(glob($directory.'/files/*.json')));Check::same('current',$inspect()['status']);Check::same($source->digest(),$inspect()['digest']);
   echo 'PASS native API key capacity race: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').PHP_EOL;return;
  }finally{foreach($jobs as $job){if($job===null){continue;}list($process,$pipes)=$job;foreach($pipes as $pipe){if(is_resource($pipe)){fclose($pipe);}}if(is_resource($process)){proc_terminate($process);proc_close($process);}}}
 }
 if($mode==='epoch'){
  $credential=$api->issue('client',['read'],10);Check::same('client',$api->authenticate($credential->token())->subject());$next=$api->rotate($credential->identity()->id());Check::same(null,$api->authenticate($credential->token()));Check::same('client',$api->authenticate($next->token())->subject());
  $boundary->run('owned.epoch.change',static function()use($store){$store->transact('api-key-epoch:'.hash('sha256','client'),static function(){return new SoSecurity\Storage\Change(['v'=>1,'subject'=>'client','epoch'=>str_repeat('b',64)],0,true);});});
  $record=$inspect();Check::same(null,$api->authenticate($next->token()));Check::same($record,$inspect());Check::same(true,$api->revoke($next->identity()->id()));$fresh=$api->issue('client',['read'],10);Check::same('client',$api->authenticate($fresh->token())->subject());
  $boundary->run('owned.epoch.invalid',static function()use($store,$clock){$store->transact('api-key-epoch:'.hash('sha256','client'),static function()use($clock){return new SoSecurity\Storage\Change(['v'=>1,'subject'=>'client','epoch'=>str_repeat('b',64)],$clock->time+10,true);});});$record=$inspect();
  try{$api->authenticate($fresh->token());throw new LogicException('Expiring permanent epoch accepted');}catch(StorageException $error){Check::same('storage.corrupt',$error->reason());}Check::same($record,$inspect());
  echo 'PASS native API key epoch: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').PHP_EOL;return;
 }
 if(in_array($mode,['late-deny','late-expiry','budget'],true)){
  $calls=0;try{$api->issue('client',['read'],10);throw new LogicException('Faulted native issuance returned a credential');}catch(SecurityException $error){Check::same($mode==='budget'?'api.timeout':'account.completion_unknown',$error->reason());}
  Check::same($mode==='budget'?0:1,count(glob($directory.'/files/*.json')));Check::same($mode==='budget'?'current':'pending',$inspect()['status']);if($mode==='budget'){Check::same($initial,$inspect());}echo 'PASS native API keys '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').PHP_EOL;return;
 }
 $guardMode='deny';Check::throws(SecurityException::class,static function()use($api):void{$api->issue('client');});Check::same($initial,$inspect());Check::same(0,count(glob($directory.'/files/*.json')));
 foreach(['error','boolean'] as $guardMode){try{$api->issue('client');throw new LogicException('Invalid authority was accepted');}catch(SoSecurity\Exception\DependencyException $error){Check::same('api.authority_unavailable',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'SYNTHETIC')!==false);}Check::same($initial,$inspect());}$guardMode='allow';
 $credential=$api->issue('client',['read'],10);$id=$credential->identity()->id();$token=$credential->token();$record=$inspect();Check::same('api.keys.issue',$record['intent']['action']);Check::same('authorized',$record['intent']['kind']);Check::same(false,strpos(json_encode($record),$token)!==false);Check::same(false,strpos(json_encode($record),'operator')!==false);
 Check::same('client',$api->authenticate($token,'read')->subject());Check::same($record,$inspect());Check::same(null,$api->authenticate($token,'write'));Check::same($record,$inspect());Check::same('client',$api->fromAuthorization('Bearer '.$token)->subject());
 $guardMode='deny';Check::same(null,$api->authenticate($token));Check::same(null,$api->rotate($id));Check::same(false,$api->revoke($id));Check::same($record,$inspect());$guardMode='allow';
 $replacement=$api->rotate($id);Check::same($credential->expiresAt(),$replacement->expiresAt());Check::same('api.keys.rotate',$inspect()['intent']['action']);Check::same(null,$api->authenticate($token));Check::same('client',$api->authenticate($replacement->token())->subject());
 Check::same(true,$api->revoke($id));Check::same('api.keys.revoke',$inspect()['intent']['action']);Check::same(null,$api->authenticate($replacement->token()));$record=$inspect();Check::same(false,$api->revoke($id));Check::same($record,$inspect());
 $one=$api->issue('client',['read'],10);$two=$api->issue('client',['read'],10);$record=$inspect();try{$api->issue('client',['read'],10);throw new LogicException('Native file capacity exceeded');}catch(SecurityException $error){Check::same('api.capacity',$error->reason());}Check::same($record,$inspect());Check::same(2,count(glob($directory.'/files/*.json')));
 $clock->time+=10;Check::same(null,$api->authenticate($one->token()));Check::same($record,$inspect());Check::same(true,$api->revoke($one->identity()->id()));Check::same(1,count(glob($directory.'/files/*.json')));$fresh=$api->issue('client',['read'],10);Check::same('client',$api->authenticate($fresh->token())->subject());
 $boundary->run('permission.disable',static function()use($pdo):void{$pdo->exec('UPDATE api_owned_permissions SET enabled=0 WHERE id=1');});$record=$inspect();Check::same(null,$api->authenticate($fresh->token()));Check::same($record,$inspect());$boundary->run('permission.enable',static function()use($pdo):void{$pdo->exec('UPDATE api_owned_permissions SET enabled=1 WHERE id=1');});
 $file=$directory.'/files/'.$store->snapshotFile('api-key:'.hash('sha256',$fresh->identity()->id()));$backup=file_get_contents($file);$rotated=$api->rotate($fresh->identity()->id());$before=$calls;file_put_contents($file,$backup);
 try{(new ApiKeys($store,$clock,$state))->authenticate($fresh->token());throw new LogicException('Stale API file backup accepted');}catch(StorageException $error){Check::same('account.witness_stale',$error->reason());}Check::same($before,$calls);
 echo 'PASS native API keys: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').PHP_EOL;
}finally{if($mysql&&$created){$pdo->exec('DROP TABLE api_owned_permissions');}foreach(['files','scratch','witness','other'] as $part){cleanDirectory($directory.'/'.$part);}cleanDirectory($directory);}
