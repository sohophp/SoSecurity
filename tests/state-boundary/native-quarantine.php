<?php
declare(strict_types=1);
require dirname(__DIR__).'/bootstrap.php';
use SoSecurity\Account as A;
use SoSecurity\Upload as U;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Storage\StorageException;
$directory=privateDirectory();$pdo=null;
try{
 foreach(['spool','web','files','scratch','witness'] as $name){mkdir($directory.'/'.$name,0700);}
 $mysql=($argv[1]??'')==='mysql';$mode=$argv[2]??'normal';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
 if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned private MySQL required.');}
 $pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$directory.'/state.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);if(!$mysql){$pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');}
 $clock=new class implements SoSecurity\Support\Clock{public $time=100000;public $fault=false;public function now():int{if($this->fault){throw new RuntimeException('private clock secret');}return $this->time;}};$policy=new U\Policy(['extensions'=>['txt'],'maximum_bytes'=>1024,'require_scan'=>true]);$queueOptions=['maximum_entries'=>2,'maximum_total_bytes'=>1536,'scan_milliseconds'=>1000,'lifetime_seconds'=>60,'retry_seconds'=>1];
 $spool=new A\QuarantineStateSnapshot($pdo,'owned-spool',$directory.'/spool',$directory.'/web',$policy,2,1536,30000);$metadata=new A\FileStateSnapshot($pdo,'owned-metadata',$directory.'/files',$directory.'/scratch',8,30000);$source=new A\CompositeStateSnapshot($pdo,['metadata'=>$metadata,'spool'=>$spool],30000);
 $keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);$epoch=str_repeat('e',64);$site='owned-site';$witness=new A\LocalStateWitness($pdo,$directory.'/witness',$site,'tenant',$epoch,$keys,$source,new A\LocalStatePersistence($directory.'/witness',30000),30000,2);$witness->initialize($source->digest());
 $allow=true;$fault=false;$mutate=false;$final=null;$calls=[];
 $boundary=new A\StateBoundary($witness,static function(string $phase,string $action)use(&$final):bool{if($phase==='final'&&$final!==null){$f=$final;$final=null;$f();}return true;});
 $store=new SoSecurity\Storage\FileStore($directory.'/files',$site.':shared',$clock);
 $scanner=new class implements U\Scanner {public $calls=0;public $callback;public $passed=true;public function scan(U\Candidate $candidate):bool{++$this->calls;if($this->callback!==null){($this->callback)();}return $this->passed;}};
 $guard=static function(string &$action,string &$scope,string &$queue,?string &$id,array &$descriptor)use(&$allow,&$fault,&$mutate,&$calls):?string{$calls[]=[$action,$scope,$queue,$id,$descriptor];if($fault){throw new RuntimeException('private authority secret');}if($mutate){$action='quarantine.remove';$scope='evil';$queue='evil';$id=str_repeat('f',32);$descriptor=['bad'=>true];}return $allow?'actual-actor':null;};
 $connection=new A\StateQuarantineConnection($boundary,$witness,$source,$metadata,'metadata',$store,$spool,'spool',$site,'tenant',$epoch,$clock,$scanner,$guard,30000);
 $config=['site'=>$site,'storage'=>['driver'=>'file','directory'=>$directory.'/files'],'upload_quarantine'=>['directory'=>$directory.'/spool','document_root'=>$directory.'/web','scanner'=>'scanner','policy'=>$policy->options(),'queue'=>$queueOptions]];
 $factory=SoSecurity\Security::fromArray($config,['scanner'=>$scanner],$clock);$queue=$factory->quarantine($connection);
 $state=static function()use($witness):array{return $witness->inspect(static function():bool{return true;});};
 $before=$state();if($mode==='clock'){$clock->fault=true;try{$queue->items();throw new RuntimeException('Fault accepted');}catch(StorageException $e){Check::same('upload.quarantine_clock',$e->reason());Check::same(null,$e->getPrevious());Check::same(false,strpos($e->getMessage(),'secret')!==false);}$clock->fault=false;Check::same($before,$state());echo 'PASS native quarantine clock '.Check::$assertions.PHP_EOL;return;}
 Check::same([],$queue->items());Check::same(null,$queue->inspect(str_repeat('a',32)));Check::same(null,$queue->process());Check::same(false,$queue->remove(str_repeat('a',32)));Check::same($before,$state());
 $allow=false;try{$queue->enqueueFile('/does-not-exist','bad.txt');throw new RuntimeException('Denied input read');}catch(SecurityException $e){Check::same('upload.quarantine_denied',$e->reason());}$allow=true;Check::same($before,$state());
 $fault=true;try{$queue->items();throw new RuntimeException('Fault accepted');}catch(DependencyException $e){Check::same(null,$e->getPrevious());Check::same(false,strpos($e->getMessage(),'secret')!==false);}$fault=false;
 Check::throws(ConfigurationException::class,static function()use($factory,$connection,$config,$clock):void{SoSecurity\Security::fromArray(array_replace($config,['site'=>'wrong']),['scanner'=>new class implements U\Scanner{public function scan(U\Candidate $c):bool{return true;}}],$clock)->quarantine($connection);});
 file_put_contents($directory.'/input.txt','owned native content');chmod($directory.'/input.txt',0600);
 $mutate=true;$item=$queue->enqueueFile($directory.'/input.txt','owned.txt');$mutate=false;$id=$item->id();Check::same('pending',$item->state());Check::same(0,$scanner->calls);Check::same('pending',$queue->inspect($id)->state());
 if($mode==='tamper'){file_put_contents($directory.'/spool/'.$id.'.txt','changed native bytes');Check::throws(StorageException::class,static function()use($queue,$id):void{$queue->process($id);});Check::same(0,$scanner->calls);echo 'PASS native quarantine tamper '.Check::$assertions.PHP_EOL;return;}
 if($mode==='scan-error'){$scanner->callback=static function():void{throw new RuntimeException('private scanner detail');};$failed=$queue->process($id);Check::same('retry',$failed->state());Check::same('scan.failed',$failed->error());Check::same(1,$scanner->calls);Check::same('current',$state()['status']);echo 'PASS native quarantine scan error '.Check::$assertions.PHP_EOL;return;}
 if($mode==='scan-expiry'){$scanner->callback=static function()use($clock):void{$clock->time+=60;};Check::throws(SecurityException::class,static function()use($queue,$id):void{$queue->process($id);});Check::same(1,$scanner->calls);Check::same('pending',$state()['status']);echo 'PASS native quarantine scan expiry '.Check::$assertions.PHP_EOL;return;}
 if($mode==='late-denial'){$scanner->callback=static function()use(&$allow):void{$allow=false;};Check::throws(SecurityException::class,static function()use($queue,$id):void{$queue->process($id);});Check::same(1,$scanner->calls);$receipt=$state();Check::same('pending',$receipt['status']);echo 'PASS native quarantine late denial '.Check::$assertions.PHP_EOL;return;}
 $second=$queue->enqueueFile($directory.'/input.txt','second.txt');$before=$state();Check::throws(StorageException::class,static function()use($queue,$directory):void{$queue->enqueueFile($directory.'/input.txt','third.txt');});Check::same($before,$state());
 $scanner->callback=static function()use($queue,$second):void{Check::throws(ConfigurationException::class,static function()use($queue,$second):void{$queue->reject($second->id());});};
 $ready=$queue->process();Check::same($id,$ready->id());Check::same('available',$ready->state());Check::same('pending',$queue->inspect($second->id())->state());Check::same('owned native content',$queue->readAvailable($id)->contents());$scanner->callback=null;
 if($mode==='final-expiry'){$final=static function()use($clock):void{$clock->time+=60;};Check::throws(SecurityException::class,static function()use($queue,$id):void{$queue->readAvailable($id);});Check::same('current',$state()['status']);echo 'PASS native quarantine final expiry '.Check::$assertions.PHP_EOL;return;}
 if($mode==='final-denial'){$final=static function()use(&$allow):void{$allow=false;};Check::throws(SecurityException::class,static function()use($queue,$id):void{$queue->readAvailable($id);});Check::same('current',$state()['status']);echo 'PASS native quarantine final denial '.Check::$assertions.PHP_EOL;return;}
 $scanner->passed=false;Check::same('rejected',$queue->process($second->id())->state());Check::same('pending',$queue->rescan($second->id())->state());$scanner->passed=true;Check::same('available',$queue->process($second->id())->state());
 Check::same('rejected',$queue->reject($id)->state());Check::throws(SecurityException::class,static function()use($queue,$id):void{$queue->readAvailable($id);});Check::same(true,$queue->remove($id));Check::same(null,$queue->inspect($id));Check::same('rejected',$queue->reject($second->id())->state());Check::same(true,$queue->remove($second->id()));Check::same([],$queue->items());
 Check::throws(StorageException::class,static function()use($factory,$directory):void{$factory->quarantine()->enqueueFile($directory.'/input.txt','raw.txt');});Check::same($source->digest(),$state()['digest']);Check::same(3,$scanner->calls);
 echo 'PASS native quarantine normal '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
}finally{$pdo=null;foreach(['spool','web','files','scratch','witness'] as $name){cleanDirectory($directory.'/'.$name);}cleanDirectory($directory);}
