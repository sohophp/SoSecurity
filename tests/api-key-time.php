<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
final class KeyTimeClock implements SoSecurity\Support\Clock
{
    public $time;public $baseline;public $fail=false;
    public function __construct(){$this->baseline=time()+300;$this->time=$this->baseline;}
    public function now():int{if($this->fail){throw new RuntimeException('SYNTHETIC-PRIVATE-CLOCK');}return $this->time;}
}
final class KeyTimeStore implements SoSecurity\Storage\AtomicStore
{
    public $after;public $calls=0;private $base;
    public function __construct(SoSecurity\Storage\AtomicStore $base){$this->base=$base;}
    public function transact(string $key,callable $callback){$result=$this->base->transact($key,$callback);++$this->calls;if($this->after!==null){($this->after)($this->calls);}return $result;}
}
$directory=privateDirectory();$mysql=($argv[1]??'')==='mysql';$redisMode=($argv[1]??'')==='redis';$pdo=null;$redis=null;
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Owned private MySQL required.');}$pdo=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);SoSecurity\Storage\MySqlStore::install($pdo);}
if($redisMode){$socket=getenv('SOSECURITY_TEST_REDIS_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-keytime-[A-Za-z0-9_-]+/redis\.sock\z~D',$socket)||!is_file(dirname($socket).'/api-key-time-owner')){throw new RuntimeException('Owned private Redis required.');}$redis=new Redis();$redis->connect($socket,0,2.0);}
try{
 foreach($redisMode?['redis']:($mysql?['mysql']:['memory','files']) as $backend){
  foreach(['authenticate'=>4,'issue'=>3,'rotate'=>4] as $operation=>$last){foreach(['expiry','backward','error','regression','initial-error'] as $fault){
   $clock=new KeyTimeClock();$namespace='key-time-'.$operation.'-'.$fault;
   $base=$backend==='mysql'?new SoSecurity\Storage\MySqlStore($pdo,$namespace,$clock):($backend==='redis'?new SoSecurity\Storage\RedisStore($redis,$namespace,$clock):($backend==='files'?new SoSecurity\Storage\FileStore($directory,$namespace,$clock):new SoSecurity\Storage\MemoryStore($clock)));if($redisMode){$base->initialize();}$store=new KeyTimeStore($base);$keys=new SoSecurity\Api\ApiKeys($store,$clock);$credential=$operation==='issue'?null:$keys->issue('owner',['read'],10);$store->calls=0;
   $store->after=static function(int $call)use($last,$clock,$fault):void{if($fault==='regression'&&$call===$last-1){++$clock->time;}if($call===$last){if($fault==='regression'){$clock->time=$clock->baseline;}elseif($fault==='expiry'){$clock->time+=10;}elseif($fault==='backward'){--$clock->time;}else{$clock->fail=true;}}};
   if($fault==='initial-error'){$clock->fail=true;}
   $call=static function()use($keys,$credential,$operation){if($operation==='authenticate'){return $keys->authenticate($credential->token(),'read');}if($operation==='rotate'){return $keys->rotate($credential->identity()->id());}return $keys->issue('owner',['read'],10);};
   if($operation==='authenticate'&&!in_array($fault,['error','initial-error'],true)){Check::same(null,$call());}
   else{try{$call();throw new LogicException('Late '.$operation.' accepted '.$fault);}catch(SoSecurity\Storage\StorageException $error){Check::same(($operation==='authenticate'||$fault==='initial-error')?'api.clock':($operation==='issue'?'api.issuance_unknown':'api.rotation_unknown'),$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'SYNTHETIC')!==false);}}
   Check::same($fault==='initial-error'?0:$last,$store->calls);
  }}
  foreach(['authenticate','rotate'] as $operation){
   $clock=new KeyTimeClock();$namespace='key-time-future-'.$operation;$base=$backend==='mysql'?new SoSecurity\Storage\MySqlStore($pdo,$namespace,$clock):($backend==='redis'?new SoSecurity\Storage\RedisStore($redis,$namespace,$clock):($backend==='files'?new SoSecurity\Storage\FileStore($directory,$namespace,$clock):new SoSecurity\Storage\MemoryStore($clock)));if($redisMode){$base->initialize();}$store=new KeyTimeStore($base);$keys=new SoSecurity\Api\ApiKeys($store,$clock);$credential=$keys->issue('owner',['read'],10);$clock->time=$clock->baseline-1;$store->calls=0;
   Check::same(null,$operation==='authenticate'?$keys->authenticate($credential->token()):$keys->rotate($credential->identity()->id()));Check::same(1,$store->calls);$clock->time=$clock->baseline;Check::same('owner',$keys->authenticate($credential->token())->subject());
  }
  foreach(['issue'=>1,'rotate'=>2] as $operation=>$last){
   $clock=new KeyTimeClock();$namespace='key-time-before-'.$operation;$base=$backend==='mysql'?new SoSecurity\Storage\MySqlStore($pdo,$namespace,$clock):($backend==='redis'?new SoSecurity\Storage\RedisStore($redis,$namespace,$clock):($backend==='files'?new SoSecurity\Storage\FileStore($directory,$namespace,$clock):new SoSecurity\Storage\MemoryStore($clock)));if($redisMode){$base->initialize();}$store=new KeyTimeStore($base);$keys=new SoSecurity\Api\ApiKeys($store,$clock);$credential=$operation==='issue'?null:$keys->issue('owner',['read'],10);$store->calls=0;$store->after=static function(int $call)use($last,$clock):void{if($call===$last){$clock->time+=10;}};
   if($operation==='issue'){try{$keys->issue('owner',['read'],10);throw new LogicException('Expired allocation attempted');}catch(SoSecurity\Exception\SecurityException $error){Check::same('api.expired',$error->reason());}}
   else{Check::same(null,$keys->rotate($credential->identity()->id()));}
   Check::same($last,$store->calls);$store->after=null;$clock->time=$clock->baseline;
   if($credential!==null){Check::same('owner',$keys->authenticate($credential->token())->subject());}
  }
 }
 echo 'PASS API key I/O time: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($redisMode?'redis':($mysql?'mysql':'memory/files')).PHP_EOL;
}finally{cleanDirectory($directory);}
