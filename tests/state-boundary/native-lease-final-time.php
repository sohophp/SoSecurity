<?php
declare(strict_types=1);
require dirname(__DIR__).'/bootstrap.php';
use SoSecurity\Account as A;
final class LeaseFinalClock implements SoSecurity\Support\Clock {public $time=100000;public function now():int{return $this->time;}}
$directory=privateDirectory();$pdo=null;
try{
 foreach(['files','scratch','witness'] as $name){mkdir($directory.'/'.$name,0700);}
 $mysql=($argv[2]??'')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
 if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned private MySQL required.');}
 $pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$directory.'/lease.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);if(!$mysql){$pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');}
 $clock=new LeaseFinalClock();$files=new A\FileStateSnapshot($pdo,'lease-final-files',$directory.'/files',$directory.'/scratch',8,30000);$source=new A\CompositeStateSnapshot($pdo,['files'=>$files],30000);$keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);$epoch=str_repeat('e',64);
 $witness=new A\LocalStateWitness($pdo,$directory.'/witness','lease-site','tenant',$epoch,$keys,$source,new A\LocalStatePersistence($directory.'/witness',30000),30000,2);$witness->initialize($source->digest());$late=false;$backward=($argv[1]??'')==='backward';$revoke=($argv[1]??'')==='authority';$allowed=true;
 $boundary=new A\StateBoundary($witness,static function(string $phase)use(&$late,$clock,$backward,$revoke,&$allowed):bool{if($late&&$phase==='final'){$late=false;if($revoke){$allowed=false;}else{$clock->time+=$backward?-1:31;}}return true;});
 $store=new SoSecurity\Storage\FileStore($directory.'/files','lease-site:shared',$clock);$connection=new A\StateLeaseConnection($boundary,$witness,$source,$files,'files',$store,'lease-site','tenant',$epoch,$clock,static function()use(&$allowed){return $allowed?'owned-worker':null;},30000);$manager=new SoSecurity\Concurrency\LeaseManager($store,null,$clock,$connection);$manager->initialize('jobs','owned');$late=true;
 try{$manager->acquire('jobs','owned','owned-worker');throw new RuntimeException('Late lease credential returned after witness completion');}catch(SoSecurity\Exception\SecurityException $error){Check::same($revoke?'lease.denied':($backward?'lease.clock':'lease.expired'),$error->reason());}
 Check::same('current',$witness->inspect(static function():bool{return true;})['status']);Check::same($source->digest(),$witness->inspect(static function():bool{return true;})['digest']);
 echo 'PASS native lease final '.($revoke?'authority revocation':($backward?'clock reversal':'expiry')).': '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; no credential returned, finalized ledger retained, no continuation'.PHP_EOL;
}finally{$pdo=null;foreach(['files','scratch','witness'] as $name){cleanDirectory($directory.'/'.$name);}cleanDirectory($directory);}
