<?php
declare(strict_types=1);
require dirname(__DIR__).'/bootstrap.php';
use SoSecurity\Account as A;
final class ProofReturnClock implements SoSecurity\Support\Clock {public $time=100000;public function now():int{return $this->time;}}
function proofReturn(string $kind,string $mode):void
{
 $directory=privateDirectory();$pdo=null;
 try{
  foreach(['files','scratch','witness'] as $name){mkdir($directory.'/'.$name,0700);}
  $mysql=($GLOBALS['argv'][3]??'')==='mysql';$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
  if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned private MySQL required.');}
  $pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$directory.'/proof.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);if(!$mysql){$pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');}
  $clock=new ProofReturnClock();$files=new A\FileStateSnapshot($pdo,'proof-return-files',$directory.'/files',$directory.'/scratch',8,30000);$source=new A\CompositeStateSnapshot($pdo,['files'=>$files],30000);$keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);$epoch=str_repeat('e',64);
  $witness=new A\LocalStateWitness($pdo,$directory.'/witness','proof-site','tenant',$epoch,$keys,$source,new A\LocalStatePersistence($directory.'/witness',30000),30000,2);$witness->initialize($source->digest());$late=false;$allowed=true;$guardCalls=0;
  $boundary=new A\StateBoundary($witness,static function(string $phase)use(&$late,$clock,$mode,&$allowed):bool{if($late&&$phase==='final'){
   if($mode==='issue-expiry'||$mode==='verify-expiry'){$clock->time+=31;}elseif($mode==='issue-backward'){--$clock->time;}elseif($mode==='issue-budget'){usleep(300000);}else{$allowed=false;}
  }return true;});
  $store=new SoSecurity\Storage\FileStore($directory.'/files','proof-site:tokens',$clock);
  $connection=new A\StateProofConnection($boundary,$witness,$source,$files,'files',$store,'proof-site','tenant',$epoch,$clock,static function()use(&$allowed,&$guardCalls,&$late,$mode){++$guardCalls;$result=$allowed?'owned-browser':null;if($late&&$mode==='readonly-authority'&&$guardCalls===2){$allowed=false;}return $result;},$mode==='issue-budget'?200:30000);
  $csrf=new SoSecurity\Csrf\CsrfTokens($store,30,16,$clock,$connection);$captcha=new SoSecurity\Captcha\Captcha($store,30,3,16,$clock,$connection);
  $issue=static function()use($kind,$csrf,$captcha){return $kind==='csrf'?$csrf->issue('form','browser'):$captcha->arithmetic('form','browser');};
  $issued=null;$answer='';if(strpos($mode,'issue-')!==0){$issued=$issue();if($kind==='captcha'){preg_match('/^(\d+) \+ (\d+)/',$issued->prompt,$parts);$answer=(string)($parts[1]+$parts[2]);}}
  $before=$witness->inspect(static function():bool{return true;});$late=true;$guardCalls=0;
  if(strpos($mode,'issue-')===0){
   $expected=['issue-expiry'=>'proof.expired','issue-backward'=>'proof.clock','issue-budget'=>'proof.timeout','issue-authority'=>'proof.denied'][$mode];
   try{$issue();throw new RuntimeException('Invalid proof returned after witness completion');}catch(SoSecurity\Exception\SecurityException $error){Check::same($expected,$error->reason());}
  }elseif($mode==='revoke-authority'){
   try{if($kind==='csrf'){$csrf->revoke('form','browser');}else{$captcha->revoke('form','browser');}throw new RuntimeException('Revocation reported success after authority loss');}catch(SoSecurity\Exception\SecurityException $error){Check::same('proof.denied',$error->reason());}
  }else{
   $verified=$kind==='csrf'?$csrf->verify('form','browser',$issued,$mode!=='readonly-authority'):$captcha->verify('form','browser',$issued->id,$answer);Check::same(false,$verified);
  }
  $state=$witness->inspect(static function():bool{return true;});Check::same('current',$state['status']);Check::same($source->digest(),$state['digest']);
  if($mode==='readonly-authority'){Check::same($before,$state);}
  $key=SoSecurity\Support\Guard::key($kind,'form','browser');$path=$directory.'/files/'.$store->snapshotFile($key);$raw=is_file($path)?file_get_contents($path):null;$entries=$raw===null?null:SoSecurity\Storage\Codec::decode($raw,0);
  Check::same(strpos($mode,'issue-')===0||$mode==='readonly-authority'?1:0,count($entries??[]));
  echo 'PASS proof return '.$kind.' '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
 }finally{$pdo=null;foreach(['files','scratch','witness'] as $name){cleanDirectory($directory.'/'.$name);}cleanDirectory($directory);}
}
$kinds=isset($argv[1])&&$argv[1]!=='all'?[$argv[1]]:['csrf','captcha'];$modes=isset($argv[2])&&$argv[2]!=='all'?[$argv[2]]:['issue-expiry','issue-backward','issue-budget','issue-authority','verify-authority','verify-expiry','revoke-authority','readonly-authority'];
foreach($kinds as $kind){foreach($modes as $mode){if($kind==='captcha'&&$mode==='readonly-authority'){continue;}proofReturn($kind,$mode);}}
