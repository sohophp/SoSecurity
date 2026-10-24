<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlTransactionGuard;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Support\SystemClock;
use SoSecurity\Support\Deadline;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;

$mysql=($argv[1]??'sqlite')==='mysql';$directory=$mysql?null:privateDirectory();
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';}else{$dsn='sqlite:'.$directory.'/owner.sqlite';}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}
$connect=static function()use($dsn,$mysql,$options):PDO{return new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);};
$admin=$connect();if(!$mysql){$admin->exec('PRAGMA journal_mode=DELETE');$admin->exec('PRAGMA synchronous=FULL');}
$witness=new ReflectionProperty(SqlTransaction::class,'witness');if(PHP_VERSION_ID<80100){$witness->setAccessible(true);}$failures=[];$created=false;$count=0;
$active=static function(PDO $pdo)use($mysql):bool{return SqlTransactionGuard::active($pdo,$mysql?'mysql':'sqlite',new Deadline(10000));};
$reason=static function($error):?string{return $error instanceof SecurityException||$error instanceof ConfigurationException?$error->reason():null;};
try{
 $admin->exec('CREATE TABLE sosecurity_read_owner(id INTEGER NOT NULL PRIMARY KEY)'.($mysql?' ENGINE=InnoDB':''));$created=true;
 foreach(['normal','entry-commit','entry-replace','return-commit','return-replace','ordinary-error','entry-error','post-timeout','owner-guard-error','owner-guard-lost-error'] as $mode){
  $pdo=$connect();$owner=new SqlTransaction($pdo,new SystemClock(),10000);$child=new SqlTransaction($pdo,new SystemClock(),$mode==='post-timeout'?1000:10000);$armed=false;$returning=false;$injected=false;$body=0;$returned=false;$after=false;$inner=null;$outer=null;$parentReturned=false;
  SqlStateAccess::bind($pdo,hash('sha256','owned-read-owner-'.$mode),hash('sha256','owned-read-owner-binding-'.$mode),static function()use($pdo,$child,$owner,$mode,$mysql,$witness,&$armed,&$returning,&$injected):void{
   if(!$armed||$injected||in_array($mode,['normal','ordinary-error'],true)){return;}
   $childNow=false;$ownerWitness=false;$ownerNow=false;foreach(debug_backtrace(DEBUG_BACKTRACE_PROVIDE_OBJECT|DEBUG_BACKTRACE_IGNORE_ARGS) as $frame){if(($frame['object']??null)===$child&&($frame['function']??null)==='now'){$childNow=true;}if(($frame['object']??null)===$owner&&($frame['function']??null)==='witness'){$ownerWitness=true;}if(($frame['object']??null)===$owner&&($frame['function']??null)==='now'){$ownerNow=true;}}
   if(strpos($mode,'owner-guard-')===0){if($returning&&$ownerNow&&!$ownerWitness){$injected=true;if($mode==='owner-guard-lost-error'){$pdo->exec('COMMIT');}throw new RuntimeException('PRIVATE-READ-OWNER-GUARD');}return;}
   if($mode==='post-timeout'){if($returning&&$ownerWitness){$injected=true;usleep(1100000);}return;}
   if(!$childNow){return;}$entry=strpos($mode,'entry-')===0;if(!$entry&&(!$returning||$witness->getValue($child)!==null)){return;}
   $injected=true;$pdo->exec('COMMIT');if(strpos($mode,'replace')!==false){if($mysql){$pdo->beginTransaction();}else{$pdo->exec('BEGIN IMMEDIATE');}}
  });
  try{$owner->run(static function()use($owner,$child,$mode,&$armed,&$returning,&$body,&$returned,&$after,&$inner):void{
   $armed=true;
   try{$child->readIn($owner,static function()use($child,$mode,&$returning,&$body):int{++$body;$child->metadataRows('SELECT COUNT(*) AS n FROM sosecurity_read_owner');if(in_array($mode,['ordinary-error','entry-error'],true)){throw new StorageException('Ordinary owned refusal.','test.refused');}$returning=true;return 17;});$returned=true;}catch(Throwable $e){$inner=$e;}
   $owner->query('INSERT INTO sosecurity_read_owner VALUES('.($mode==='normal'?1:(in_array($mode,['ordinary-error','post-timeout','owner-guard-error'],true)?3:9)).')')->closeCursor();$after=true;
  });$parentReturned=true;}catch(Throwable $e){$outer=$e;}
  $armed=false;$ids=array_map('intval',$admin->query('SELECT id FROM sosecurity_read_owner ORDER BY id')->fetchAll(PDO::FETCH_COLUMN));$leftActive=$active($pdo);$fault=!in_array($mode,['normal','ordinary-error','post-timeout','owner-guard-error'],true);
  echo 'OBSERVATION read owner '.json_encode(['mode'=>$mode,'injected'=>$injected,'body'=>$body,'returned'=>$returned,'after'=>$after,'parent_returned'=>$parentReturned,'ids'=>$ids,'inner'=>$reason($inner),'outer'=>$reason($outer),'left_active'=>$leftActive,'private_detail'=>strpos((string)$inner.(string)$outer,'PRIVATE-READ-OWNER-GUARD')!==false]).PHP_EOL;
  try{Check::same(false,strpos((string)$inner.(string)$outer,'PRIVATE-READ-OWNER-GUARD')!==false);Check::same($fault||in_array($mode,['post-timeout','owner-guard-error'],true),$injected);Check::same(!$fault,$parentReturned);Check::same(!$fault,$after);Check::same($mode==='normal',$returned);Check::same($fault?[]:[$mode==='normal'?1:3],$ids);if($fault){Check::same(true,$inner instanceof SecurityException||$inner instanceof ConfigurationException);Check::same(true,$outer instanceof SecurityException||$outer instanceof ConfigurationException);foreach([$owner,$child] as $failed){Check::throws(StorageException::class,static function()use($failed):void{$failed->run(static function():void{});});}}else{Check::same($mode==='ordinary-error'?'test.refused':($mode==='post-timeout'?'sql.timeout':($mode==='owner-guard-error'?'sql.unavailable':null)),$reason($inner));Check::same(null,$outer);Check::same(false,$leftActive);}++$count;echo 'PASS exact read owner '.($mysql?'mysql':'sqlite').' '.$mode.' PHP '.PHP_VERSION.PHP_EOL;}catch(Throwable $e){$failures[]=$mode;echo 'FAIL exact read owner '.$mode.' '.$e->getMessage().PHP_EOL;}
  // A replacement transaction belongs only to this test; the SDK must not commit it.
  if($leftActive){$pdo->exec('ROLLBACK');}$admin->exec('DELETE FROM sosecurity_read_owner');
 }
}finally{if(isset($pdo)&&$active($pdo)){$pdo->exec('ROLLBACK');}if($created){$admin->exec('DROP TABLE sosecurity_read_owner');}if($directory!==null){$owner=null;$child=null;$pdo=null;$admin=null;cleanDirectory($directory);}}
if($failures){throw new RuntimeException('Exact owner read cases failed: '.implode(', ',$failures));}
echo 'PASS exact read owner complete '.$count.' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
