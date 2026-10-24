<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Storage\StorageException;
class MetadataTimeoutStatement extends PDOStatement {
 public static $mode='normal';public static $closed=0;
 private function target():bool{return in_array($this->queryString,['SELECT @@SESSION.lock_wait_timeout'],true);}
 public function closeCursor():bool{
  $closed=parent::closeCursor();if(!$this->target()){return $closed;}++self::$closed;
  if(self::$mode==='close-throw'){throw new RuntimeException('PRIVATE-TIMEOUT-CURSOR');}
  return self::$mode==='close-false'?false:$closed;
 }
 public function fetchAll($mode=null,$className=null,$constructorArgs=null,...$extra):array{
  $rows=parent::fetchAll(...func_get_args());if(!$this->target()){return $rows;}
  if(self::$mode==='fetch-throw'){throw new RuntimeException('PRIVATE-TIMEOUT-FETCH');}
  if(self::$mode==='empty'){return [];}
  if(self::$mode==='extra-row'){return array_merge($rows,$rows);}
  if(self::$mode==='extra-column'){$rows[0]['unexpected']=1;}
  if(self::$mode==='zero'){$rows[0][array_keys($rows[0])[0]]='0';}
  if(self::$mode==='overflow'){$rows[0][array_keys($rows[0])[0]]='31536001';}
  if(self::$mode==='invalid'){$rows[0][array_keys($rows[0])[0]]='-1';}
  return $rows;
 }
}
$backend=$argv[1]??'sqlite';$mysql=$backend==='mysql';if(!in_array($backend,['sqlite','mysql'],true)){throw new RuntimeException('Use an owned backend');}
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned MySQL required');}
if(!$mysql){throw new RuntimeException('MySQL only');}
$modes=['normal','close-false','close-throw','fetch-throw','empty','extra-row','extra-column','invalid','zero','overflow'];
foreach($modes as $mode){foreach(['run','enlist','readIn'] as $method){
 if(isset($argv[2])&&$argv[2]!==$mode){continue;}if(isset($argv[3])&&$argv[3]!==$method){continue;}
 $directory=privateDirectory();$pdo=null;$body=0;$reason=null;$unit=null;$host=false;
 try{
  $pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test':'sqlite:'.$directory.'/owned.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
  $read=static function()use($pdo,$mysql):int{$q=$pdo->query($mysql?'SELECT @@SESSION.lock_wait_timeout':'PRAGMA busy_timeout');$v=(int)$q->fetchColumn();$q->closeCursor();return $v;};
  $pdo->exec($mysql?'SET SESSION innodb_lock_wait_timeout=19,lock_wait_timeout=19':'PRAGMA busy_timeout=19000');$original=$read();
  SqlStateAccess::bind($pdo,hash('sha256','owned-lock-timeout:'.$mode.':'.$method),hash('sha256','owned-lock-timeout-binding:'.$mode.':'.$method),static function():void{});
  $pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[MetadataTimeoutStatement::class]);MetadataTimeoutStatement::$mode='normal';MetadataTimeoutStatement::$closed=0;
  $unit=new SqlTransaction($pdo,new TestClock(),10000);
  $operation=static function()use(&$body,$read,$original):int{++$body;Check::same(true,$read()<$original);return 17;};
  try{
   if($method==='readIn'){$owner=new SqlTransaction($pdo,new TestClock(),10000);$result=$owner->run(static function()use($unit,$owner,$operation,$mode){MetadataTimeoutStatement::$mode=$mode;return $unit->readIn($owner,$operation);});}
   else{if($method==='enlist'){$pdo->beginTransaction();$host=true;}MetadataTimeoutStatement::$mode=$mode;$result=$unit->$method($operation);}
  }catch(SoSecurity\Exception\SecurityException|SoSecurity\Exception\ConfigurationException $error){$reason=$error->reason();Check::same(false,strpos((string)$error,'PRIVATE-TIMEOUT-')!==false);}
  echo 'OBSERVATION lock timeout '.json_encode(['backend'=>$backend,'mode'=>$mode,'method'=>$method,'body'=>$body,'reason'=>$reason,'explicit_closes'=>MetadataTimeoutStatement::$closed]).PHP_EOL;
  if($mode==='normal'){Check::same(null,$reason);Check::same(1,$body);Check::same(17,$result);Check::same(true,MetadataTimeoutStatement::$closed>0);}
  else{Check::same(0,$body);Check::same(in_array($mode,['close-false','close-throw'],true)?'sql.cleanup':($mode==='fetch-throw'?'sql.unavailable':'sql.corrupt'),$reason);Check::same(true,MetadataTimeoutStatement::$closed>0);}
  MetadataTimeoutStatement::$mode='normal';
  if(in_array($mode,['close-false','close-throw'],true)){Check::throws(StorageException::class,static function()use($unit):void{$unit->run(static function():void{});});}
  else{Check::same($original,$read());if($host){Check::same(true,$pdo->inTransaction());$pdo->rollBack();$host=false;}Check::same(23,$unit->run(static function():int{return 23;}));Check::same($original,$read());}
  echo 'PASS SQL metadata timeout '.$mode.' '.$method.' '.$backend.' PHP '.PHP_VERSION.PHP_EOL;
 }finally{
  MetadataTimeoutStatement::$mode='normal';if($pdo instanceof PDO){try{if($pdo->inTransaction()){$pdo->rollBack();}}catch(Throwable $cleanup){}}
  $pdo=null;$unit=null;gc_collect_cycles();cleanDirectory($directory);
 }
}}
