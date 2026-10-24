<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Storage\MySqlStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
final class StorePolicyConnection extends PDO {
 public static $armed=false;public static $mode;public static $sets=0;public static $closes=0;
 #[\ReturnTypeWillChange]
 public function exec($sql){
  if(self::$armed&&strpos($sql,'SET SESSION lock_wait_timeout = ')===0){
   ++self::$sets;$entry=strpos(self::$mode,'entry-')===0;$restore=strpos(self::$mode,'restore-')===0;
   if(($entry&&self::$sets===1)||($restore&&self::$sets===2)){
    if(strpos(self::$mode,'changed')!==false){parent::exec($sql);}
    if(strpos(self::$mode,'throw')!==false){throw new RuntimeException('PRIVATE-STORE-POLICY');}return false;
   }
  }return parent::exec($sql);
 }
}
final class StorePolicyStatement extends PDOStatement {
 private function target():bool{return StorePolicyConnection::$armed&&$this->queryString==='SELECT @@SESSION.lock_wait_timeout';}
 public function closeCursor():bool{
  $result=parent::closeCursor();if(!$this->target()){return $result;}++StorePolicyConnection::$closes;
  if(StorePolicyConnection::$mode==='close-throw'){throw new RuntimeException('PRIVATE-STORE-CURSOR');}
  return StorePolicyConnection::$mode==='close-false'?false:$result;
 }
 public function execute($parameters=null):bool{
  $result=$parameters===null?parent::execute():parent::execute($parameters);if(!$this->target()){return $result;}
  if(StorePolicyConnection::$mode==='execute-throw'){throw new RuntimeException('PRIVATE-STORE-EXECUTE');}
  return StorePolicyConnection::$mode==='execute-false'?false:$result;
 }
 public function fetchAll($mode=null,$className=null,$constructorArgs=null,...$extra):array{
  $rows=parent::fetchAll(...func_get_args());if(!$this->target()){return $rows;}$fault=StorePolicyConnection::$mode;
  if($fault==='fetch-throw'){throw new RuntimeException('PRIVATE-STORE-FETCH');}
  if($fault==='empty'){return [];}
  if($fault==='extra-row'){return array_merge($rows,$rows);}
  if($fault==='extra-column'){$rows[0][]=1;}
  if($fault==='invalid'){$rows[0][0]='-1';}
  if($fault==='zero'){$rows[0][0]='0';}
  if($fault==='overflow'){$rows[0][0]='31536001';}
  return $rows;
 }
}
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$modes=['execute-false','execute-throw','normal','locked','policy-change','short-policy','callback-error','empty','extra-row','extra-column','invalid','zero','overflow','fetch-throw','close-false','close-throw','entry-false','entry-throw','entry-changed-false','restore-false','restore-throw'];
foreach(['transact','prune'] as $method){foreach($modes as $mode){
 if(isset($argv[1])&&$mode!==$argv[1]){continue;}
 if(isset($argv[2])&&$method!==$argv[2]){continue;}
 if($method==='prune'&&in_array($mode,['policy-change','callback-error'],true)){continue;}
 $dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$pdo=new StorePolicyConnection($dsn,'sosecurity_test','integration-only',$options);$other=new PDO($dsn,'sosecurity_test','integration-only',$options);$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[StorePolicyStatement::class]);$created=false;$locked=false;$body=0;$reason=null;$result=null;
 try{
  StorePolicyConnection::$armed=false;MySqlStore::install($pdo);$created=true;$store=new MySqlStore($pdo,'owned-session-policy');$pdo->exec('SET SESSION innodb_lock_wait_timeout=19,lock_wait_timeout='.($mode==='short-policy'?1:23));
  $read=static function()use($pdo):array{$q=$pdo->query('SELECT @@SESSION.innodb_lock_wait_timeout,@@SESSION.lock_wait_timeout');try{return array_map('intval',$q->fetch(PDO::FETCH_NUM));}finally{$q->closeCursor();}};
  if($mode==='locked'){$other->exec('LOCK TABLES sosecurity_state WRITE');$locked=true;}
  StorePolicyConnection::$armed=true;StorePolicyConnection::$mode=$mode;StorePolicyConnection::$sets=0;StorePolicyConnection::$closes=0;$start=microtime(true);
  try{
   if($method==='prune'){$result=$store->prune(1);}
   else{$result=$store->transact('owned-key',static function()use(&$body,$read,$mode,$pdo){++$body;Check::same([1,1],$read());if($mode==='callback-error'){throw new StorageException('Expected callback refusal.','test.denied');}if($mode==='policy-change'){$pdo->exec('SET SESSION innodb_lock_wait_timeout=7,lock_wait_timeout=9');}return new Change(['owned'=>true],0,17);});}
  }catch(SoSecurity\Exception\SecurityException $error){$reason=$error->reason();$chain=$error;$depth=0;while($chain!==null){Check::same(true,$chain instanceof StorageException);Check::same(false,strpos($chain->getMessage(),'PRIVATE-')!==false);Check::same(true,++$depth<=4);$chain=$chain->getPrevious();}}
  $seconds=microtime(true)-$start;StorePolicyConnection::$armed=false;if($locked){$other->exec('UNLOCK TABLES');$locked=false;}
  $poison=in_array($mode,['close-false','close-throw','restore-false','restore-throw'],true);
  if($poison){Check::same('storage.cleanup',$reason);Check::throws(StorageException::class,static function()use($store):void{$store->prune(1);});}
  elseif(in_array($mode,['normal','policy-change','short-policy'],true)){Check::same(null,$reason);Check::same($method==='transact'?17:0,$result);}
  elseif($mode==='callback-error'){Check::same('test.denied',$reason);}
  elseif(in_array($mode,['empty','extra-row','extra-column','invalid','zero','overflow'],true)){Check::same('storage.corrupt',$reason);}
  else{Check::same('storage.database',$reason);}
  if(!$poison){Check::same([19,$mode==='short-policy'?1:23],$read());Check::same(0,$store->prune(1));}
  Check::same(true,StorePolicyConnection::$closes>0);Check::same(false,$pdo->inTransaction());
  if($mode==='locked'){Check::same(0,$body);Check::same(true,$seconds>=0.8&&$seconds<2.5);}
  if($method==='transact'&&!in_array($mode,['normal','policy-change','short-policy','callback-error','restore-false','restore-throw'],true)){Check::same(0,$body);}
  echo 'PASS MySQL store session policy '.json_encode(['method'=>$method,'mode'=>$mode,'seconds'=>$seconds,'reason'=>$reason,'php'=>PHP_VERSION]).PHP_EOL;
 }finally{StorePolicyConnection::$armed=false;if($locked){$other->exec('UNLOCK TABLES');}if($pdo->inTransaction()){$pdo->rollBack();}if($created){$pdo->exec('DROP TABLE sosecurity_state');}}
}}
