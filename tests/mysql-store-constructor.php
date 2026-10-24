<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Storage\MySqlStore;
use SoSecurity\Storage\StorageException;
final class ConstructorPolicyConnection extends PDO {
 public static $armed=false;public static $mode;public static $sets=0;public static $closes=0;public static $changed=false;
 #[\ReturnTypeWillChange]
 public function exec($sql){
  if(self::$armed&&strpos($sql,'SET SESSION lock_wait_timeout = ')===0){
   ++self::$sets;$entry=strpos(self::$mode,'entry-')===0;$restore=strpos(self::$mode,'restore-')===0;
   if(($entry&&self::$sets===1)||($restore&&self::$sets===2)){
    if(strpos(self::$mode,'changed')!==false){parent::exec($sql);}
    if(strpos(self::$mode,'throw')!==false){throw new RuntimeException('PRIVATE-CONSTRUCTOR-SET');}return false;
   }
  }return parent::exec($sql);
 }
}
final class ConstructorPolicyStatement extends PDOStatement {
 private $connection;
 protected function __construct(ConstructorPolicyConnection $connection){$this->connection=$connection;}
 private function target():bool{return ConstructorPolicyConnection::$armed&&$this->queryString==='SELECT @@SESSION.lock_wait_timeout';}
 public function execute($params=null):bool{
  $r=$params===null?parent::execute():parent::execute($params);
  if(ConstructorPolicyConnection::$armed&&ConstructorPolicyConnection::$mode==='policy-change'&&!ConstructorPolicyConnection::$changed&&strpos($this->queryString,'information_schema.COLUMNS')!==false){ConstructorPolicyConnection::$changed=true;$this->connection->exec('SET SESSION lock_wait_timeout = 9');}
  return $r;
 }
 public function closeCursor():bool{$r=parent::closeCursor();if(!$this->target()){return $r;}++ConstructorPolicyConnection::$closes;if(ConstructorPolicyConnection::$mode==='close-throw'){throw new RuntimeException('PRIVATE-CONSTRUCTOR-CLOSE');}return ConstructorPolicyConnection::$mode==='close-false'?false:$r;}
 public function fetchAll($mode=null,$className=null,$constructorArgs=null,...$extra):array{
  $r=parent::fetchAll(...func_get_args());if(!$this->target()){return $r;}
  if(ConstructorPolicyConnection::$mode==='fetch-throw'){throw new RuntimeException('PRIVATE-CONSTRUCTOR-FETCH');}
  if(ConstructorPolicyConnection::$mode==='zero'){$r[0][0]='0';}return $r;
 }
}
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$modes=['normal','short-policy','locked','schema-bad','entry-false','entry-throw','entry-changed-false','restore-false','restore-throw','fetch-throw','close-false','close-throw','policy-change','zero'];
foreach(['idle','pdo-host','sql-host'] as $context){foreach($modes as $mode){
 if(isset($argv[1])&&$context!==$argv[1]){continue;}if(isset($argv[2])&&$mode!==$argv[2]){continue;}
 $dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$pdo=new ConstructorPolicyConnection($dsn,'sosecurity_test','integration-only',$options);$other=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=false;$marker=false;$host=false;$locked=false;$reason=null;$service=null;
 try{
  ConstructorPolicyConnection::$armed=false;$pdo->exec(MySqlStore::schema());$created=true;$pdo->exec('CREATE TABLE sosecurity_constructor_host(id INT NOT NULL PRIMARY KEY) ENGINE=InnoDB');$marker=true;
  if($mode==='schema-bad'){$pdo->exec('ALTER TABLE sosecurity_state ADD UNIQUE KEY owned_constructor_extra(namespace_hash)');}
  $original=$mode==='short-policy'?1:23;$pdo->exec('SET SESSION innodb_lock_wait_timeout=19,lock_wait_timeout='.$original);
  if($context!=='idle'){if($context==='pdo-host'){$pdo->beginTransaction();}else{$pdo->exec('START TRANSACTION');}$host=true;$pdo->exec('INSERT INTO sosecurity_constructor_host VALUES(1)');}
  if($mode==='locked'){$other->exec('LOCK TABLES sosecurity_state WRITE');$locked=true;}
  $pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[ConstructorPolicyStatement::class,[$pdo]]);ConstructorPolicyConnection::$mode=$mode;ConstructorPolicyConnection::$sets=0;ConstructorPolicyConnection::$closes=0;ConstructorPolicyConnection::$changed=false;ConstructorPolicyConnection::$armed=true;$start=microtime(true);
  try{$service=new MySqlStore($pdo,'owned-constructor',null,1);}catch(SoSecurity\Exception\SecurityException|SoSecurity\Exception\ConfigurationException $error){$reason=$error->reason();$chain=$error;$depth=0;while($chain!==null){Check::same(false,strpos($chain->getMessage(),'PRIVATE-')!==false);Check::same(true,++$depth<=4);$chain=$chain->getPrevious();}}
  $seconds=microtime(true)-$start;ConstructorPolicyConnection::$armed=false;if($locked){$other->exec('UNLOCK TABLES');$locked=false;}
  if(in_array($mode,['normal','short-policy','policy-change'],true)){Check::same(null,$reason);Check::same(true,$service instanceof MySqlStore);}
  elseif($mode==='schema-bad'){Check::same('configuration.schema',$reason);}
  elseif($mode==='zero'){Check::same('storage.corrupt',$reason);}
  elseif(in_array($mode,['close-false','close-throw','restore-false','restore-throw'],true)){Check::same('storage.cleanup',$reason);}
  else{Check::same('storage.schema',$reason);}
  Check::same(1,ConstructorPolicyConnection::$closes);
  if($mode==='locked'){Check::same(true,$seconds>=0.8&&$seconds<2.5);}
  if($mode==='policy-change'){Check::same(true,ConstructorPolicyConnection::$changed);}
  $q=$pdo->query('SELECT @@SESSION.lock_wait_timeout,@@SESSION.innodb_lock_wait_timeout');$policy=array_map('intval',$q->fetch(PDO::FETCH_NUM));$q->closeCursor();Check::same([in_array($mode,['restore-false','restore-throw'],true)?1:$original,19],$policy);
  $q=$other->query('SELECT COUNT(*) FROM sosecurity_constructor_host');$diagnosticRemote=(int)$q->fetchColumn();$q->closeCursor();$q=$pdo->query('SELECT COUNT(*) FROM sosecurity_constructor_host');$diagnosticLocal=(int)$q->fetchColumn();$q->closeCursor();$engineActive=SoSecurity\Support\SqlTransactionGuard::active($pdo,'mysql',new SoSecurity\Support\Deadline(5000));echo 'OBSERVATION constructor host '.json_encode(['context'=>$context,'mode'=>$mode,'pdo_active'=>$pdo->inTransaction(),'engine_active'=>$engineActive,'local_rows'=>$diagnosticLocal,'observer_rows'=>$diagnosticRemote]).PHP_EOL;
  Check::same($host,$engineActive);$q=$other->query('SELECT COUNT(*) FROM sosecurity_constructor_host');$visible=(int)$q->fetchColumn();$q->closeCursor();Check::same(0,$visible);
  $q=$pdo->query('SELECT COUNT(*) FROM sosecurity_constructor_host');$local=(int)$q->fetchColumn();$q->closeCursor();Check::same($host?1:0,$local);
  if($host){$pdo->exec('ROLLBACK');$host=false;$q=$other->query('SELECT COUNT(*) FROM sosecurity_constructor_host');Check::same(0,(int)$q->fetchColumn());$q->closeCursor();}
  echo 'PASS MySQL constructor policy '.json_encode(['context'=>$context,'mode'=>$mode,'reason'=>$reason,'seconds'=>$seconds,'php'=>PHP_VERSION]).PHP_EOL;
 }finally{ConstructorPolicyConnection::$armed=false;if($locked){$other->exec('UNLOCK TABLES');}if($host){$pdo->exec('ROLLBACK');}if($created){$pdo->exec('DROP TABLE sosecurity_state');}if($marker){$pdo->exec('DROP TABLE sosecurity_constructor_host');}}
}}
