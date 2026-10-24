<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Support\SystemClock;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function durableContextControl(string $sql):string{$pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned control unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}return trim($out);}
class DurableContextAdapter extends PDO {}
class DurableContextStatement extends PDOStatement {}
class DurableContextFaultStatement extends PDOStatement {
 public static $mode='';
 private function selected():bool{return self::$mode!==''&&$this->queryString==='SELECT @@GLOBAL.innodb_flush_log_at_trx_commit';}
 public function fetchAll($mode=null,$className=null,$constructorArgs=null,...$extra):array{if($this->selected()&&self::$mode!=='close'){throw new RuntimeException('PRIVATE-DURABLE-READ');}return parent::fetchAll(...func_get_args());}
 public function closeCursor():bool{$closed=parent::closeCursor();return $this->selected()&&self::$mode!=='fetch'?false:$closed;}
}
$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$admin=new PDO($dsn,'sosecurity_test','integration-only',$options);$original=(int)durableContextControl('SELECT @@GLOBAL.innodb_flush_log_at_trx_commit');$created=[];$failures=[];$count=0;
try{
 durableContextControl('SET GLOBAL innodb_flush_log_at_trx_commit=1');
 foreach(explode(';',preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-mysql.sql'))) as $ddl){if(trim($ddl)!==''){$admin->exec($ddl);if(preg_match('/CREATE TABLE\s+(\w+)/i',$ddl,$m)){$created[]=$m[1];}}}
 foreach(['native','clock','pdo','statement','registered'] as $mode){
  $beforeFailures=count($failures);$directory=privateDirectory();$boundary=null;$pdo=$mode==='pdo'?new DurableContextAdapter($dsn,'sosecurity_test','integration-only',$options):new PDO($dsn,'sosecurity_test','integration-only',$options);if($mode==='statement'){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[DurableContextStatement::class]);}$clock=$mode==='clock'?new TestClock():new SystemClock();
  if($mode==='registered'){$pdo->exec('CREATE TABLE sosecurity_durable_context(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');mkdir($directory.'/witness',0700);$keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);$source=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-durable-source',['sosecurity_durable_context'=>['columns'=>['id'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>2]],10000);$witness=new SoSecurity\Account\LocalStateWitness($pdo,$directory.'/witness','owned-durable','tenant',str_repeat('e',64),$keys,$source,new SoSecurity\Account\LocalStatePersistence($directory.'/witness',10000),10000,2);$witness->initialize($source->digest());$boundary=new SoSecurity\Account\StateBoundary($witness,static function():bool{return true;});SqlStateAccess::bind($pdo,hash('sha256','owned-durable'),$boundary->binding(),$boundary->sqlGuard($pdo),$boundary);}
  $unit=new SqlTransaction($pdo,$clock,10000);$native=$unit->canBatchLedgerReads();$q=$pdo->query('SELECT CONNECTION_ID()');$thread=(int)$q->fetchColumn();$q->closeCursor();$observed=[];
  $body=static function()use($unit,$native,$mode,&$observed,&$failures):void{
   durableContextControl("SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");$one=$unit->verifyLedgerSchema();$two=$unit->verifyLedgerSchema();durableContextControl('SET GLOBAL general_log=OFF');Check::same($native?['database'=>'sosecurity_test']:null,$one);Check::same($one,$two);
   foreach([0,2] as $value){durableContextControl('SET GLOBAL innodb_flush_log_at_trx_commit='.$value);foreach(['ledger','context'] as $path){$reason=null;try{if($path==='ledger'){$unit->verifyLedgerSchema();}else{SqlSchema::ledgerSchemaContext($unit);}}catch(SoSecurity\Exception\ConfigurationException $e){$reason=$e->reason();}$observed[]=['value'=>$value,'path'=>$path,'reason'=>$reason];try{Check::same('configuration.sql_durability',$reason);}catch(Throwable $e){$failures[]=$mode.' '.$path.' '.$value;}}durableContextControl('SET GLOBAL innodb_flush_log_at_trx_commit=1');Check::same($native?['database'=>'sosecurity_test']:null,$unit->verifyLedgerSchema());}
   Check::same(['database'=>'sosecurity_test'],SqlSchema::ledgerSchemaContext($unit));
  };
  try{$run=static function()use($unit,$body):void{$unit->run($body);};if($boundary!==null){$boundary->run('owned.durable.context',$run);}else{$run();}
   $single=(int)durableContextControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$thread." AND command_type='Execute' AND argument='SELECT @@GLOBAL.innodb_flush_log_at_trx_commit'");echo 'OBSERVATION ledger durable context '.json_encode(['mode'=>$mode,'native'=>$native,'standalone_durable_executes'=>$single,'observed'=>$observed,'php'=>PHP_VERSION]).PHP_EOL;Check::same($native?0:2,$single);Check::same(false,$pdo->inTransaction());if(count($failures)===$beforeFailures){++$count;echo 'PASS durable context '.$mode.' PHP '.PHP_VERSION.PHP_EOL;}else{echo 'FAIL durable context '.$mode.' PHP '.PHP_VERSION.PHP_EOL;}
  }finally{durableContextControl('SET GLOBAL general_log=OFF; SET GLOBAL innodb_flush_log_at_trx_commit=1');if($pdo->inTransaction()){$pdo->rollBack();}if($mode==='registered'){$pdo->exec('DROP TABLE sosecurity_durable_context');}$unit=null;$boundary=null;if(is_dir($directory.'/witness')){cleanDirectory($directory.'/witness');}cleanDirectory($directory);}
 }
 $admin->exec('CREATE TABLE sosecurity_durable_effects(id INTEGER NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created[]='sosecurity_durable_effects';
 foreach(['fetch','close','fetch-close'] as $mode){$pdo=new PDO($dsn,'sosecurity_test','integration-only',$options);$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[DurableContextFaultStatement::class]);$unit=new SqlTransaction($pdo,new SystemClock(),10000);$inner=null;$outer=null;$returned=false;DurableContextFaultStatement::$mode=$mode;
  try{$unit->run(static function()use($unit,&$inner):void{try{SqlSchema::ledgerSchemaContext($unit);}catch(Throwable $e){$inner=$e;}DurableContextFaultStatement::$mode='';$unit->query('INSERT INTO sosecurity_durable_effects VALUES(1)')->closeCursor();});$returned=true;}catch(Throwable $e){$outer=$e;}
  DurableContextFaultStatement::$mode='';$visible=(int)$admin->query('SELECT COUNT(*) FROM sosecurity_durable_effects')->fetchColumn();$reason=$inner instanceof SoSecurity\Exception\SecurityException||$inner instanceof SoSecurity\Exception\ConfigurationException?$inner->reason():null;Check::same($mode==='fetch',$returned);Check::same($mode==='fetch'?1:0,$visible);Check::same($mode==='fetch'?'sql.unavailable':'sql.cleanup',$reason);Check::same(false,strpos((string)$inner.(string)$outer,'PRIVATE-DURABLE-')!==false);Check::same(false,$pdo->inTransaction());if($mode!=='fetch'){Check::throws(SoSecurity\Storage\StorageException::class,static function()use($unit):void{$unit->run(static function():void{});});}$admin->exec('DELETE FROM sosecurity_durable_effects');++$count;echo 'PASS durable context error '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
 }
}finally{durableContextControl('SET GLOBAL general_log=OFF; SET GLOBAL innodb_flush_log_at_trx_commit='.$original);foreach(array_reverse($created) as $table){$admin->exec('DROP TABLE '.$table);}}
if($failures){throw new RuntimeException('Durable context cases failed: '.implode(', ',$failures));}
echo 'PASS durable context complete '.$count.' profiles '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
