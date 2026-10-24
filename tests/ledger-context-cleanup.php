<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Storage\StorageException;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
final class ContextCleanupStatement extends PDOStatement {
 public static $fault='';
 private function selected():bool{return self::$fault!==''&&(strpos(self::$fault,'resolution-')===0?strpos($this->queryString,'SELECT 1 FROM `sosecurity_account_roots` AS _sosecurity_left_0')===0:strpos($this->queryString,'SELECT 0 AS position,')===0);}
 public function fetchAll($mode=null,$className=null,$constructorArgs=null,...$extra):array{if($this->selected()&&self::$fault==='context-fetch-close'){throw new RuntimeException('PRIVATE-CONTEXT-FETCH');}return parent::fetchAll(...func_get_args());}
 public function closeCursor():bool{$closed=parent::closeCursor();if(!$this->selected()){return $closed;}if(strpos(self::$fault,'throw')!==false){throw new RuntimeException('PRIVATE-CONTEXT-CLOSE');}return false;}
}
$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$admin=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=[];$failures=[];$rows=[];
try{
 foreach(explode(';',preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-mysql.sql'))) as $ddl){if(trim($ddl)!==''){$admin->exec($ddl);if(preg_match('/CREATE TABLE\s+(\w+)/i',$ddl,$m)){$created[]=$m[1];}}}
 $admin->exec('CREATE TABLE sosecurity_context_cleanup(id BIGINT NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created[]='sosecurity_context_cleanup';
 foreach(['owned','host','borrowed'] as $ownership){foreach(['resolution-false','resolution-throw','context-false','context-throw','context-fetch-close'] as $mode){
  $pdo=new PDO($dsn,'sosecurity_test','integration-only',$options);$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[ContextCleanupStatement::class]);if(($argv[1]??'')==='protected'){SoSecurity\Support\SqlStateAccess::bind($pdo,hash('sha256','owned-context-cleanup-'.count($rows)),hash('sha256','owned-context-binding-'.count($rows)),static function():void{});}$unit=new SqlTransaction($pdo,new SoSecurity\Support\SystemClock(),10000);$owner=$ownership==='borrowed'?new SqlTransaction($pdo,new SoSecurity\Support\SystemClock(),10000):null;$inner=null;$outer=null;$returned=false;$id=count($rows)+1;ContextCleanupStatement::$fault=$mode;
  $body=static function()use($unit,$id,&$inner):void{try{SqlSchema::ledgerSchemaContext($unit);}catch(Throwable $e){$inner=$e;}ContextCleanupStatement::$fault='';$unit->query('INSERT INTO sosecurity_context_cleanup VALUES(:id)',['id'=>$id])->closeCursor();};
  try{if($ownership==='host'){$pdo->beginTransaction();$unit->enlist($body);}elseif($ownership==='borrowed'){$owner->run(static function()use($unit,$owner,$body,&$outer):void{try{$unit->readIn($owner,$body);}catch(Throwable $e){$outer=$e;}$owner->query('INSERT INTO sosecurity_context_cleanup VALUES(1000)')->closeCursor();});}else{$unit->run($body);}$returned=true;}catch(Throwable $e){$outer=$e;}
  $visible=(int)$admin->query('SELECT COUNT(*) FROM sosecurity_context_cleanup')->fetchColumn();$hostActive=$pdo->inTransaction();$observed=['ownership'=>$ownership,'mode'=>$mode,'returned'=>$returned,'visible'=>$visible,'inner_reason'=>$inner instanceof SoSecurity\Exception\SecurityException||$inner instanceof SoSecurity\Exception\ConfigurationException?$inner->reason():null,'outer_reason'=>$outer instanceof SoSecurity\Exception\SecurityException||$outer instanceof SoSecurity\Exception\ConfigurationException?$outer->reason():null,'private_detail'=>strpos((string)$inner.(string)$outer,'PRIVATE-CONTEXT-')!==false,'host_active'=>$hostActive];$rows[]=$observed;echo 'OBSERVATION cleanup '.json_encode($observed).PHP_EOL;
  try{Check::same(false,$returned);Check::same(0,$visible);Check::same('sql.cleanup',$observed['inner_reason']);Check::same(false,$observed['private_detail']);Check::same($ownership==='host',$hostActive);Check::same(true,$outer instanceof SoSecurity\Exception\SecurityException||$outer instanceof SoSecurity\Exception\ConfigurationException);ContextCleanupStatement::$fault='';Check::throws(StorageException::class,static function()use($unit):void{$unit->run(static function():void{});});if($owner!==null){Check::throws(StorageException::class,static function()use($owner):void{$owner->run(static function():void{});});}echo 'PASS context cleanup '.$ownership.' '.$mode.' PHP '.PHP_VERSION.PHP_EOL;}catch(Throwable $e){$failures[]=$ownership.' '.$mode;echo 'FAIL context cleanup '.$ownership.' '.$mode.' '.$e->getMessage().PHP_EOL;}
  ContextCleanupStatement::$fault='';if($pdo->inTransaction()){$pdo->rollBack();}$admin->exec('DELETE FROM sosecurity_context_cleanup');
 }}
}finally{ContextCleanupStatement::$fault='';if(isset($pdo)&&$pdo->inTransaction()){$pdo->rollBack();}foreach(array_reverse($created) as $table){$admin->exec('DROP TABLE '.$table);}}
if($failures){throw new RuntimeException('Context cleanup cases failed: '.implode(', ',$failures));}
echo 'PASS context cleanup complete '.count($rows).' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
