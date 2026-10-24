<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Storage\StorageException;
$mysql=($argv[1]??'sqlite')==='mysql';$directory=$mysql?null:privateDirectory();
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';}else{$dsn='sqlite:'.$directory.'/state.sqlite';}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}
$connect=static function()use($dsn,$options,$mysql):PDO{return new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);};
final class CaughtCleanupStatement extends PDOStatement {
 public static $fault='';
 private function selected():bool{return self::$fault!==''&&strpos($this->queryString,'SELECT value FROM sosecurity_caught_cleanup')===0;}
 public function fetchAll($mode=null,$className=null,$constructorArgs=null,...$extra):array{if($this->selected()&&self::$fault==='fetch-close'){throw new RuntimeException('PRIVATE-CAUGHT-FETCH');}return parent::fetchAll(...func_get_args());}
 public function closeCursor():bool{$closed=parent::closeCursor();if(!$this->selected()){return $closed;}if(self::$fault==='throw'){throw new RuntimeException('PRIVATE-CAUGHT-CLOSE');}return false;}
}
$admin=$connect();if(!$mysql){$admin->exec('PRAGMA journal_mode=DELETE');$admin->exec('PRAGMA synchronous=FULL');}$admin->exec('CREATE TABLE sosecurity_caught_cleanup(id INTEGER NOT NULL PRIMARY KEY,value VARCHAR(16) NOT NULL)'.($mysql?' ENGINE=InnoDB':''));$cases=0;
try{
 foreach(['owned','host','borrowed'] as $ownership){foreach(['normal','false','throw','fetch-close'] as $fault){foreach($fault==='normal'?['return']:['insert','callback','return'] as $action){
  ++$cases;$admin->exec("INSERT INTO sosecurity_caught_cleanup VALUES(1,'owned')");$pdo=$connect();$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[CaughtCleanupStatement::class]);$unit=new SqlTransaction($pdo,new SoSecurity\Support\SystemClock(),10000);$owner=$ownership==='borrowed'?new SqlTransaction($pdo,new SoSecurity\Support\SystemClock(),10000):null;$inner=null;$outer=null;$returned=false;$callback=0;$postReturn=false;CaughtCleanupStatement::$fault=$fault==='normal'?'':$fault;
  $body=static function()use($unit,$action,&$inner,&$callback,&$postReturn):void{try{$unit->metadataRows('SELECT value FROM sosecurity_caught_cleanup WHERE id=1');}catch(Throwable $e){$inner=$e;}CaughtCleanupStatement::$fault='';if($action==='insert'){$unit->query("INSERT INTO sosecurity_caught_cleanup VALUES(2,'blocked')")->closeCursor();}if($action==='callback'){$unit->invoke(static function()use(&$callback):void{++$callback;},[],'test.callback');}$postReturn=true;};
  try{if($ownership==='host'){$pdo->beginTransaction();$unit->enlist($body);}elseif($owner!==null){$owner->run(static function()use($unit,$owner,$body):void{$unit->readIn($owner,$body);});}else{$unit->run($body);}$returned=true;}catch(Throwable $e){$outer=$e;}
  $visible=(int)$admin->query('SELECT COUNT(*) FROM sosecurity_caught_cleanup WHERE id=2')->fetchColumn();$reason=$inner instanceof SoSecurity\Exception\SecurityException||$inner instanceof SoSecurity\Exception\ConfigurationException?$inner->reason():null;
  Check::same($fault==='normal',$returned);Check::same(0,$visible);Check::same(0,$callback);Check::same($ownership==='host',$pdo->inTransaction());
  if($fault==='normal'){Check::same(null,$inner);Check::same(null,$outer);Check::same(true,$postReturn);}else{Check::same('sql.cleanup',$reason);Check::same(false,strpos((string)$inner.(string)$outer,'PRIVATE-CAUGHT-')!==false);Check::same($action==='return',$postReturn);Check::same(true,$outer instanceof SoSecurity\Exception\SecurityException||$outer instanceof SoSecurity\Exception\ConfigurationException);Check::throws(StorageException::class,static function()use($unit):void{$unit->run(static function():void{});});if($owner!==null){Check::throws(StorageException::class,static function()use($owner):void{$owner->run(static function():void{});});}}
  CaughtCleanupStatement::$fault='';if($pdo->inTransaction()){$pdo->rollBack();}$admin->exec('DELETE FROM sosecurity_caught_cleanup');echo 'PASS caught cleanup '.($mysql?'mysql':'sqlite').' '.$ownership.' '.$fault.' '.$action.' PHP '.PHP_VERSION.PHP_EOL;
 }}}
}finally{CaughtCleanupStatement::$fault='';if(isset($pdo)&&$pdo->inTransaction()){$pdo->rollBack();}$admin->exec('DROP TABLE sosecurity_caught_cleanup');if($directory!==null){$unit=null;$owner=null;$pdo=null;$admin=null;cleanDirectory($directory);}}
echo 'PASS caught cleanup complete '.$cases.' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
