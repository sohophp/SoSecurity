<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;
$mysql=($argv[1]??'sqlite')==='mysql';$directory=$mysql?null:privateDirectory();if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';}else{$dsn='sqlite:'.$directory.'/state.sqlite';}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}$connect=static function()use($dsn,$mysql,$options):PDO{return new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);};
final class ReadFallbackStatement extends PDOStatement {
 public static $mode='';
 private function selected():bool{return self::$mode!==''&&strpos($this->queryString,'SELECT id FROM sosecurity_read_fallback')===0;}
 public function fetchAll($mode=null,$className=null,$constructorArgs=null,...$extra):array{if($this->selected()&&self::$mode==='fetch-close'){throw new RuntimeException('PRIVATE-FALLBACK-FETCH');}return parent::fetchAll(...func_get_args());}
 public function closeCursor():bool{$closed=parent::closeCursor();if(!$this->selected()){return $closed;}if(self::$mode==='throw'){throw new RuntimeException('PRIVATE-FALLBACK-CLOSE');}return false;}
}
$admin=$connect();if(!$mysql){$admin->exec('PRAGMA journal_mode=DELETE');$admin->exec('PRAGMA synchronous=FULL');}$admin->exec('CREATE TABLE sosecurity_read_fallback(id INTEGER NOT NULL PRIMARY KEY)'.($mysql?' ENGINE=InnoDB':''));$failures=[];$count=0;
try{
 foreach(['normal','denied','false','throw','fetch-close'] as $mode){
  ++$count;$pdo=$connect();$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[ReadFallbackStatement::class]);SqlStateAccess::bind($pdo,hash('sha256','owned-fallback-'.$mode),hash('sha256','owned-fallback-binding-'.$mode),static function():void{});$owner=new SqlTransaction($pdo,new SoSecurity\Support\SystemClock(),10000);$child=new SqlTransaction($pdo,new SoSecurity\Support\SystemClock(),10000);$inner=null;$outer=null;$returned=false;$after=false;$fault=in_array($mode,['false','throw','fetch-close'],true);ReadFallbackStatement::$mode=$fault?$mode:'';
  try{$owner->run(static function()use($owner,$child,$mode,&$inner,&$after):void{try{$child->readIn($owner,static function()use($child,$mode):void{try{$child->metadataRows('SELECT id FROM sosecurity_read_fallback');}catch(Throwable $e){ReadFallbackStatement::$mode='';}if($mode==='denied'){throw new SecurityException('Ordinary test refusal.','test.denied');}});}catch(Throwable $e){$inner=$e;}ReadFallbackStatement::$mode='';$owner->query('INSERT INTO sosecurity_read_fallback VALUES(1)')->closeCursor();$after=true;});$returned=true;}catch(Throwable $e){$outer=$e;}
  ReadFallbackStatement::$mode='';$visible=(int)$admin->query('SELECT COUNT(*) FROM sosecurity_read_fallback')->fetchColumn();$reason=$inner instanceof SecurityException||$inner instanceof SoSecurity\Exception\ConfigurationException?$inner->reason():null;echo 'OBSERVATION fallback '.json_encode(['mode'=>$mode,'returned'=>$returned,'visible'=>$visible,'inner_reason'=>$reason,'after'=>$after]).PHP_EOL;
  try{Check::same(!$fault,$returned);Check::same($fault?0:1,$visible);Check::same(!$fault,$after);Check::same($fault?'sql.cleanup':($mode==='denied'?'test.denied':null),$reason);Check::same(false,$pdo->inTransaction());Check::same(false,strpos((string)$inner.(string)$outer,'PRIVATE-FALLBACK-')!==false);if($fault){foreach([$owner,$child] as $failed){Check::throws(StorageException::class,static function()use($failed):void{$failed->run(static function():void{});});}}else{$owner->run(static function():void{});$child->run(static function():void{});}echo 'PASS read fallback '.($mysql?'mysql':'sqlite').' '.$mode.' PHP '.PHP_VERSION.PHP_EOL;}catch(Throwable $e){$failures[]=$mode;echo 'FAIL read fallback '.$mode.' '.$e->getMessage().PHP_EOL;}
  if($pdo->inTransaction()){$pdo->rollBack();}$admin->exec('DELETE FROM sosecurity_read_fallback');
 }
}finally{ReadFallbackStatement::$mode='';if(isset($pdo)&&$pdo->inTransaction()){$pdo->rollBack();}$admin->exec('DROP TABLE sosecurity_read_fallback');if($directory!==null){$owner=null;$child=null;$pdo=null;$admin=null;cleanDirectory($directory);}}
if($failures){throw new RuntimeException('Read fallback cases failed: '.implode(', ',$failures));}echo 'PASS read fallback complete '.$count.' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
