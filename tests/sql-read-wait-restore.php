<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;
use SoSecurity\Storage\StorageException;
$backend=$argv[1]??'mysql';if(!in_array($backend,['mysql','sqlite'],true)){throw new RuntimeException('Use sqlite|mysql');}$mysql=$backend==='mysql';$directory=$mysql?null:privateDirectory();if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}}
function readWaitRestoreChange(PDO $pdo):void{$pdo->exec($pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql'?'SET SESSION innodb_lock_wait_timeout=7,lock_wait_timeout=9':'PRAGMA busy_timeout=7000');}
final class ReadWaitRestoreClock implements Clock {
 private $pdo;public $armed=false;
 public function __construct(PDO $pdo){$this->pdo=$pdo;}
 public function now():int{if($this->armed){$this->armed=false;readWaitRestoreChange($this->pdo);}return 100000;}
}
final class ReadWaitRestoreStatement extends PDOStatement {
 private $pdo;public static $armed=false;
 protected function __construct(PDO $pdo){$this->pdo=$pdo;}
 public function fetchAll($mode=null,$className=null,$constructorArgs=null,...$extra):array{$rows=parent::fetchAll(...func_get_args());if(self::$armed&&$this->queryString==='SELECT id FROM sosecurity_read_wait_restore'){self::$armed=false;readWaitRestoreChange($this->pdo);}return $rows;}
}
$dsn=$mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test':'sqlite:'.$directory.'/wait.sqlite';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}$admin=new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);if(!$mysql){$admin->exec('PRAGMA journal_mode=DELETE');$admin->exec('PRAGMA synchronous=FULL');}$failures=[];$count=0;$created=false;
try{
 $admin->exec('CREATE TABLE sosecurity_read_wait_restore(id INTEGER NOT NULL PRIMARY KEY)'.($mysql?' ENGINE=InnoDB':''));$created=true;
 foreach(['plain','plain-mutated','clock','statement'] as $dependency){foreach(['normal','error'] as $mode){foreach([0,1] as $initial){
  $pdo=new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);$pdo->exec($mysql?'SET SESSION innodb_lock_wait_timeout='.$initial.',lock_wait_timeout=1':'PRAGMA busy_timeout='.$initial);$clock=$dependency==='clock'?new ReadWaitRestoreClock($pdo):new SystemClock();if($dependency==='statement'){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[ReadWaitRestoreStatement::class,[$pdo]]);}$owner=new SqlTransaction($pdo,new SystemClock(),10000);$child=new SqlTransaction($pdo,$clock,1000);$observed=null;$inner=null;
  $read=static function()use($pdo,$mysql):array{$q=$pdo->query($mysql?'SELECT @@SESSION.innodb_lock_wait_timeout AS row_wait,@@SESSION.lock_wait_timeout AS metadata_wait':'PRAGMA busy_timeout');try{$r=$q->fetch(PDO::FETCH_NUM);return array_map('intval',$r);}finally{$q->closeCursor();}};
  $external=$read();Check::same(true,in_array($external[0],$mysql&&$initial===0?[0,1]:[$initial],true));$expected=null;
  $owner->run(static function()use($owner,$child,$clock,$dependency,$mode,$read,$pdo,&$observed,&$inner,&$expected):void{$expected=$read();try{$child->readIn($owner,static function()use($child,$clock,$dependency,$mode,$pdo):void{if($dependency==='plain-mutated'){readWaitRestoreChange($pdo);}if($clock instanceof ReadWaitRestoreClock){$clock->armed=true;}ReadWaitRestoreStatement::$armed=$dependency==='statement';$child->metadataRows('SELECT id FROM sosecurity_read_wait_restore');if($mode==='error'){throw new StorageException('Ordinary owned refusal.','test.refused');}});}catch(Throwable $e){$inner=$e;}$observed=$read();});
  ReadWaitRestoreStatement::$armed=false;$after=$read();echo 'OBSERVATION borrowed wait restore '.json_encode(['backend'=>$backend,'dependency'=>$dependency,'mode'=>$mode,'initial'=>$initial,'actual_initial'=>$external,'inside_owner'=>$observed,'after_owner'=>$after,'inner'=>$inner instanceof SoSecurity\Exception\SecurityException?$inner->reason():null]).PHP_EOL;
  try{Check::same($expected,$observed);Check::same($external,$after);Check::same($mode==='error'?'test.refused':null,$inner instanceof SoSecurity\Exception\SecurityException?$inner->reason():null);Check::same(false,$pdo->inTransaction());++$count;echo 'PASS borrowed wait restore '.$dependency.' '.$mode.' PHP '.PHP_VERSION.PHP_EOL;}catch(Throwable $e){$failures[]=$dependency.' '.$mode;echo 'FAIL borrowed wait restore '.$dependency.' '.$mode.' '.$e->getMessage().PHP_EOL;}
 }}}
}finally{ReadWaitRestoreStatement::$armed=false;if(isset($pdo)&&$pdo->inTransaction()){$pdo->rollBack();}if($created){$admin->exec('DROP TABLE sosecurity_read_wait_restore');}if($directory!==null){$owner=null;$child=null;$pdo=null;$admin=null;cleanDirectory($directory);}}
if($failures){throw new RuntimeException('Borrowed wait restore cases failed: '.implode(', ',$failures));}
echo 'PASS borrowed wait restore complete '.$count.' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
