<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;
use SoSecurity\Storage\StorageException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ConfigurationException;
final class ReadRestoreFailureConnection extends PDO {
 public $armed=false;public $fault='normal';public $target='';public $injected=false;
 #[\ReturnTypeWillChange]
 public function exec($statement){if($this->armed&&$statement===$this->target){$this->armed=false;if($this->fault!=='normal'){$this->injected=true;if($this->fault==='false'){return false;}if($this->fault==='after'){parent::exec($statement);}throw new RuntimeException('PRIVATE-WAIT-RESTORE');}}return parent::exec($statement);}
}
$backend=$argv[1]??'sqlite';if(!in_array($backend,['mysql','sqlite'],true)){throw new RuntimeException('Use sqlite|mysql');}$mysql=$backend==='mysql';$directory=$mysql?null:privateDirectory();
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}}
$dsn=$mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test':'sqlite:'.$directory.'/restore.sqlite';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}$admin=new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);if(!$mysql){$admin->exec('PRAGMA journal_mode=DELETE');$admin->exec('PRAGMA synchronous=FULL');}$failures=[];$created=false;$count=0;
try{
 $admin->exec('CREATE TABLE sosecurity_restore_failure(id INTEGER NOT NULL PRIMARY KEY)'.($mysql?' ENGINE=InnoDB':''));$created=true;
 foreach(['normal','false','throw','after'] as $mode){foreach([0,1] as $initial){foreach([false,true] as $bodyError){
  $pdo=new ReadRestoreFailureConnection($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);$pdo->fault=$mode;$pdo->target=($mysql?'SET SESSION innodb_lock_wait_timeout=':'PRAGMA busy_timeout=').$initial;$pdo->exec($pdo->target);$actual=$initial;if($mysql){$q=$pdo->query('SELECT @@SESSION.innodb_lock_wait_timeout');$actual=(int)$q->fetchColumn();$q->closeCursor();}Check::same(true,in_array($actual,$mysql&&$initial===0?[0,1]:[$initial],true));$pdo->target=($mysql?'SET SESSION innodb_lock_wait_timeout=':'PRAGMA busy_timeout=').$actual;if($mysql){$pdo->exec('SET SESSION lock_wait_timeout=1');}$owner=new SqlTransaction($pdo,new SystemClock(),10000);$child=new SqlTransaction($pdo,new SystemClock(),1000);$inner=null;$outer=null;$returned=false;
  try{$owner->run(static function()use($owner,$child,$pdo,$mysql,$bodyError,&$inner):void{try{$child->readIn($owner,static function()use($child,$pdo,$mysql,$bodyError):void{$child->metadataRows('SELECT id FROM sosecurity_restore_failure');$pdo->exec($mysql?'SET SESSION innodb_lock_wait_timeout=7':'PRAGMA busy_timeout=7000');$pdo->armed=true;if($bodyError){throw new RuntimeException('PRIVATE-WAIT-BODY');}});}catch(Throwable $e){$inner=$e;}$pdo->armed=false;$owner->query('INSERT INTO sosecurity_restore_failure VALUES(1)')->closeCursor();});$returned=true;}catch(Throwable $e){$outer=$e;}
  $pdo->armed=false;$visible=(int)$admin->query('SELECT COUNT(*) FROM sosecurity_restore_failure')->fetchColumn();$reason=$inner instanceof SecurityException||$inner instanceof ConfigurationException?$inner->reason():null;$private=strpos((string)$inner.(string)$outer,'PRIVATE-WAIT-')!==false;$fault=$mode!=='normal';echo 'OBSERVATION wait restore failure '.json_encode(['backend'=>$backend,'mode'=>$mode,'initial'=>$initial,'actual'=>$actual,'body_error'=>$bodyError,'injected'=>$pdo->injected,'returned'=>$returned,'visible'=>$visible,'inner'=>$reason,'private_detail'=>$private]).PHP_EOL;
  try{Check::same($fault,$pdo->injected);Check::same(!$fault,$returned);Check::same($fault?0:1,$visible);Check::same($fault?'sql.cleanup':($bodyError?'sql.unavailable':null),$reason);Check::same(false,$private);Check::same(false,$pdo->inTransaction());if($fault){foreach([$owner,$child] as $failed){Check::throws(StorageException::class,static function()use($failed):void{$failed->run(static function():void{});});}}++$count;echo 'PASS wait restore failure '.$backend.' '.$mode.' '.$initial.' '.($bodyError?'error':'normal').' PHP '.PHP_VERSION.PHP_EOL;}catch(Throwable $e){$failures[]=$mode.' '.$initial.' '.(int)$bodyError;echo 'FAIL wait restore failure '.$mode.' '.$e->getMessage().PHP_EOL;}
  $admin->exec('DELETE FROM sosecurity_restore_failure');
 }}}
}finally{if(isset($pdo)&&$pdo->inTransaction()){$pdo->rollBack();}if($created){$admin->exec('DROP TABLE sosecurity_restore_failure');}if($directory!==null){$owner=null;$child=null;$pdo=null;$admin=null;cleanDirectory($directory);}}
if($failures){throw new RuntimeException('Read wait restore failure cases failed: '.implode(', ',$failures));}
echo 'PASS wait restore failure complete '.$count.' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
