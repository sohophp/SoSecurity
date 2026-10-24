<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;
use SoSecurity\Storage\StorageException;
final class MetadataPolicyConnection extends PDO {
 public static $mode;public static $armed=false;public static $sets=0;
 #[\ReturnTypeWillChange]
 public function exec($sql) {
  if(self::$armed&&strpos($sql,'SET SESSION lock_wait_timeout=')===0){
   ++self::$sets;
   $entry=strpos(self::$mode,'entry-')===0;
   if(($entry&&self::$sets===1)||(!$entry&&self::$sets===2)){
    if(strpos(self::$mode,'changed')!==false){parent::exec($sql);}
    if(strpos(self::$mode,'throw')!==false){throw new RuntimeException('PRIVATE-METADATA-SET');}
    return false;
   }
  }
  return parent::exec($sql);
 }
}
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
foreach(['run','enlist','readIn'] as $method){foreach(['entry-false','entry-throw','entry-changed-false','entry-changed-throw','restore-false','restore-throw'] as $mode){
 $pdo=new MetadataPolicyConnection('mysql:unix_socket='.$socket.';dbname=sosecurity_test','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
 $read=static function()use($pdo):array{$q=$pdo->query('SELECT @@SESSION.innodb_lock_wait_timeout,@@SESSION.lock_wait_timeout');try{return array_map('intval',$q->fetch(PDO::FETCH_NUM));}finally{$q->closeCursor();}};
 $body=0;$reason=null;$host=false;$unit=new SqlTransaction($pdo,new SystemClock(),1000);$owner=new SqlTransaction($pdo,new SystemClock(),5000);
 try{
  MetadataPolicyConnection::$armed=false;$pdo->exec('SET SESSION innodb_lock_wait_timeout=19,lock_wait_timeout=23');
  if($method==='enlist'){$pdo->beginTransaction();$host=true;}
  MetadataPolicyConnection::$mode=$mode;MetadataPolicyConnection::$sets=0;
  $operation=static function()use(&$body):void{++$body;};
  try{
   if($method==='readIn'){$owner->run(static function()use($unit,$owner,$operation):void{MetadataPolicyConnection::$armed=true;$unit->readIn($owner,$operation);});}
   else{MetadataPolicyConnection::$armed=true;$unit->$method($operation);}
  }catch(SoSecurity\Exception\SecurityException $error){$reason=$error->reason();Check::same(false,strpos((string)$error,'PRIVATE-METADATA-SET')!==false);}
  MetadataPolicyConnection::$armed=false;$entry=strpos($mode,'entry-')===0;
  Check::same($entry?'sql.unavailable':'sql.cleanup',$reason);Check::same($entry?0:1,$body);
  if($entry){Check::same([19,23],$read());if($host){Check::same(true,$pdo->inTransaction());$pdo->rollBack();$host=false;}Check::same(17,$unit->run(static function():int{return 17;}));Check::same([19,23],$read());}
  else{Check::throws(StorageException::class,static function()use($unit):void{$unit->run(static function():void{});});if($method==='readIn'){Check::throws(StorageException::class,static function()use($owner):void{$owner->run(static function():void{});});}}
  echo 'PASS SQL metadata policy failure '.$method.' '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
 }finally{MetadataPolicyConnection::$armed=false;if($pdo->inTransaction()){$pdo->rollBack();}}
}}
