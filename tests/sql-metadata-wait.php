<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;
use SoSecurity\Support\SqlStateAccess;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
foreach(['run','enlist','context','readIn'] as $method){foreach(['normal','error','policy-change','locked','short-policy','opaque'] as $mode){
 if(isset($argv[1])&&$argv[1]!==$mode){continue;}
 $dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];
 $pdo=new PDO($dsn,'sosecurity_test','integration-only',$options);$other=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=false;$locked=false;$host=false;$body=0;$reason=null;$observed=null;$outerPolicy=null;
 try{
  $pdo->exec('CREATE TABLE sosecurity_metadata_wait(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created=true;$pdo->exec('INSERT INTO sosecurity_metadata_wait VALUES(1)');
  $pdo->exec('SET SESSION innodb_lock_wait_timeout=19,lock_wait_timeout='.($mode==='short-policy'?1:23));
  $read=static function()use($pdo):array{$q=$pdo->query('SELECT @@SESSION.innodb_lock_wait_timeout AS row_wait,@@SESSION.lock_wait_timeout AS metadata_wait');try{$r=$q->fetch(PDO::FETCH_ASSOC);return [(int)$r['row_wait'],(int)$r['metadata_wait']];}finally{$q->closeCursor();}};
  if($mode==='opaque'){SqlStateAccess::bind($pdo,hash('sha256',$method.'opaque'),hash('sha256',$method.'binding'),static function():void{});}
  $unit=new SqlTransaction($pdo,new SystemClock(),1000);$owner=new SqlTransaction($pdo,new SystemClock(),5000);
  if($method==='enlist'){$pdo->beginTransaction();$host=true;}
  if($mode==='locked'){$other->exec('LOCK TABLES sosecurity_metadata_wait WRITE');$locked=true;}
  $operation=static function()use($pdo,$unit,$read,$mode,&$body,&$observed):int{
   ++$body;$observed=$read();Check::same([1,1],$observed);
   if($mode==='error'){throw new RuntimeException('PRIVATE-METADATA-ERROR');}
   if($mode==='policy-change'){$pdo->exec('SET SESSION innodb_lock_wait_timeout=7,lock_wait_timeout=9');}
   $unit->query('SELECT id FROM sosecurity_metadata_wait')->closeCursor();return 17;
  };
  $start=microtime(true);
  try{
   if($method==='readIn'){$result=$owner->run(static function()use($unit,$owner,$operation,$read,&$outerPolicy){$before=$read();try{return $unit->readIn($owner,$operation);}finally{$outerPolicy=[$before,$read()];}});}
   elseif($method==='context'){$result=$unit->inContext($operation);}
   else{$result=$unit->$method($operation);}
  }catch(SoSecurity\Exception\SecurityException $error){$reason=$error->reason();Check::same(false,strpos((string)$error,'PRIVATE-METADATA-ERROR')!==false);}
  $seconds=microtime(true)-$start;
  if($locked){$other->exec('UNLOCK TABLES');$locked=false;}
  Check::same(1,$body);Check::same([1,1],$observed);
  if(in_array($mode,['locked','error'],true)){Check::same('sql.unavailable',$reason);Check::same(false,$unit->committed());}
  else{Check::same(null,$reason);Check::same(17,$result);}
  if($mode==='locked'){Check::same(true,$seconds>=0.8&&$seconds<2.5);}
  Check::same([19,$mode==='short-policy'?1:23],$read());
  if($method==='readIn'){Check::same($outerPolicy[0],$outerPolicy[1]);}
  if($host){Check::same(true,$pdo->inTransaction());$pdo->rollBack();$host=false;}
  Check::same(false,$pdo->inTransaction());
  echo 'PASS SQL metadata wait '.json_encode(['method'=>$method,'mode'=>$mode,'seconds'=>$seconds,'observed'=>$observed,'reason'=>$reason,'php'=>PHP_VERSION]).PHP_EOL;
 }finally{if($locked){$other->exec('UNLOCK TABLES');}if($pdo->inTransaction()){$pdo->rollBack();}if($created){$pdo->exec('DROP TABLE sosecurity_metadata_wait');}}
}}
