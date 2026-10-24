<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlStateAccess;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function witnessBytes(PDO $pdo):int{
 $q=$pdo->query("SHOW SESSION STATUS LIKE 'Bytes_received'");try{$row=$q->fetch(PDO::FETCH_NUM);Check::same(true,is_array($row)&&isset($row[1])&&ctype_digit((string)$row[1]));return (int)$row[1];}finally{Check::same(true,$q->closeCursor());}
}
class WitnessBatchAdapter extends PDO {}
class WitnessBatchStatement extends PDOStatement {}
$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$multi=PHP_VERSION_ID>=80400?\Pdo\Mysql::ATTR_MULTI_STATEMENTS:PDO::MYSQL_ATTR_MULTI_STATEMENTS;
$created=false;$admin=new PDO($dsn,'sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
try{
 $admin->exec('CREATE TABLE sosecurity_witness_batch(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created=true;
 foreach(['native-owned','native-enlisted','multi-disabled','multi-disabled-rollback','multi-disabled-rollback-initial','ended','silent-ended','early-rollback','custom-clock','pdo-adapter','statement-adapter','opaque-guard','borrow','multi-disabled-borrow','callback-error'] as $mode){
  $options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];if(strpos($mode,'multi-disabled')===0){$options[$multi]=false;}
  $pdo=$mode==='pdo-adapter'?new WitnessBatchAdapter($dsn,'sosecurity_test','integration-only',$options):new PDO($dsn,'sosecurity_test','integration-only',$options);
  if($mode==='statement-adapter'){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[WitnessBatchStatement::class]);}
  $guardCalls=0;if($mode==='opaque-guard'){SqlStateAccess::bind($pdo,hash('sha256','owned-batch'),hash('sha256','owned-batch-binding'),static function()use(&$guardCalls):void{++$guardCalls;});}
  $clock=$mode==='custom-clock'?new TestClock():new SoSecurity\Support\SystemClock();$unit=new SqlTransaction($pdo,$clock,10000);$joined=in_array($mode,['native-enlisted','early-rollback','multi-disabled-rollback','multi-disabled-rollback-initial'],true);$calls=0;$error=null;$lost=null;$fixtureFailure=null;
  if($joined){$pdo->beginTransaction();$pdo->exec('SAVEPOINT owned_before_unit');}

  try{$execute=[$unit,$joined?'enlist':'run'];$execute(static function()use($unit,$pdo,$clock,$mode,$joined,&$calls,&$lost,&$fixtureFailure):void{try{
   $unit->query('INSERT INTO sosecurity_witness_batch VALUES(1)')->closeCursor();
   if($mode!=='multi-disabled-rollback-initial'){
    $manual=($joined?'sosecurity_witness_':'sosecurity_unit_').str_repeat('z',32);$pdo->exec('SAVEPOINT '.$manual);
    $start=witnessBytes($pdo);$pdo->exec('RELEASE SAVEPOINT '.$manual);$pdo->exec('SAVEPOINT '.$manual);$baseline=witnessBytes($pdo)-$start;$pdo->exec('RELEASE SAVEPOINT '.$manual);
    $start=witnessBytes($pdo);$unit->invoke(static function():void{},[],'test.bytes');$actual=witnessBytes($pdo)-$start;
    echo 'WITNESS_BYTES '.$mode.' separate '.$baseline.' sdk '.$actual.PHP_EOL;
    $eligible=!in_array($mode,['custom-clock','pdo-adapter','statement-adapter','opaque-guard'],true);
    if(!$eligible){Check::same($baseline,$actual);}
    elseif(strpos($mode,'multi-disabled')===0){Check::same(true,$actual>$baseline);$start=witnessBytes($pdo);$unit->invoke(static function():void{},[],'test.bytes');Check::same($baseline,witnessBytes($pdo)-$start);}
    else{Check::same(true,$actual<$baseline);Check::same(true,$baseline-$actual<=64);}

   }

   try{$unit->invoke(static function()use($pdo,$mode):void{if($mode==='silent-ended'){$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_SILENT);}if($mode==='ended'||$mode==='silent-ended'){$pdo->exec('COMMIT');}if(in_array($mode,['early-rollback','multi-disabled-rollback','multi-disabled-rollback-initial'],true)){$pdo->exec('ROLLBACK TO SAVEPOINT owned_before_unit');}if($mode==='callback-error'){throw new RuntimeException('PRIVATE-WITNESS-CALLBACK');}},[],'test.callback');}catch(SoSecurity\Exception\ConfigurationException $caught){$lost=$caught->reason();throw $caught;}
   if($mode==='borrow'||$mode==='multi-disabled-borrow'){$child=new SqlTransaction($pdo,new SoSecurity\Support\SystemClock(),10000);$count=$child->readIn($unit,static function()use($child):int{return (int)$child->query('SELECT COUNT(*) FROM sosecurity_witness_batch')->fetchColumn();});Check::same(1,$count);}
   $unit->invoke(static function():bool{return true;},[],'test.callback');++$calls;}catch(Throwable $failure){$fixtureFailure=$failure;throw $failure;}
  });}catch(SoSecurity\Exception\SecurityException|SoSecurity\Exception\ConfigurationException $caught){$error=$caught;}

  $lostMode=in_array($mode,['ended','silent-ended','early-rollback','multi-disabled-rollback','multi-disabled-rollback-initial'],true);
  if($lostMode){Check::same('configuration.sql_transaction_lost',$lost);Check::same('sql.cleanup',$error->reason());Check::same(0,$calls);Check::same(false,$unit->committed());Check::throws(SoSecurity\Storage\StorageException::class,static function()use($unit):void{$unit->run(static function():void{});});}
  elseif($mode==='callback-error'){Check::same('test.callback',$error->reason());Check::same(0,$calls);Check::same(false,strpos((string)$error,'PRIVATE-WITNESS-CALLBACK')!==false);Check::same(0,(int)$admin->query('SELECT COUNT(*) FROM sosecurity_witness_batch')->fetchColumn());Check::same(7,$unit->run(static function():int{return 7;}));}
  else{if($error!==null&&$fixtureFailure!==null){echo 'FIXTURE_FAILURE '.get_class($fixtureFailure).' '.$fixtureFailure->getMessage().PHP_EOL;}Check::same(null,$error);Check::same(1,$calls);Check::same(!$joined,$unit->committed());}
  if($mode==='opaque-guard'){Check::same(true,$guardCalls>4);}
  if($joined){Check::same(0,(int)$admin->query('SELECT COUNT(*) FROM sosecurity_witness_batch')->fetchColumn());$pdo->exec('ROLLBACK');}
  else{Check::same(in_array($mode,['callback-error'],true)?0:1,(int)$admin->query('SELECT COUNT(*) FROM sosecurity_witness_batch')->fetchColumn());}
  if(strpos($mode,'multi-disabled')===0){$disabled=null;try{$pdo->exec('SAVEPOINT owned_disabled_a; SAVEPOINT owned_disabled_b');}catch(PDOException $caught){$disabled=$caught;}Check::same(true,$disabled instanceof PDOException);Check::same(1064,(int)$disabled->errorInfo[1]);}
  $admin->exec('DELETE FROM sosecurity_witness_batch WHERE id=1');$pdo=null;echo 'PASS witness batch '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
 }
}finally{if(isset($pdo)&&$pdo instanceof PDO){try{$pdo->exec('ROLLBACK');}catch(Throwable $cleanup){}}if($created){$admin->exec('DROP TABLE sosecurity_witness_batch');}}
