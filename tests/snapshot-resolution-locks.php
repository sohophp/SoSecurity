<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4';$pdo=new PDO($dsn,'sosecurity_test','integration-only',$options);$observer=new PDO($dsn,'sosecurity_test','integration-only',$options);$observer->exec('SET SESSION lock_wait_timeout=1');$created=[];$added=[];$tables=[];
try{
 foreach(['a','b','c','d'] as $suffix){$name='snapshot_lock_'.$suffix;$pdo->exec('CREATE TABLE `'.$name.'`(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created[]=$name;$pdo->exec('INSERT INTO `'.$name.'` VALUES(7)');$tables[$name]=['columns'=>['id'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>2];}
 $source=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-resolution-locks',$tables,15000);$digest=$source->digest();$unit=SoSecurity\Support\SqlTransaction::forObservation($pdo,new SoSecurity\Support\SystemClock(),15000);Check::same(true,$unit->canBatchLedgerReads());$method=new ReflectionMethod(SoSecurity\Account\SqlStateSnapshot::class,'mysqlSchemas');if(PHP_VERSION_ID<80100){$method->setAccessible(true);}
 try{$unit->run(static function()use($unit,$source,$method,$tables,$observer,&$added):void{
  // Exercise the production group parser inside the same kind of native observation unit.
  $schema=$method->invoke($source,$unit,$tables);Check::same(array_keys($tables),array_keys($schema));
  foreach(array_keys($tables) as $name){$blocked=false;try{$observer->exec('ALTER TABLE `'.$name.'` ADD owned_snapshot_lock INT');$added[]=$name;}catch(PDOException $e){$blocked=isset($e->errorInfo[1])&&(int)$e->errorInfo[1]===1205;}Check::same(true,$blocked);}
 });}finally{foreach($added as $name){$observer->exec('ALTER TABLE `'.$name.'` DROP COLUMN owned_snapshot_lock');}$added=[];}
 Check::same(false,$pdo->inTransaction());Check::same($digest,$source->digest());foreach($created as $name){Check::same(['7'],array_map('strval',$observer->query('SELECT id FROM `'.$name.'`')->fetchAll(PDO::FETCH_COLUMN)));}
 echo 'PASS snapshot resolution metadata locks 4 tables '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
}finally{if($pdo->inTransaction()){$pdo->rollBack();}foreach($added as $name){$observer->exec('ALTER TABLE `'.$name.'` DROP COLUMN owned_snapshot_lock');}$source=null;$unit=null;foreach(array_reverse($created) as $name){$pdo->exec('DROP TABLE `'.$name.'`');}}
