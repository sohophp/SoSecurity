<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Support\SqlTransaction;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function durableControl(string $sql):string{
 $pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned controller unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}return trim($out);
}
class DurableAdapter extends PDO {}
final class DurableReentrantClock implements SoSecurity\Support\Clock {
 public $calls=0;public $at=PHP_INT_MAX;public $hook;public $entries=0;
 public function now():int{++$this->calls;if($this->calls===$this->at&&$this->hook!==null){$hook=$this->hook;$this->hook=null;$hook();}return 100000;}
}
class DurableCloseStatement extends PDOStatement {
 public static $fault=true;
 public function closeCursor():bool{$closed=parent::closeCursor();return self::$fault&&$this->queryString==='SELECT @@GLOBAL.innodb_flush_log_at_trx_commit'?false:$closed;}
}
$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$sql='SELECT @@GLOBAL.innodb_flush_log_at_trx_commit';$other=false;
try{
 durableControl('CREATE DATABASE sosecurity_durable_other');$other=true;durableControl("GRANT SELECT ON sosecurity_durable_other.* TO 'sosecurity_test'@'localhost'");
 foreach(['normal','unregistered','pdo-adapter','statement-adapter','changed-global','changed-database','fetch-settings','eviction','reentrant','cleanup-failure'] as $mode){
  durableControl('SET GLOBAL innodb_flush_log_at_trx_commit=1');$pdo=$mode==='pdo-adapter'?new DurableAdapter($dsn,'sosecurity_test','integration-only',$options):new PDO($dsn,'sosecurity_test','integration-only',$options);
  if(in_array($mode,['statement-adapter','cleanup-failure'],true)){DurableCloseStatement::$fault=$mode==='cleanup-failure';$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[DurableCloseStatement::class]);}
  $supported=true;try{foreach([PDO::ATTR_CASE,PDO::ATTR_ORACLE_NULLS,PDO::ATTR_STRINGIFY_FETCHES] as $attribute){$pdo->getAttribute($attribute);}}catch(Throwable $unsupported){$supported=false;}
  if($mode==='normal'){echo 'DRIVER_CACHE '.($supported?'eligible':'fresh').PHP_EOL;}
  if($mode!=='unregistered'){SqlStateAccess::bind($pdo,hash('sha256','owned-durable-'.$mode),hash('sha256','owned-durable-binding-'.$mode),static function():void{});}
  $clock=$mode==='reentrant'?new DurableReentrantClock():new TestClock();$unit=new SqlTransaction($pdo,$clock,10000);$id=(int)$pdo->query('SELECT CONNECTION_ID()')->fetchColumn();durableControl("SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");$error=null;$completed=false;
  try{$unit->run(static function()use($unit,$pdo,$clock,$mode,&$completed):void{
   SqlSchema::durable($unit);
   if($mode==='eviction'){for($i=0;$i<8;++$i){$unit->metadataRows('SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table LIMIT 1 /* owned_durable_'.$i.' */',['table'=>'sosecurity_absent']);}}
   $unit->invoke(static function()use($pdo,$mode):void{if($mode==='changed-global'){durableControl('SET GLOBAL innodb_flush_log_at_trx_commit=2');}if($mode==='changed-database'){$pdo->exec('USE sosecurity_durable_other');}if($mode==='fetch-settings'){$pdo->setAttribute(PDO::ATTR_CASE,PDO::CASE_UPPER);}},[],'test.callback');
   if($mode==='reentrant'){$clock->at=$clock->calls+2;$clock->hook=static function()use($pdo,$clock):void{$child=new SqlTransaction($pdo,new TestClock(),10000);$child->enlist(static function()use($child):void{SqlSchema::durable($child);});++$clock->entries;};}
   SqlSchema::durable($unit);
   if($mode==='fetch-settings'){$pdo->setAttribute(PDO::ATTR_CASE,PDO::CASE_NATURAL);$pdo->setAttribute(PDO::ATTR_STRINGIFY_FETCHES,true);}
   SqlSchema::durable($unit);$completed=true;
  });}catch(SoSecurity\Exception\SecurityException|SoSecurity\Exception\ConfigurationException $caught){$error=$caught;}
  durableControl('SET GLOBAL general_log=OFF');
  if($mode==='changed-global'){Check::same(false,$completed);Check::same('configuration.sql_durability',$error->reason());}
  elseif($mode==='cleanup-failure'){Check::same(false,$completed);Check::same('sql.cleanup',$error->reason());DurableCloseStatement::$fault=false;Check::throws(SoSecurity\Storage\StorageException::class,static function()use($unit):void{$unit->run(static function():void{});});}
  else{Check::same(null,$error);Check::same(true,$completed);}
  $prepares=(int)durableControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='Prepare' AND argument='SELECT @@GLOBAL.innodb_flush_log_at_trx_commit'");
  $executes=(int)durableControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='Execute' AND argument='SELECT @@GLOBAL.innodb_flush_log_at_trx_commit'");
  if($mode==='reentrant'){Check::same(1,$clock->entries);}
  $expectedExecute=$mode==='changed-global'?2:($mode==='cleanup-failure'?1:($mode==='reentrant'?4:3));
  $reuse=$supported&&get_class($pdo)===PDO::class&&$mode!=='unregistered'&&$pdo->getAttribute(PDO::ATTR_STATEMENT_CLASS)===[PDOStatement::class];
  $expectedPrepare=$reuse?(in_array($mode,['eviction','reentrant'],true)?2:($mode==='fetch-settings'?3:1)):$expectedExecute;
  echo 'COUNTS '.$mode.' prepare '.$prepares.' execute '.$executes.PHP_EOL;Check::same($expectedPrepare,$prepares);Check::same($expectedExecute,$executes);
  $databaseProbes=(int)durableControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='Execute' AND argument='SELECT CAST(DATABASE() AS BINARY)'");Check::same($mode==='eviction'&&$supported?8:0,$databaseProbes);
  echo 'PASS durable statement '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
 }
}finally{durableControl('SET GLOBAL general_log=OFF; SET GLOBAL innodb_flush_log_at_trx_commit=1');if($other){durableControl('DROP DATABASE sosecurity_durable_other');}}
