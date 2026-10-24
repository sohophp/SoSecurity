<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlStateAccess;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function timeoutControl(string $sql):string{
 $pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned controller unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}return trim($out);
}
class TimeoutAdapter extends PDO {}
class TimeoutCacheStatement extends PDOStatement {}
final class TimeoutReentrantClock implements SoSecurity\Support\Clock {
 public $calls=0;public $at=PHP_INT_MAX;public $hook;public $entries=0;
 public function now():int{++$this->calls;if($this->calls===$this->at&&$this->hook!==null){$hook=$this->hook;$this->hook=null;$hook();}return 100000;}
}
$sql='SELECT @@SESSION.innodb_lock_wait_timeout';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$other=false;
try{
 timeoutControl('CREATE DATABASE sosecurity_timeout_other');$other=true;timeoutControl("GRANT SELECT ON sosecurity_timeout_other.* TO 'sosecurity_test'@'localhost'");
 foreach(['normal','unregistered','pdo-adapter','statement-adapter','changed-session','changed-database','fetch-settings','eviction','unbuffered','reentrant'] as $mode){
  $opts=$options;if($mode==='unbuffered'){$opts[PHP_VERSION_ID>=80400?Pdo\Mysql::ATTR_USE_BUFFERED_QUERY:PDO::MYSQL_ATTR_USE_BUFFERED_QUERY]=false;}
  $dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$pdo=$mode==='pdo-adapter'?new TimeoutAdapter($dsn,'sosecurity_test','integration-only',$opts):new PDO($dsn,'sosecurity_test','integration-only',$opts);
  if($mode==='statement-adapter'){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[TimeoutCacheStatement::class]);}
  $supported=true;try{foreach([PDO::ATTR_CASE,PDO::ATTR_ORACLE_NULLS,PDO::ATTR_STRINGIFY_FETCHES] as $attr){$pdo->getAttribute($attr);}}catch(Throwable $unsupported){$supported=false;}
  if($mode!=='unregistered'){SqlStateAccess::bind($pdo,hash('sha256','owned-timeout-cache:'.$mode),hash('sha256','owned-timeout-cache-binding:'.$mode),static function():void{});}
  $read=static function()use($pdo,$sql):int{$q=$pdo->query($sql.' /* owned_timeout_observe */');$value=(int)$q->fetchColumn();Check::same(true,$q->closeCursor());return $value;};
  $pdo->exec('SET SESSION innodb_lock_wait_timeout=19');$q=$pdo->query('SELECT CONNECTION_ID()');$id=(int)$q->fetchColumn();$q->closeCursor();
  $clock=$mode==='reentrant'?new TimeoutReentrantClock():new TestClock();timeoutControl("SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");$restored=19;
  for($i=0;$i<3;++$i){
   $unit=new SqlTransaction($pdo,$clock,10000);
   $unit->run(static function()use($pdo,$unit,$clock,$mode,$i,$read,$restored,$sql):void{
    Check::same(true,$read()<=min(10,$restored));
    if($i===0&&$mode==='eviction'){for($j=0;$j<8;++$j){$unit->metadataRows('SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table LIMIT 1 /* owned_timeout_'.$j.' */',['table'=>'sosecurity_absent']);}}
    if($i===0&&$mode==='reentrant'){
     $clock->at=$clock->calls+3;$clock->hook=static function()use($pdo,$clock):void{$child=new SqlTransaction($pdo,new TestClock(),10000);$child->enlist(static function():void{});++$clock->entries;};
     $rows=$unit->metadataRows($sql);Check::same(1,count($rows));
    }
   });
   Check::same($restored,$read());
   if($i===0&&$mode==='changed-session'){$pdo->exec('SET SESSION innodb_lock_wait_timeout=7');$restored=7;}
   if($i===0&&$mode==='changed-database'){$pdo->exec('USE sosecurity_timeout_other');}
   if($mode==='fetch-settings'){if($i===0){$pdo->setAttribute(PDO::ATTR_CASE,PDO::CASE_UPPER);}if($i===1){$pdo->setAttribute(PDO::ATTR_STRINGIFY_FETCHES,true);}}
  }
  timeoutControl('SET GLOBAL general_log=OFF');
  $prepares=(int)timeoutControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='Prepare' AND argument='".$sql."'");
  $executes=(int)timeoutControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='Execute' AND argument='".$sql."'");
  $eligible=$supported&&get_class($pdo)===PDO::class&&$mode!=='unregistered'&&$pdo->getAttribute(PDO::ATTR_STATEMENT_CLASS)===[PDOStatement::class];
  $expectedExecute=$mode==='reentrant'?5:3;$expectedPrepare=$eligible?(in_array($mode,['eviction','reentrant'],true)?2:($mode==='fetch-settings'?3:1)):$expectedExecute;
  echo 'COUNTS timeout '.$mode.' prepare '.$prepares.' execute '.$executes.' eligible '.($eligible?'yes':'no').PHP_EOL;
  Check::same($expectedExecute,$executes);Check::same($expectedPrepare,$prepares);if($mode==='reentrant'){Check::same(1,$clock->entries);}
  $databaseProbes=(int)timeoutControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='Execute' AND argument='SELECT DATABASE()'");Check::same($mode==='eviction'&&$supported?8:0,$databaseProbes);
  echo 'PASS SQL lock timeout cache '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
 }
}finally{timeoutControl('SET GLOBAL general_log=OFF');if($other){timeoutControl('DROP DATABASE sosecurity_timeout_other');}}
