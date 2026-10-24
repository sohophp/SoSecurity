<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlStateAccess;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function batchControl(string $sql):string{
 $pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned control unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}return trim($out);
}

class ContextAdapter extends PDO {}
class ContextStatement extends PDOStatement {}
$modes=['native','custom-clock','pdo-adapter','statement-adapter','opaque-guard','temporary-roots','temporary-records','trigger','permission-roots','permission-records','permission-trigger','database','mdl'];
$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$admin=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=[];$other=false;
try{
 foreach(explode(';',preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-mysql.sql'))) as $ddl){if(trim($ddl)===''){continue;}$admin->exec($ddl);if(preg_match('/CREATE TABLE\s+(\w+)/i',$ddl,$match)){$created[]=$match[1];}}
 foreach($modes as $mode){
 if(isset($argv[1])&&$argv[1]!==$mode){continue;}$temporary=null;$reason=null;$calls=0;
 try{
  if(in_array($mode,['permission-roots','permission-records'],true)){batchControl("REVOKE SELECT ON sosecurity_test.* FROM 'sosecurity_test'@'localhost'; GRANT SELECT ON sosecurity_test.sosecurity_account_".($mode==='permission-roots'?'roots':'records')." TO 'sosecurity_test'@'localhost'");}
  $pdo=$mode==='pdo-adapter'?new ContextAdapter($dsn,'sosecurity_test','integration-only',$options):new PDO($dsn,'sosecurity_test','integration-only',$options);
  if($mode==='statement-adapter'){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[ContextStatement::class]);}
  if($mode==='opaque-guard'){SqlStateAccess::bind($pdo,hash('sha256','owned-context'),hash('sha256','owned-context-binding'),static function():void{});}
  if(strpos($mode,'temporary-')===0){$temporary='sosecurity_account_'.substr($mode,10);$pdo->exec('CREATE TEMPORARY TABLE '.$temporary.'(x INT) ENGINE=InnoDB');}
  if($mode==='trigger'){$admin->exec('CREATE TRIGGER owned_context_trigger BEFORE INSERT ON sosecurity_account_records FOR EACH ROW SET NEW.revision=NEW.revision');}
  if($mode==='database'){batchControl("CREATE DATABASE sosecurity_context_other; GRANT ALL ON sosecurity_context_other.* TO 'sosecurity_test'@'localhost'");$other=true;foreach($created as $table){$admin->exec('CREATE TABLE sosecurity_context_other.'.$table.' LIKE sosecurity_test.'.$table);}}
  $clock=$mode==='custom-clock'?new TestClock():new SoSecurity\Support\SystemClock();$unit=new SqlTransaction($pdo,$clock,30000);$native=$unit->canBatchLedgerReads();$q=$pdo->query('SELECT CONNECTION_ID()');$thread=(int)$q->fetchColumn();$q->closeCursor();batchControl("SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");
  try{$unit->run(static function()use($unit,$mode,$pdo,$admin,&$calls):void{
   $first=SqlSchema::ledgerSchemaContext($unit);Check::same(['database'=>'sosecurity_test'],$first);++$calls;
   if($mode==='permission-trigger'){$unit->invoke(static function():void{batchControl("REVOKE TRIGGER ON sosecurity_test.* FROM 'sosecurity_test'@'localhost'");},[],'test.revoke');}
   if($mode==='database'){$unit->invoke(static function()use($pdo):void{$pdo->exec('USE sosecurity_context_other');},[],'test.database');Check::same(['database'=>'sosecurity_context_other'],SqlSchema::ledgerSchemaContext($unit));$unit->invoke(static function()use($pdo):void{$pdo->exec('USE sosecurity_test');},[],'test.database');}
   Check::same($first,SqlSchema::ledgerSchemaContext($unit));++$calls;
   if($mode==='mdl'){$admin->exec('SET SESSION lock_wait_timeout=1');foreach(['roots','records'] as $part){$locked=false;try{$admin->exec('ALTER TABLE sosecurity_account_'.$part.' ADD owned_context_lock INT');}catch(PDOException $error){$locked=isset($error->errorInfo[1])&&(int)$error->errorInfo[1]===1205;}Check::same(true,$locked);}}
  });}catch(SoSecurity\Exception\SecurityException|SoSecurity\Exception\ConfigurationException $error){$reason=$error->reason();}
  batchControl('SET GLOBAL general_log=OFF');$expected=in_array($mode,['trigger','permission-trigger'],true)?'configuration.sql_schema':(in_array($mode,['temporary-roots','temporary-records','permission-roots','permission-records'],true)?'sql.unavailable':null);Check::same($expected,$reason);Check::same($mode==='permission-trigger'?1:($expected===null?2:0),$calls);
  $count=(int)batchControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$thread." AND command_type='Execute' AND (argument LIKE '%_sosecurity_left_0%' OR argument LIKE 'SELECT 0 AS position,%')");echo 'COUNTS context '.$mode.' '.$count.' native '.($native?'yes':'no').PHP_EOL;
  if($expected===null){Check::same(($mode==='database'?3:2)*($native?1:2),$count);}
  Check::same(false,$pdo->inTransaction());echo 'PASS ledger context '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
 }finally{batchControl('SET GLOBAL general_log=OFF');if(isset($pdo)){if($pdo->inTransaction()){$pdo->rollBack();}if($temporary!==null){$pdo->exec('DROP TEMPORARY TABLE '.$temporary);}$pdo->exec('USE sosecurity_test');}if($mode==='trigger'){$admin->exec('DROP TRIGGER owned_context_trigger');}if(in_array($mode,['permission-roots','permission-records'],true)){batchControl("REVOKE SELECT ON sosecurity_test.sosecurity_account_".($mode==='permission-roots'?'roots':'records')." FROM 'sosecurity_test'@'localhost'");}if(strpos($mode,'permission-')===0){batchControl("GRANT ALL ON sosecurity_test.* TO 'sosecurity_test'@'localhost'");}}
 }
}finally{batchControl('SET GLOBAL general_log=OFF');if($other){batchControl('DROP DATABASE sosecurity_context_other');}foreach(array_reverse($created) as $table){$admin->exec('DROP TABLE '.$table);}}
