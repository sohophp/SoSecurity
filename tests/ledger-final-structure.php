<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ConfigurationException;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function finalStructureControl(string $sql):string{$pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned control unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}return trim($out);}
class FinalStructureStatement extends PDOStatement{}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$admin=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=[];$failures=[];$rows=[];
try{
 foreach(explode(';',preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-mysql.sql'))) as $ddl){if(trim($ddl)!==''){$admin->exec($ddl);if(preg_match('/CREATE TABLE\s+(\w+)/i',$ddl,$m)){$created[]=$m[1];}}}
 finalStructureControl("CREATE DATABASE sosecurity_final_other; GRANT ALL ON sosecurity_final_other.* TO 'sosecurity_test'@'localhost'");
 foreach(['roots','records'] as $part){$admin->exec('CREATE TABLE sosecurity_final_other.sosecurity_account_'.$part.' LIKE sosecurity_test.sosecurity_account_'.$part);}
 $admin->exec('ALTER TABLE sosecurity_final_other.sosecurity_account_roots MODIFY revision VARBINARY(8) NOT NULL');
 $admin->exec('CREATE TABLE sosecurity_final_structure(id INT NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created[]='sosecurity_final_structure';
 foreach(['owned','enlisted'] as $ownership){foreach(['normal','clock','statement','generic','database','spoof-before','spoof-final','temporary-roots','temporary-records','trigger','select-roots','select-records','trigger-permission','durable','transaction-lost'] as $mode){
  if(strpos($mode,'spoof-')===0){$admin->exec('ALTER TABLE sosecurity_account_roots MODIFY revision VARBINARY(8) NOT NULL');}
  if(strpos($mode,'select-')===0){finalStructureControl("REVOKE SELECT ON sosecurity_test.* FROM 'sosecurity_test'@'localhost'; GRANT SELECT ON sosecurity_test.sosecurity_account_roots TO 'sosecurity_test'@'localhost'; GRANT SELECT ON sosecurity_test.sosecurity_account_records TO 'sosecurity_test'@'localhost'");}
  $pdo=new PDO($dsn,'sosecurity_test','integration-only',$options);$clock=$mode==='clock'?new TestClock():new SoSecurity\Support\SystemClock();$unit=new SqlTransaction($pdo,$clock,10000);$q=$pdo->query('SELECT CONNECTION_ID()');$id=(int)$q->fetchColumn();$q->closeCursor();$reason=null;$callback=0;$temporary=null;$genericChecks=0;$bodyEffect=0;
  finalStructureControl("SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");
  $body=static function()use($unit,$mode,&$genericChecks,&$bodyEffect):void{
   if(strpos($mode,'spoof-')===0){$unit->verifySchema('account-ledger-v1',static function():void{},static function():array{return ['database'=>'sosecurity_test'];});if($mode==='spoof-final'){return;}}
   $unit->verifyLedgerSchema();$unit->verifyLedgerSchema();if($mode==='spoof-before'){++$bodyEffect;}
   if($mode==='generic'){for($i=0;$i<2;++$i){$unit->verifySchema('owned-generic',static function()use(&$genericChecks):void{++$genericChecks;});}}
  };
  $finish=static function()use($unit,$mode,$pdo,$admin,&$callback,&$temporary,&$genericChecks):void{
   ++$callback;
   if(strpos($mode,'temporary-')===0){$temporary='sosecurity_account_'.substr($mode,10);$pdo->exec('CREATE TEMPORARY TABLE '.$temporary.'(id INT) ENGINE=InnoDB');}
   elseif($mode==='trigger'){$pdo->exec('CREATE TRIGGER owned_final_structure BEFORE INSERT ON sosecurity_account_records FOR EACH ROW SET NEW.revision=NEW.revision');}
   elseif(strpos($mode,'select-')===0){finalStructureControl("REVOKE SELECT ON sosecurity_test.sosecurity_account_".substr($mode,7)." FROM 'sosecurity_test'@'localhost'");}
   elseif($mode==='database'){$pdo->exec('USE sosecurity_final_other');}
   elseif($mode==='trigger-permission'){finalStructureControl("REVOKE TRIGGER ON sosecurity_test.* FROM 'sosecurity_test'@'localhost'");}
   elseif($mode==='durable'){finalStructureControl('SET GLOBAL innodb_flush_log_at_trx_commit=0');}
   elseif($mode==='transaction-lost'){$pdo->commit();$pdo->beginTransaction();}
   elseif($mode==='statement'){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[FinalStructureStatement::class]);}
   $unit->verifyLedgerSchema();if($mode==='generic'){$unit->verifySchema('owned-generic',static function()use(&$genericChecks):void{++$genericChecks;});}
  };
  try{if($ownership==='enlisted'){$pdo->beginTransaction();$unit->enlist($body,null,$finish);}else{$unit->run($body,null,$finish);}}
  catch(SecurityException|ConfigurationException $e){$reason=$e->reason();}
  finally{
   finalStructureControl('SET GLOBAL general_log=OFF; SET GLOBAL innodb_flush_log_at_trx_commit=1');
   if($pdo->inTransaction()){$pdo->rollBack();}$pdo->exec('USE sosecurity_test');if($temporary!==null){$pdo->exec('DROP TEMPORARY TABLE '.$temporary);}
   if($mode==='trigger'){$admin->exec('DROP TRIGGER owned_final_structure');}if(strpos($mode,'spoof-')===0){$admin->exec('ALTER TABLE sosecurity_account_roots MODIFY revision BIGINT UNSIGNED NOT NULL');}
   if(strpos($mode,'select-')===0){finalStructureControl("REVOKE SELECT ON sosecurity_test.sosecurity_account_".($mode==='select-roots'?'records':'roots')." FROM 'sosecurity_test'@'localhost'; GRANT ALL ON sosecurity_test.* TO 'sosecurity_test'@'localhost'");}
   if($mode==='trigger-permission'){finalStructureControl("GRANT ALL ON sosecurity_test.* TO 'sosecurity_test'@'localhost'");}
  }
  $ddl=(int)finalStructureControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='Execute' AND argument LIKE '%information_schema.COLUMNS%' AND argument LIKE '%sosecurity_account_roots%'");
  $expected=in_array($mode,['normal','clock','statement','generic'],true)?null:($mode==='durable'?'configuration.sql_durability':(in_array($mode,['trigger-permission','database','spoof-before','spoof-final'],true)?'configuration.sql_schema':(in_array($mode,['transaction-lost','trigger'],true)?'sql.cleanup':'sql.unavailable')));
  $observed=['ownership'=>$ownership,'mode'=>$mode,'reason'=>$reason,'ddl_checks'=>$ddl,'callback'=>$callback,'body_effect'=>$bodyEffect];$rows[]=$observed;echo 'OBSERVATION final structure '.json_encode($observed).PHP_EOL;
  try{Check::same($expected,$reason);Check::same($mode==='spoof-before'?0:1,$callback);Check::same(0,$bodyEffect);if($mode==='normal'){Check::same(1,$ddl);}if($mode==='clock'){Check::same(3,$ddl);}if($mode==='statement'){Check::same(2,$ddl);}if($mode==='generic'){Check::same(2,$genericChecks);}Check::same(0,(int)$admin->query('SELECT COUNT(*) FROM sosecurity_final_structure')->fetchColumn());echo 'PASS final ledger structure '.$ownership.' '.$mode.' PHP '.PHP_VERSION.PHP_EOL;}catch(Throwable $e){$failures[]=$ownership.' '.$mode;echo 'FAIL final ledger structure '.$ownership.' '.$mode.' '.$e->getMessage().PHP_EOL;}
 }}
}finally{finalStructureControl('SET GLOBAL general_log=OFF; SET GLOBAL innodb_flush_log_at_trx_commit=1');if(isset($pdo)&&$pdo->inTransaction()){$pdo->rollBack();}foreach(array_reverse($created) as $table){$admin->exec('DROP TABLE '.$table);}finalStructureControl('DROP DATABASE sosecurity_final_other');}
if($failures){throw new RuntimeException('Final ledger structure cases failed: '.implode(',',$failures));}
echo 'PASS final structure complete '.count($rows).' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
