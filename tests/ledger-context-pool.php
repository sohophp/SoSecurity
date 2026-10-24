<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Exception\ConfigurationException;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function contextPoolControl(string $sql):string{$pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned control unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}return trim($out);}
class ContextPoolAdapter extends PDO{}
class ContextPoolStatement extends PDOStatement{}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$admin=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=[];$failures=[];
try{
 foreach(explode(';',preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-mysql.sql'))) as $ddl){if(trim($ddl)!==''){$admin->exec($ddl);if(preg_match('/CREATE TABLE\s+(\w+)/i',$ddl,$m)){$created[]=$m[1];}}}
 $admin->exec('CREATE TABLE sosecurity_context_pool(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created[]='sosecurity_context_pool';contextPoolControl("CREATE DATABASE sosecurity_pool_other; GRANT ALL ON sosecurity_pool_other.* TO 'sosecurity_test'@'localhost'");foreach(['roots','records'] as $part){$admin->exec('CREATE TABLE sosecurity_pool_other.sosecurity_account_'.$part.' LIKE sosecurity_test.sosecurity_account_'.$part);}
 $modes=['warm','databases','temporary-roots','temporary-records','durability','trigger-permission','select-roots','select-records','trigger','fetch-mode','unregistered','custom-clock','custom-pdo','custom-statement','opaque','mdl'];if(($argv[1]??'')==='mdl-only'){$modes=['mdl'];}
 foreach($modes as $mode){
  $directory=privateDirectory();mkdir($directory.'/witness',0700);
  if(strpos($mode,'select-')===0){contextPoolControl("REVOKE SELECT ON sosecurity_test.* FROM 'sosecurity_test'@'localhost'; GRANT SELECT ON sosecurity_test.sosecurity_account_roots TO 'sosecurity_test'@'localhost'; GRANT SELECT ON sosecurity_test.sosecurity_account_records TO 'sosecurity_test'@'localhost'; GRANT SELECT ON sosecurity_test.sosecurity_context_pool TO 'sosecurity_test'@'localhost'");}
  $pdo=$mode==='custom-pdo'?new ContextPoolAdapter($dsn,'sosecurity_test','integration-only',$options):new PDO($dsn,'sosecurity_test','integration-only',$options);if($mode==='custom-statement'){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[ContextPoolStatement::class]);}$clock=$mode==='custom-clock'?new TestClock():new SoSecurity\Support\SystemClock();$keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);
  $source=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-context-pool',['sosecurity_context_pool'=>['columns'=>['id'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>2]],10000);$witness=new SoSecurity\Account\LocalStateWitness($pdo,$directory.'/witness','owned-context-pool','tenant',str_repeat('e',64),$keys,$source,new SoSecurity\Account\LocalStatePersistence($directory.'/witness',10000),10000,2);$witness->initialize($source->digest());$boundary=new SoSecurity\Account\StateBoundary($witness,static function():bool{return true;});
  if($mode==='opaque'){SqlStateAccess::bind($pdo,hash('sha256','owned-context-pool-'.$mode),$boundary->binding(),static function():void{});}elseif($mode!=='unregistered'){SqlStateAccess::bind($pdo,hash('sha256','owned-context-pool-'.$mode),$boundary->binding(),$boundary->sqlGuard($pdo),$boundary);}
  $unit=new SqlTransaction($pdo,$clock,10000);$q=$pdo->query('SELECT CONNECTION_ID()');$id=(int)$q->fetchColumn();$q->closeCursor();$trigger=false;$temporary=null;$denials=0;$prepares=null;$fallbackPrepares=null;
  try{$boundary->run('owned.pool.'.$mode,static function()use($pdo,$admin,$unit,$mode,$id,&$trigger,&$temporary,&$denials,&$prepares,&$fallbackPrepares):void{
   $unit->run(static function()use($pdo,$unit,$mode,$id,&$temporary,&$denials,&$prepares,&$fallbackPrepares):void{
    contextPoolControl("SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");
    Check::same(['database'=>'sosecurity_test'],SqlSchema::ledgerSchemaContext($unit));Check::same(['database'=>'sosecurity_test'],SqlSchema::ledgerSchemaContext($unit));contextPoolControl('SET GLOBAL general_log=OFF');
    $prepares=(int)contextPoolControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='Prepare' AND argument LIKE 'SELECT _sosecurity_context.%'");
    $fallbackPrepares=(int)contextPoolControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='Prepare' AND argument LIKE 'SELECT 0 AS position,%'");
    if($mode==='databases'){$unit->invoke(static function()use($pdo):void{$pdo->exec('USE sosecurity_pool_other');},[],'test.use');Check::same(['database'=>'sosecurity_pool_other'],SqlSchema::ledgerSchemaContext($unit));$unit->invoke(static function()use($pdo):void{$pdo->exec('USE sosecurity_test');},[],'test.use');Check::same(['database'=>'sosecurity_test'],SqlSchema::ledgerSchemaContext($unit));}
    if(strpos($mode,'temporary-')===0){$temporary='sosecurity_account_'.substr($mode,10);$unit->invoke(static function()use($pdo,$temporary):void{$pdo->exec('CREATE TEMPORARY TABLE '.$temporary.'(id INT) ENGINE=InnoDB');},[],'test.shadow');try{SqlSchema::ledgerSchemaContext($unit);}catch(PDOException $e){++$denials;}$unit->invoke(static function()use($pdo,$temporary):void{$pdo->exec('DROP TEMPORARY TABLE '.$temporary);},[],'test.shadow');$temporary=null;Check::same(['database'=>'sosecurity_test'],SqlSchema::ledgerSchemaContext($unit));}
    if($mode==='durability'){foreach([0,2] as $value){contextPoolControl('SET GLOBAL innodb_flush_log_at_trx_commit='.$value);try{SqlSchema::ledgerSchemaContext($unit);}catch(ConfigurationException $e){Check::same('configuration.sql_durability',$e->reason());++$denials;}contextPoolControl('SET GLOBAL innodb_flush_log_at_trx_commit=1');Check::same(['database'=>'sosecurity_test'],SqlSchema::ledgerSchemaContext($unit));}}
    if($mode==='trigger-permission'){contextPoolControl("REVOKE TRIGGER ON sosecurity_test.* FROM 'sosecurity_test'@'localhost'");try{SqlSchema::ledgerSchemaContext($unit);}catch(ConfigurationException $e){Check::same('configuration.sql_schema',$e->reason());++$denials;}contextPoolControl("GRANT ALL ON sosecurity_test.* TO 'sosecurity_test'@'localhost'");Check::same(['database'=>'sosecurity_test'],SqlSchema::ledgerSchemaContext($unit));}
    if(strpos($mode,'select-')===0){contextPoolControl("REVOKE SELECT ON sosecurity_test.sosecurity_account_".substr($mode,7)." FROM 'sosecurity_test'@'localhost'");try{SqlSchema::ledgerSchemaContext($unit);}catch(PDOException $e){++$denials;}contextPoolControl("GRANT SELECT ON sosecurity_test.sosecurity_account_".substr($mode,7)." TO 'sosecurity_test'@'localhost'");Check::same(['database'=>'sosecurity_test'],SqlSchema::ledgerSchemaContext($unit));}
    if($mode==='fetch-mode'){foreach([true,false] as $stringify){$unit->invoke(static function()use($pdo,$stringify):void{$pdo->setAttribute(PDO::ATTR_STRINGIFY_FETCHES,$stringify);},[],'test.fetch');Check::same(['database'=>'sosecurity_test'],SqlSchema::ledgerSchemaContext($unit));}}
   });
   if($mode==='mdl'){
    // The first unit has committed: this second unit must reuse its statement and acquire fresh MDL.
    contextPoolControl('SET GLOBAL general_log=ON');
    $unit->run(static function()use($unit,$admin):void{
     Check::same(['database'=>'sosecurity_test'],SqlSchema::ledgerSchemaContext($unit));$admin->exec('SET SESSION lock_wait_timeout=1');
     foreach(['roots','records'] as $part){$locked=false;try{$admin->exec('ALTER TABLE sosecurity_account_'.$part.' ADD owned_context_pool_lock INT');}catch(PDOException $e){$locked=isset($e->errorInfo[1])&&(int)$e->errorInfo[1]===1205;}Check::same(true,$locked);}
    });
    contextPoolControl('SET GLOBAL general_log=OFF');$allPrepares=(int)contextPoolControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='Prepare' AND argument LIKE 'SELECT _sosecurity_context.%'");Check::same(1,$allPrepares);
   }
   if($mode==='trigger'){
    $pdo->exec('CREATE TRIGGER owned_context_pool BEFORE INSERT ON sosecurity_account_records FOR EACH ROW SET NEW.revision=NEW.revision');$trigger=true;
    try{$unit->run(static function()use($unit):void{SqlSchema::ledgerSchemaContext($unit);});}catch(ConfigurationException $e){Check::same('configuration.sql_schema',$e->reason());++$denials;}
    $pdo->exec('DROP TRIGGER owned_context_pool');$trigger=false;
   }
  });
  $expectedDenials=$mode==='durability'?2:(in_array($mode,['temporary-roots','temporary-records','trigger-permission','select-roots','select-records','trigger'],true)?1:0);$fallback=in_array($mode,['custom-clock','custom-pdo','custom-statement','opaque'],true);$expectedPrepares=$fallback?0:($mode==='unregistered'?2:1);
  echo 'OBSERVATION context pool '.json_encode(['mode'=>$mode,'prepares'=>$prepares,'fallback_prepares'=>$fallbackPrepares,'denials'=>$denials,'php'=>PHP_VERSION]).PHP_EOL;
  try{Check::same($expectedPrepares,$prepares);Check::same($fallback?2:0,$fallbackPrepares);Check::same($expectedDenials,$denials);Check::same(false,$pdo->inTransaction());echo 'PASS context pool '.$mode.' PHP '.PHP_VERSION.PHP_EOL;}catch(Throwable $e){$failures[]=$mode;echo 'FAIL context pool '.$mode.' '.$e->getMessage().PHP_EOL;}
  }finally{
   contextPoolControl('SET GLOBAL general_log=OFF; SET GLOBAL innodb_flush_log_at_trx_commit=1');if($pdo->inTransaction()){$pdo->rollBack();}$pdo->exec('USE sosecurity_test');if($temporary!==null){$pdo->exec('DROP TEMPORARY TABLE '.$temporary);}if($trigger){$pdo->exec('DROP TRIGGER owned_context_pool');}
   if(strpos($mode,'select-')===0){contextPoolControl("REVOKE SELECT ON sosecurity_test.sosecurity_account_roots FROM 'sosecurity_test'@'localhost'; REVOKE SELECT ON sosecurity_test.sosecurity_account_records FROM 'sosecurity_test'@'localhost'; REVOKE SELECT ON sosecurity_test.sosecurity_context_pool FROM 'sosecurity_test'@'localhost'; GRANT ALL ON sosecurity_test.* TO 'sosecurity_test'@'localhost'");}
   $unit=null;$boundary=null;$witness=null;$source=null;$pdo=null;cleanDirectory($directory.'/witness');cleanDirectory($directory);
  }
 }
}finally{contextPoolControl('SET GLOBAL general_log=OFF; SET GLOBAL innodb_flush_log_at_trx_commit=1; DROP DATABASE sosecurity_pool_other');foreach(array_reverse($created) as $table){$admin->exec('DROP TABLE '.$table);}}
if($failures){throw new RuntimeException('Context pool cases failed: '.implode(',',$failures));}echo 'PASS context pool complete '.count($modes).' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
