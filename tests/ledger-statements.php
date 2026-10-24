<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
Check::same('8M',ini_get('memory_limit'));
use SoSecurity\Account\Ledger;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlStateAccess;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function batchControl(string $sql):string{
 $pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned control unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}return trim($out);
}

class LedgerStatementAdapter extends PDOStatement {}
$modes=['native','raw-format','paged','different-param','changed-data','corrupt','body','permission','temporary','database','fetch-settings','statement-switch','unregistered','custom-clock','opaque-guard','eviction','invalid-context','transaction-boundary'];
$admin=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);$created=[];$clone=false;
try{
 $ddl=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-mysql.sql'));foreach(explode(';',$ddl) as $sql){if(trim($sql)!==''){$admin->exec($sql);if(preg_match('/CREATE TABLE\s+(\w+)/i',$sql,$match)){$created[]=$match[1];}}}
 foreach($modes as $mode){
 if(isset($argv[1])&&$argv[1]!==$mode){continue;}
 $directory=privateDirectory();mkdir($directory.'/witness',0700);$temporary=false;$reason=null;$callbacks=0;$pdo=null;$copyCheckpoint=null;
 try{
 $pdo=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);$supported=true;try{foreach([PDO::ATTR_CASE,PDO::ATTR_ORACLE_NULLS] as $attribute){$pdo->getAttribute($attribute);}}catch(Throwable $error){$supported=false;}
 $clock=$mode==='custom-clock'?new TestClock():new SoSecurity\Support\SystemClock();if($clock instanceof TestClock){$clock->time=time();}
 $site='owned-statements-'.$mode;$keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);$policy=new SoSecurity\Account\Policy(['maximum_entries'=>100]);$unit=new SqlTransaction($pdo,$clock,30000);$ledger=new Ledger($unit,$site,'tenant',str_repeat('e',64),$keys,$policy);$other=new Ledger($unit,$site,'other',str_repeat('e',64),$keys,$policy);$id=str_repeat('a',64);
 $unit->run(static function()use($ledger,$other,$clock,$id,$mode):void{$ledger->initialize();$ledger->put($id,str_repeat('b',64),'notice','owned-body',$clock->now()+3600);if($mode==='paged'){for($i=1;$i<=64;++$i){$ledger->put(str_pad(dechex($i),64,'0',STR_PAD_LEFT),str_repeat('b',64),'notice','owned-page-'.$i,$clock->now()+3600);}}$other->initialize();});
 $first=$unit->run(static function()use($ledger):array{return $ledger->checkpoint();});
 if($mode==='database'){
  batchControl("CREATE DATABASE sosecurity_statement_other; GRANT ALL ON sosecurity_statement_other.* TO 'sosecurity_test'@'localhost'");$clone=true;
  foreach($created as $table){$admin->exec('CREATE TABLE sosecurity_statement_other.'.$table.' LIKE sosecurity_test.'.$table);$admin->exec('INSERT INTO sosecurity_statement_other.'.$table.' SELECT * FROM sosecurity_test.'.$table);}
  $copy=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_statement_other','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);$copyUnit=new SqlTransaction($copy,$clock,30000);$copyLedger=new Ledger($copyUnit,$site,'tenant',str_repeat('e',64),$keys,$policy);$copyCheckpoint=$copyUnit->run(static function()use($copyLedger,$id,$clock):array{$copyLedger->put($id,str_repeat('b',64),'notice','owned-copy',$clock->now()+3600,1);return $copyLedger->checkpoint();});
 }
 $recordTypes=Ledger::recordTypes();$recordTypes['payload']='blob:16384';$definitions=['sosecurity_account_roots'=>['columns'=>Ledger::rootTypes(),'primary'=>['namespace'],'where'=>[],'maximum_rows'=>1000],'sosecurity_account_records'=>['columns'=>$recordTypes,'primary'=>['namespace','record_id'],'where'=>[],'maximum_rows'=>1000]];
 $source=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-statement-source',$definitions,30000);$witness=new SoSecurity\Account\LocalStateWitness($pdo,$directory.'/witness',$site,'tenant',str_repeat('e',64),$keys,$source,new SoSecurity\Account\LocalStatePersistence($directory.'/witness',30000),30000,2);$witness->initialize($source->digest());
 $boundary=new SoSecurity\Account\StateBoundary($witness,static function():bool{return true;});
 if($mode==='opaque-guard'){SqlStateAccess::bind($pdo,hash('sha256',$site),$boundary->binding(),static function()use($boundary):void{$boundary->assertActive();});}
 elseif($mode!=='unregistered'){SqlStateAccess::bind($pdo,hash('sha256',$site),$boundary->binding(),$boundary->sqlGuard($pdo),$boundary);}
 $q=$pdo->query('SELECT CONNECTION_ID()');$thread=(int)$q->fetchColumn();$q->closeCursor();$native=$unit->canBatchLedgerReads();$reuse=$supported&&$mode!=='unregistered'&&$native;$baseline=$source->digest();
 batchControl("SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");
 $boundary->run('owned.read',static function()use($unit,$ledger,$other,$pdo,$mode,$first,$id,$clock,$site,&$temporary,&$reason,&$callbacks,$copyCheckpoint,$thread,$reuse):void{
  try{
   if($mode==='transaction-boundary'){$unit->run(static function()use($ledger,$first):void{Check::same($first,$ledger->checkpoint());});$unit->run(static function()use($ledger,$first):void{Check::same($first,$ledger->checkpoint());});return;}
   $unit->run(static function()use($unit,$ledger,$other,$pdo,$mode,$first,$id,$clock,$site,&$temporary,&$callbacks,$copyCheckpoint,$thread,$reuse):void{
    Check::same($first,$ledger->checkpoint());
    if($mode==='paged'){Check::same(65,$first['entries']);Check::same('owned-body',$ledger->read($id)['payload']);}
    if($mode==='raw-format'){
     $sql=batchControl("SELECT argument FROM mysql.general_log WHERE thread_id=".$thread." AND command_type='Prepare' AND argument LIKE 'SELECT CASE WHEN %' AND argument LIKE '% AS h_body_length,%' ORDER BY event_time LIMIT 1");Check::same(true,strlen($sql)>100);$sql=str_replace('r.namespace=?','r.namespace=:namespace',$sql,$replacements);Check::same(1,$replacements);
     foreach([false,true] as $stringify){$unit->invoke(static function()use($pdo,$stringify,&$callbacks):void{++$callbacks;$pdo->setAttribute(PDO::ATTR_STRINGIFY_FETCHES,$stringify);},[],'test.format');$ledger->verifySchema();$rows=$unit->metadataRows($sql,['namespace'=>$first['namespace']],'sosecurity_test');Check::same(1,count($rows));$types=[];foreach($rows[0] as $name=>$value){$types[$name]=gettype($value);}echo 'RAW_TYPES '.($stringify?'stringify':'native').' '.json_encode($types).PHP_EOL;foreach($rows[0] as $value){Check::same(true,is_string($value)||$value===null);}}
    }
    if($mode==='different-param'){Check::same(0,$other->checkpoint()['entries']);Check::same($first,$ledger->checkpoint());return;}
    if($mode==='changed-data'){$unit->invoke(static function()use($ledger,$id,$clock,&$callbacks):void{++$callbacks;$ledger->put($id,str_repeat('b',64),'notice','owned-next',$clock->now()+3600,1);},[],'test.write');$next=$ledger->checkpoint();Check::same(true,$next['revision']>$first['revision']);Check::same('owned-next',$ledger->read($id)['payload']);Check::same(null,$ledger->readIfCheckpoint($id,$first));return;}
    if($mode==='body'){$ledger->readCheckpoint($id,static function()use($unit,$pdo,$first,$id,&$callbacks):void{$unit->invoke(static function()use($pdo,$first,$id,&$callbacks):void{++$callbacks;$q=$pdo->prepare("UPDATE sosecurity_account_records SET payload=REPEAT('x',length(payload)) WHERE namespace=? AND record_id=?");$q->execute([$first['namespace'],$id]);},[],'test.body');});throw new RuntimeException('Changed body returned');}
    if($mode==='corrupt'){$unit->invoke(static function()use($pdo,$first,$id,&$callbacks):void{++$callbacks;$q=$pdo->prepare('UPDATE sosecurity_account_records SET seal=? WHERE namespace=? AND record_id=?');$q->execute([str_repeat('0',64),$first['namespace'],$id]);},[],'test.corrupt');}
    if($mode==='permission'){$unit->invoke(static function()use(&$callbacks):void{++$callbacks;batchControl("REVOKE TRIGGER ON sosecurity_test.* FROM 'sosecurity_test'@'localhost'");},[],'test.permission');}
    if($mode==='temporary'){$unit->invoke(static function()use($pdo,&$temporary,&$callbacks):void{++$callbacks;$pdo->exec('CREATE TEMPORARY TABLE sosecurity_account_roots(x INT) ENGINE=InnoDB');$temporary=true;},[],'test.temporary');}
    if($mode==='database'){$unit->invoke(static function()use($pdo,&$callbacks):void{++$callbacks;$pdo->exec('USE sosecurity_statement_other');},[],'test.database');Check::same($copyCheckpoint,$ledger->checkpoint());$unit->invoke(static function()use($pdo,&$callbacks):void{++$callbacks;$pdo->exec('USE sosecurity_test');},[],'test.database');}
    if($mode==='fetch-settings'){$unit->invoke(static function()use($pdo,&$callbacks):void{++$callbacks;$pdo->setAttribute(PDO::ATTR_STRINGIFY_FETCHES,true);},[],'test.fetch');}
    if($mode==='statement-switch'){$unit->invoke(static function()use($pdo,&$callbacks):void{++$callbacks;$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[LedgerStatementAdapter::class]);},[],'test.statement');Check::same(false,$unit->canBatchLedgerReads());Check::same($first,$ledger->checkpoint());$unit->invoke(static function()use($pdo,&$callbacks):void{++$callbacks;$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[PDOStatement::class]);},[],'test.statement');}
    if($mode==='eviction'){
     $sql=batchControl("SELECT argument FROM mysql.general_log WHERE thread_id=".$thread." AND command_type='Prepare' AND argument LIKE 'SELECT CASE WHEN %' AND argument LIKE '% AS h_body_length,%' ORDER BY event_time LIMIT 1");$sql=str_replace('r.namespace=?','r.namespace=:namespace',$sql,$replacements);Check::same(1,$replacements);
     for($i=1;$i<=8;++$i){$variant=preg_replace('/ LIMIT 64 FOR UPDATE\z/D',' LIMIT '.$i.' FOR UPDATE',$sql,1,$replaced);Check::same(1,$replaced);$ledger->verifySchema();Check::same(1,count($unit->metadataRows($variant,['namespace'=>$first['namespace']],'sosecurity_test')));}
    }
    if($mode==='invalid-context'){
     foreach(['',str_repeat('d',257),"bad\0db"] as $database){Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($unit,$database):void{$unit->metadataRows('SELECT 1',[],$database);});}
     Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($unit):void{$unit->metadataRows('SELECT 1',[],'sosecurity_test');});
    }
    $beforeProbes=$mode==='native'?(int)batchControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$thread." AND command_type IN ('Query','Execute') AND argument='SELECT CAST(DATABASE() AS BINARY)'"):null;
    Check::same($first,$ledger->checkpoint());
    if($mode==='native'){$afterProbes=(int)batchControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$thread." AND command_type IN ('Query','Execute') AND argument='SELECT CAST(DATABASE() AS BINARY)'");Check::same($reuse?1:0,$afterProbes-$beforeProbes);echo 'CONTEXT_DATABASE_PROBES '.($afterProbes-$beforeProbes).PHP_EOL;}
   });
  }catch(SoSecurity\Exception\SecurityException|SoSecurity\Exception\ConfigurationException $error){$reason=$error->reason();}
  finally{if($pdo->inTransaction()){$pdo->rollBack();}if($temporary){$pdo->exec('DROP TEMPORARY TABLE sosecurity_account_roots');$temporary=false;}if($mode==='permission'){batchControl("GRANT ALL ON sosecurity_test.* TO 'sosecurity_test'@'localhost'");}$pdo->exec('USE sosecurity_test');$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[PDOStatement::class]);$pdo->setAttribute(PDO::ATTR_STRINGIFY_FETCHES,false);}
 });batchControl('SET GLOBAL general_log=OFF');
 $expected=in_array($mode,['body','corrupt'],true)?'account.corrupt':($mode==='permission'?'configuration.sql_schema':($mode==='temporary'?'sql.unavailable':null));Check::same($expected,$reason);
 $filter=" FROM mysql.general_log WHERE thread_id=".$thread." AND argument LIKE 'SELECT CASE WHEN %' AND argument LIKE '% AS h_body_length,%'";
 if($mode==='eviction'){$filter.=" AND argument LIKE '% LIMIT 64 FOR UPDATE'";}
 $prepares=(int)batchControl("SELECT COUNT(*)".$filter." AND command_type='Prepare'");$executes=(int)batchControl("SELECT COUNT(*)".$filter." AND command_type='Execute'");$databases=(int)batchControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$thread." AND command_type IN ('Query','Execute') AND argument='SELECT CAST(DATABASE() AS BINARY)'");
 echo 'COUNTS '.$mode.' prepared '.$prepares.' execute '.$executes.' database_query '.$databases.' reuse '.($reuse?'yes':'no').PHP_EOL;
 if(in_array($mode,['native','raw-format','paged','different-param','permission','temporary','database','fetch-settings','unregistered','custom-clock','opaque-guard','eviction','invalid-context','transaction-boundary'],true)){
  $expectedExec=!$native?0:(in_array($mode,['permission','temporary'],true)?1:($mode==='raw-format'?4:(in_array($mode,['database','different-param','paged'],true)?3:2)));$expectedPrepare=$expectedExec;
  if($reuse){$expectedPrepare=in_array($mode,['database','eviction'],true)?2:1;}
  Check::same($expectedExec,$executes);Check::same($expectedPrepare,$prepares);
 }
 if(in_array($mode,['corrupt','body'],true)){Check::same(2,$executes);Check::same($reuse?1:2,$prepares);}
 if($mode==='changed-data'&&$reuse){Check::same(true,$prepares<$executes);}
 $poolProperty=new ReflectionProperty(SqlStateAccess::class,'metadata');if(PHP_VERSION_ID<80100){$poolProperty->setAccessible(true);}$pools=$poolProperty->getValue();$pool=$pools[spl_object_hash($pdo)]['statements']??[];Check::same(true,count($pool)<=8);foreach($pool as $statement){Check::same(PDOStatement::class,get_class($statement));}echo 'POOL_SIZE '.$mode.' '.count($pool).PHP_EOL;
 Check::same(in_array($mode,['body','corrupt','permission','temporary','changed-data','fetch-settings'],true)?1:(in_array($mode,['database','statement-switch','raw-format'],true)?2:0),$callbacks);
 Check::same('current',$witness->inspect(static function():bool{return true;})['status']);if($mode!=='changed-data'){Check::same($baseline,$source->digest());}Check::same(false,$pdo->inTransaction());echo 'MEMORY '.$mode.' used '.memory_get_peak_usage(false).' allocated '.memory_get_peak_usage(true).PHP_EOL;Check::same(true,memory_get_peak_usage(false)<=8388608);Check::same(true,memory_get_peak_usage(true)<=8388608);echo 'PASS ledger statements '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
 }finally{batchControl('SET GLOBAL general_log=OFF');if($pdo!==null){if($pdo->inTransaction()){$pdo->rollBack();}if($temporary){$pdo->exec('DROP TEMPORARY TABLE sosecurity_account_roots');}}cleanDirectory($directory.'/witness');cleanDirectory($directory);}
 }
}finally{batchControl('SET GLOBAL general_log=OFF');batchControl("GRANT ALL ON sosecurity_test.* TO 'sosecurity_test'@'localhost'");if($clone){batchControl('DROP DATABASE sosecurity_statement_other');}foreach(array_reverse($created) as $table){$admin->exec('DROP TABLE '.$table);}}
