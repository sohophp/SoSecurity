<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Account\Ledger;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$admin=new PDO($dsn,'sosecurity_test','integration-only',$options);$pdo=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=[];
try{
 foreach(explode(';',preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-mysql.sql'))) as $ddl){if(trim($ddl)!==''){$admin->exec($ddl);if(preg_match('/CREATE TABLE\s+(\w+)/i',$ddl,$m)){$created[]=$m[1];}}}
 // This private method only constructs fixed SQL text. Reflection supplies no permission or state change.
 $factory=new ReflectionMethod(SqlSchema::class,'mysqlLedgerVisibilitySql');if(PHP_VERSION_ID<80100){$factory->setAccessible(true);}$visibility=$factory->invoke(null);
 $resolution='SELECT 1 FROM `sosecurity_account_roots` AS _sosecurity_left_0 JOIN `sosecurity_account_roots` AS _sosecurity_right_0 ON 1=0 JOIN `sosecurity_account_records` AS _sosecurity_left_1 ON 1=0 JOIN `sosecurity_account_records` AS _sosecurity_right_1 ON 1=0 LIMIT 0';
 $context='SELECT _sosecurity_context.* FROM ('.$visibility.') AS _sosecurity_context LEFT JOIN ('.$resolution.') AS _sosecurity_resolution ON 1=0 ORDER BY _sosecurity_context.position';
 $parameters=['context_0_visibility_table'=>'sosecurity_account_roots','context_0_visibility_trigger_table'=>'sosecurity_account_roots','context_1_visibility_table'=>'sosecurity_account_records','context_1_visibility_trigger_table'=>'sosecurity_account_records'];
 $recordTypes=Ledger::recordTypes();unset($recordTypes['payload']);
 $projection=SqlSchema::boundedProjection('mysql',Ledger::rootTypes(),'r','r_',true).','.SqlSchema::boundedProjection('mysql',$recordTypes,'h','h_',true).',CAST('.SqlSchema::blobLength('mysql','payload','h')." AS CHAR) AS h_body_length,CASE WHEN h.namespace IS NULL THEN '0' ELSE '1' END AS has_record";
 $rootSql='SELECT '.$projection.' FROM sosecurity_account_roots r LEFT JOIN sosecurity_account_records h ON h.namespace=r.namespace WHERE r.namespace=:namespace ORDER BY h.record_id LIMIT 64 FOR UPDATE';
 $contextFields=['position','database_name','identity','ledger_durable','scoped','unrestricted','has_trigger'];$rootFields=[];
 foreach(array_keys(Ledger::rootTypes()) as $n){$rootFields[]='r_'.$n;}foreach(array_keys($recordTypes) as $n){$rootFields[]='h_'.$n;}$rootFields[]='h_body_length';$rootFields[]='has_record';
 $combined="SELECT 'context' AS section,c.*,".implode(',',array_map(static function(string $n):string{return 'NULL AS '.$n;},$rootFields)).' FROM ('.$context.") c UNION ALL SELECT 'ledger',".implode(',',array_fill(0,count($contextFields),'NULL')).',d.* FROM ('.$rootSql.') d ORDER BY section,position,h_record_id';
 Check::same(true,strlen($combined)<=16384);
 $bufferAttribute=PHP_VERSION_ID>=80500?\Pdo\Mysql::ATTR_USE_BUFFERED_QUERY:PDO::MYSQL_ATTR_USE_BUFFERED_QUERY;
 $clock=new SoSecurity\Support\SystemClock();$keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);$policy=new SoSecurity\Account\Policy(['maximum_entries'=>100]);$unit=new SqlTransaction($pdo,$clock,30000);
 foreach(['empty'=>0,'small'=>3,'paged'=>65,'absent'=>null] as $mode=>$count){
  $site='owned-context-root-'.$mode;$ledger=new Ledger($unit,$site,'tenant',str_repeat('e',64),$keys,$policy);$namespace=hash('sha256',json_encode(['SoSecurity.Account.Ledger.1',$site,'tenant',str_repeat('e',64)],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
  if($count!==null){$unit->run(static function()use($ledger,$count,$clock):void{$ledger->initialize();for($i=1;$i<=$count;++$i){$ledger->put(str_pad(dechex($i),64,'0',STR_PAD_LEFT),str_repeat('b',64),'notice','owned-'.$i,$clock->now()+3600);}});}
  $unit->run(static function()use($unit,$pdo,$admin,$ledger,$count,$mode,$namespace,$parameters,$context,$rootSql,$combined,$contextFields,$rootFields,$bufferAttribute):void{
   if($count!==null){Check::same($count,$ledger->checkpoint()['entries']);}
   $baselineContext=$pdo->prepare($context);$baselineContext->execute($parameters);$expectedContext=$baselineContext->fetchAll(PDO::FETCH_ASSOC);$baselineContext->closeCursor();
   $baselineRoot=$pdo->prepare($rootSql);$baselineRoot->execute(['namespace'=>$namespace]);$expectedRoot=$baselineRoot->fetchAll(PDO::FETCH_ASSOC);$baselineRoot->closeCursor();
   foreach([false,true] as $stringify){foreach([true,false] as $buffered){
    $pdo->setAttribute(PDO::ATTR_STRINGIFY_FETCHES,$stringify);$pdo->setAttribute($bufferAttribute,$buffered);
    $q=$pdo->prepare($combined);$q->execute($parameters+['namespace'=>$namespace]);$rows=$q->fetchAll(PDO::FETCH_ASSOC);Check::same(true,$q->closeCursor());$c=[];$r=[];
    foreach($rows as $row){Check::same(count($contextFields)+count($rootFields)+1,count($row));if($row['section']==='context'){$part=[];foreach($contextFields as $name){$part[$name]=$row[$name];}$c[]=$part;}else{Check::same('ledger',$row['section']);$part=[];foreach($rootFields as $name){$part[$name]=$row[$name];}$r[]=$part;}}
    $text=static function(array $rows):array{return array_map(static function(array $row):array{return array_map(static function($v){return $v===null?null:(string)$v;},$row);},$rows);};
    Check::same($text($expectedContext),$text($c));Check::same($text($expectedRoot),$text($r));Check::same(2+count($expectedRoot),count($rows));Check::same(true,count($rows)<=66);
   }}
   $pdo->setAttribute(PDO::ATTR_STRINGIFY_FETCHES,false);$pdo->setAttribute($bufferAttribute,true);
   if($mode==='small'){
    // Compare only transport/parser cost for the same fixed bounded reads; no full API timing claim.
    $timer=static function():float{return function_exists('hrtime')?hrtime(true)/1000000000:microtime(true);};$durations=[];
    foreach(['separate','combined','combined','separate'] as $variant){$at=$timer();for($i=0;$i<32;++$i){if($variant==='separate'){$q=$pdo->prepare($context);$q->execute($parameters);$q->fetchAll(PDO::FETCH_ASSOC);$q->closeCursor();$baselineRoot->execute(['namespace'=>$namespace]);$baselineRoot->fetchAll(PDO::FETCH_ASSOC);$baselineRoot->closeCursor();}else{$q=$pdo->prepare($combined);$q->execute($parameters+['namespace'=>$namespace]);$q->fetchAll(PDO::FETCH_ASSOC);$q->closeCursor();}}$durations[$variant][]=$timer()-$at;}
    echo 'OBSERVATION combined prototype '.json_encode(['iterations_per_round'=>32,'rounds'=>4,'sql_bytes'=>strlen($combined),'seconds'=>$durations,'php'=>PHP_VERSION,'acceptance'=>false]).PHP_EOL;
   }
  });
  if($mode==='small'){
   // This NEW transaction has no baseline SELECT FOR UPDATE or SDK checkpoint. Only the candidate acquires row locks.
   $unit->run(static function()use($pdo,$admin,$combined,$parameters,$namespace):void{
    $q=$pdo->prepare($combined);$q->execute($parameters+['namespace'=>$namespace]);$q->fetchAll(PDO::FETCH_ASSOC);$q->closeCursor();
    // Use a second owned connection. The derived FOR UPDATE must retain row and namespace-gap locks.
    $admin->exec('SET SESSION innodb_lock_wait_timeout=1');
    foreach(['UPDATE sosecurity_account_roots SET revision=revision WHERE namespace=?','UPDATE sosecurity_account_records SET revision=revision WHERE namespace=? AND record_id=\''.str_pad('1',64,'0',STR_PAD_LEFT).'\''] as $sql){$locked=false;try{$q=$admin->prepare($sql);$q->execute([$namespace]);}catch(PDOException $e){$locked=isset($e->errorInfo[1])&&(int)$e->errorInfo[1]===1205;}Check::same(true,$locked);}
    $entry=$pdo->query("SELECT * FROM sosecurity_account_records WHERE namespace='".$namespace."' ORDER BY record_id LIMIT 1")->fetch(PDO::FETCH_ASSOC);$entry['record_id']=str_repeat('f',64);$locked=false;
    try{$q=$admin->prepare('INSERT INTO sosecurity_account_records('.implode(',',array_keys($entry)).') VALUES('.implode(',',array_fill(0,count($entry),'?')).')');$q->execute(array_values($entry));}catch(PDOException $e){$locked=isset($e->errorInfo[1])&&(int)$e->errorInfo[1]===1205;}Check::same(true,$locked);
    $admin->exec('SET SESSION lock_wait_timeout=1');
    foreach(['roots','records'] as $part){$locked=false;try{$admin->exec('ALTER TABLE sosecurity_account_'.$part.' ADD owned_prototype_mdl INT');}catch(PDOException $e){$locked=isset($e->errorInfo[1])&&(int)$e->errorInfo[1]===1205;}Check::same(true,$locked);}
   });
  }
  echo 'PASS context root prototype '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
 }
 // Fresh parsing must continue to reject either fixed table being shadowed.
 foreach(['roots','records'] as $part){$pdo->exec('CREATE TEMPORARY TABLE sosecurity_account_'.$part.'(id INT) ENGINE=InnoDB');$rejected=false;try{$q=$pdo->prepare($combined);$q->execute($parameters+['namespace'=>str_repeat('0',64)]);$q->closeCursor();}catch(PDOException $e){$rejected=true;}finally{$pdo->exec('DROP TEMPORARY TABLE sosecurity_account_'.$part);}Check::same(true,$rejected);}
 Check::same(false,$pdo->inTransaction());echo 'PASS context root prototype complete '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
}finally{if($pdo->inTransaction()){$pdo->rollBack();}foreach(array_reverse($created) as $table){$admin->exec('DROP TABLE '.$table);}}
