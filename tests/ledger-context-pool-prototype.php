<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function poolPrototypeControl(string $sql):string{$pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned control unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}return trim($out);}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$admin=new PDO($dsn,'sosecurity_test','integration-only',$options);$pdo=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=[];$other=false;$outcomes=[];
try{
 foreach(explode(';',preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-mysql.sql'))) as $ddl){if(trim($ddl)!==''){$admin->exec($ddl);if(preg_match('/CREATE TABLE\s+(\w+)/i',$ddl,$m)){$created[]=$m[1];}}}
 poolPrototypeControl("CREATE DATABASE sosecurity_pool_other; GRANT ALL ON sosecurity_pool_other.* TO 'sosecurity_test'@'localhost'");$other=true;foreach($created as $table){$admin->exec('CREATE TABLE sosecurity_pool_other.'.$table.' LIKE sosecurity_test.'.$table);}
 $factory=new ReflectionMethod(SqlSchema::class,'mysqlLedgerVisibilitySql');if(PHP_VERSION_ID<80100){$factory->setAccessible(true);}$visibility=$factory->invoke(null);
 $resolution='SELECT 1 FROM `sosecurity_account_roots` AS _sosecurity_left_0 JOIN `sosecurity_account_roots` AS _sosecurity_right_0 ON 1=0 JOIN `sosecurity_account_records` AS _sosecurity_left_1 ON 1=0 JOIN `sosecurity_account_records` AS _sosecurity_right_1 ON 1=0 LIMIT 0';
 $sql='SELECT _sosecurity_context.* FROM ('.$visibility.') AS _sosecurity_context LEFT JOIN ('.$resolution.') AS _sosecurity_resolution ON 1=0 ORDER BY _sosecurity_context.position';
 $params=['context_0_visibility_table'=>'sosecurity_account_roots','context_0_visibility_trigger_table'=>'sosecurity_account_roots','context_1_visibility_table'=>'sosecurity_account_records','context_1_visibility_trigger_table'=>'sosecurity_account_records'];
 $database=$pdo->prepare('SELECT CASE WHEN OCTET_LENGTH(DATABASE())<=256 THEN DATABASE() ELSE NULL END AS database_name');$statements=[];
 $current=static function()use($pdo):string{$probe=$pdo->query('SELECT CASE WHEN OCTET_LENGTH(DATABASE())<=256 THEN DATABASE() ELSE NULL END AS database_name');$name=$probe->fetchColumn();Check::same(true,$probe->closeCursor());Check::same(true,is_string($name));return $name;};
 $read=static function()use($pdo,$sql,$params,$current,&$statements):array{$name=$current();if(!isset($statements[$name])){$statements[$name]=$pdo->prepare($sql);}$q=$statements[$name];$q->execute($params);$rows=$q->fetchAll(PDO::FETCH_ASSOC);Check::same(true,$q->closeCursor());return $rows;};
 foreach(['sosecurity_test','sosecurity_pool_other','sosecurity_test'] as $name){$pdo->exec('USE '.$name);$rows=$read();Check::same(2,count($rows));Check::same([$name,$name],array_column($rows,'database_name'));}Check::same(2,count($statements));
 foreach(['roots','records'] as $part){
  $pdo->exec('CREATE TEMPORARY TABLE sosecurity_account_'.$part.'(id INT) ENGINE=InnoDB');$cachedRejected=false;$freshRejected=false;
  try{$read();}catch(PDOException $e){$cachedRejected=true;}
  try{$q=$pdo->prepare($sql);$q->execute($params);$q->fetchAll(PDO::FETCH_ASSOC);$q->closeCursor();}catch(PDOException $e){$freshRejected=true;}
  finally{$pdo->exec('DROP TEMPORARY TABLE sosecurity_account_'.$part);}
  $outcomes[]=['shadow'=>$part,'cached_rejected'=>$cachedRejected,'fresh_rejected'=>$freshRejected];echo 'OBSERVATION context cache shadow '.json_encode(end($outcomes)).PHP_EOL;
  Check::same(true,$freshRejected);Check::same(true,$cachedRejected);Check::same(2,count($read()));
 }
 // The result, never the authorization decision, must remain fresh after a completed read.
 poolPrototypeControl("REVOKE TRIGGER ON sosecurity_test.* FROM 'sosecurity_test'@'localhost'");$rows=$read();Check::same(['0','0'],array_map('strval',array_column($rows,'scoped')));poolPrototypeControl("GRANT ALL ON sosecurity_test.* TO 'sosecurity_test'@'localhost'");Check::same(['1','1'],array_map('strval',array_column($read(),'scoped')));
 foreach([0,2,1] as $value){poolPrototypeControl('SET GLOBAL innodb_flush_log_at_trx_commit='.$value);Check::same([(string)$value,(string)$value],array_map('strval',array_column($read(),'ledger_durable')));}
 $pdo->beginTransaction();$read();$admin->exec('SET SESSION lock_wait_timeout=1');foreach(['roots','records'] as $part){$locked=false;try{$admin->exec('ALTER TABLE sosecurity_account_'.$part.' ADD owned_pool_lock INT');}catch(PDOException $e){$locked=isset($e->errorInfo[1])&&(int)$e->errorInfo[1]===1205;}Check::same(true,$locked);}$pdo->rollBack();
 $timer=static function():float{return function_exists('hrtime')?hrtime(true)/1000000000:microtime(true);};$durations=[];
 foreach(['fresh','pool','pool','fresh'] as $variant){$at=$timer();for($i=0;$i<32;++$i){if($variant==='fresh'){$q=$pdo->prepare($sql);$q->execute($params);$q->fetchAll(PDO::FETCH_ASSOC);$q->closeCursor();}else{$name=$current();$q=$statements[$name];$q->execute($params);$q->fetchAll(PDO::FETCH_ASSOC);$q->closeCursor();}}$durations[$variant][]=$timer()-$at;}
 echo 'OBSERVATION context pool prototype '.json_encode(['seconds'=>$durations,'iterations_per_round'=>32,'php'=>PHP_VERSION,'acceptance'=>false]).PHP_EOL;
 echo 'PASS context pool prototype '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
}finally{
 poolPrototypeControl('SET GLOBAL innodb_flush_log_at_trx_commit=1');if($pdo->inTransaction()){$pdo->rollBack();}$pdo->exec('USE sosecurity_test');poolPrototypeControl("GRANT ALL ON sosecurity_test.* TO 'sosecurity_test'@'localhost'");if($other){poolPrototypeControl('DROP DATABASE sosecurity_pool_other');}foreach(array_reverse($created) as $table){$admin->exec('DROP TABLE '.$table);}
}
