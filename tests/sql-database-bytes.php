<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Account\Ledger;
use SoSecurity\Exception\ConfigurationException;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function databaseBytesControl(string $sql):void{$pipes=[];$p=proc_open('mysql --no-defaults --default-character-set=utf8mb4 --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned control unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}}
class DatabaseBytesAdapter extends PDO{
 #[\ReturnTypeWillChange]
 public function getAttribute($attribute){return $attribute===PDO::ATTR_STRINGIFY_FETCHES?false:parent::getAttribute($attribute);}
}
$options=[PDO::ATTR_STRINGIFY_FETCHES=>false,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4';$admin=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=[];$schemas=['sosecurity_库甲','sosecurity_库乙'];$failures=[];
try{
 foreach(explode(';',preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/account-mysql.sql'))) as $ddl){if(trim($ddl)!==''){$admin->exec($ddl);if(preg_match('/CREATE TABLE\s+(\w+)/i',$ddl,$m)){$created[]=$m[1];}}}
 $admin->exec('CREATE TABLE sosecurity_database_bytes(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created[]='sosecurity_database_bytes';
 $modes=($argv[1]??'')==='metadata-only'?['metadata']:['checkpoint','structure','context','metadata'];
 foreach($modes as $mode){$made=[];$directory=privateDirectory();mkdir($directory.'/witness',0700);$keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);$policy=new SoSecurity\Account\Policy();$clock=new SoSecurity\Support\SystemClock();$expected=[];
  try{
   foreach($schemas as $index=>$schema){databaseBytesControl('CREATE DATABASE `'.$schema."`; GRANT ALL ON `".$schema."`.* TO 'sosecurity_test'@'localhost'");$made[]=$schema;foreach(['roots','records'] as $part){$admin->exec('CREATE TABLE `'.$schema.'`.sosecurity_account_'.$part.' LIKE sosecurity_test.sosecurity_account_'.$part);}
    $writer=new PDO($dsn,'sosecurity_test','integration-only',$options);$writer->exec('USE `'.$schema.'`');$u=new SqlTransaction($writer,$clock,10000);$l=new Ledger($u,'owned-database-bytes','tenant',str_repeat('e',64),$keys,$policy);
    $expected[$schema]=$u->run(static function()use($l,$index,$clock):array{$l->initialize();$l->put(str_repeat('a',64),str_repeat('b',64),'notice','owned-'.$index,$clock->now()+3600);return $l->checkpoint();});$u=null;$l=null;$writer=null;
   }
   if(in_array($mode,['structure','metadata'],true)){$admin->exec('ALTER TABLE `'.$schemas[1].'`.sosecurity_account_roots MODIFY revision VARBINARY(8) NOT NULL');}
   if($mode==='context'){databaseBytesControl("REVOKE TRIGGER ON `".$schemas[1]."`.* FROM 'sosecurity_test'@'localhost'");}
   $pdo=$mode==='metadata'?new DatabaseBytesAdapter($dsn,'sosecurity_test','integration-only',$options):new PDO($dsn,'sosecurity_test','integration-only',$options);$source=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-db-bytes',['sosecurity_database_bytes'=>['columns'=>['id'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>2]],10000);$witness=new SoSecurity\Account\LocalStateWitness($pdo,$directory.'/witness','owned-db-bytes','tenant',str_repeat('e',64),$keys,$source,new SoSecurity\Account\LocalStatePersistence($directory.'/witness',10000),10000,2);$witness->initialize($source->digest());$boundary=new SoSecurity\Account\StateBoundary($witness,static function():bool{return true;});SqlStateAccess::bind($pdo,hash('sha256','owned-db-bytes-'.$mode),$boundary->binding(),$boundary->sqlGuard($pdo),$boundary);$unit=new SqlTransaction($pdo,$clock,10000);$ledger=new Ledger($unit,'owned-database-bytes','tenant',str_repeat('e',64),$keys,$policy);$labels=[];$actual=[];$denied=false;$sdkNames=[];
   $boundary->run('owned.database.bytes',static function()use($unit,$pdo,$ledger,$schemas,$mode,&$labels,&$actual,&$denied,&$sdkNames):void{
    $unit->run(static function()use($unit,$pdo,$ledger,$schemas,$mode,&$labels,&$actual,&$denied,&$sdkNames):void{
     foreach($schemas as $index=>$schema){$unit->invoke(static function()use($pdo,$schema):void{$pdo->exec('USE `'.$schema.'`');$pdo->exec("SET SESSION character_set_results='latin1'");},[],'test.database');$q=$pdo->query('SELECT DATABASE()');$labels[]=$q->fetchColumn();$q->closeCursor();
      try{if($mode==='checkpoint'){$actual[]=$ledger->checkpoint();}elseif(in_array($mode,['structure','metadata'],true)){$unit->verifyLedgerSchema();}else{$view=SqlSchema::ledgerSchemaContext($unit);$sdkNames[]=$view['database'];}}
      catch(ConfigurationException $e){if($index!==1||$e->reason()!=='configuration.sql_schema'){throw $e;}$denied=true;}
     }
     $unit->invoke(static function()use($pdo):void{$pdo->exec('USE sosecurity_test');$pdo->exec("SET SESSION character_set_results='utf8mb4'");},[],'test.database');
    });
   });
   $observation=['mode'=>$mode,'raw_names_collide'=>count($labels)===2&&$labels[0]===$labels[1],'denied_second'=>$denied,'checkpoint_matches_second'=>$mode==='checkpoint'&&isset($actual[1])&&$actual[1]===$expected[$schemas[1]],'sdk_name_hex'=>array_map('bin2hex',$sdkNames)];echo 'OBSERVATION database bytes '.json_encode($observation).PHP_EOL;
   try{Check::same(true,$observation['raw_names_collide']);if($mode==='checkpoint'){Check::same($expected[$schemas[0]],$actual[0]);Check::same($expected[$schemas[1]],$actual[1]);}else{Check::same(true,$denied);}Check::same(false,$pdo->inTransaction());echo 'PASS database bytes '.$mode.' PHP '.PHP_VERSION.PHP_EOL;}catch(Throwable $e){$failures[]=$mode;echo 'FAIL database bytes '.$mode.' '.$e->getMessage().PHP_EOL;}
  }finally{if(isset($pdo)&&$pdo->inTransaction()){$pdo->rollBack();}$unit=null;$ledger=null;$boundary=null;$witness=null;$source=null;$pdo=null;cleanDirectory($directory.'/witness');cleanDirectory($directory);foreach(array_reverse($made) as $schema){databaseBytesControl('DROP DATABASE `'.$schema.'`');}}
 }
}finally{foreach(array_reverse($created) as $table){$admin->exec('DROP TABLE '.$table);}}
if($failures){throw new RuntimeException('Database byte identity failed: '.implode(',',$failures));}echo 'PASS database bytes complete '.count($modes).' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
