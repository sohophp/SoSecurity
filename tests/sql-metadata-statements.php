<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Support\SqlTransaction;use SoSecurity\Support\SqlStateAccess;use SoSecurity\Support\SqlSchema;
final class MetadataCountConnection extends InboxTestConnection
{
 public $metadataPrepares=0;public $metadataExecutions=0;public $alternate=false;
 public function prepare($statement,$driverOptions=[]):PDOStatement {if(strpos($statement,'information_schema.COLUMNS')!==false||strpos($statement,'information_schema.STATISTICS')!==false){++$this->metadataPrepares;}$configuration=$this->getAttribute(PDO::ATTR_STATEMENT_CLASS);if($this->alternate){$this->setAttribute(PDO::ATTR_STATEMENT_CLASS,[MetadataAlternateStatement::class,[$this]]);}try{$query=parent::prepare($statement,$driverOptions);}finally{if($this->alternate){$this->setAttribute(PDO::ATTR_STATEMENT_CLASS,$configuration);}}if($query===false){throw new RuntimeException('Owned preparation failed');}return $query;}
}
class MetadataAlternateStatement extends InboxTestStatement
{
 public static $executions=0;
 public function execute($params=null):bool{if(strpos($this->queryString,'information_schema.COLUMNS')!==false||strpos($this->queryString,'information_schema.STATISTICS')!==false){++self::$executions;}return parent::execute($params);}
}
class MetadataCleanupStatement extends InboxTestStatement
{
 public static $fault='';
 public function execute($params=null):bool{if(self::$fault==='double'&&strpos($this->queryString,'information_schema.COLUMNS')!==false){throw new RuntimeException('PRIVATE-METADATA-EXECUTE');}return parent::execute($params);}
 public function closeCursor():bool {if(strpos($this->queryString,'information_schema.COLUMNS')!==false){if(self::$fault==='throw'){throw new RuntimeException('PRIVATE-METADATA-CLEANUP');}if(in_array(self::$fault,['false','double'],true)){return false;}}return parent::closeCursor();}
}
final class MetadataHookClock implements SoSecurity\Support\Clock
{
 public $calls=0;public $at=0;public $hook;
 public function now():int{if(++$this->calls===$this->at&&$this->hook!==null){$hook=$this->hook;$this->hook=null;$hook();}return 100000;}
}
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned private MySQL required');}
$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false,PDO::ATTR_STRINGIFY_FETCHES=>false];
$pdo=new MetadataCountConnection($dsn,'sosecurity_test','integration-only',$options);$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[PDOStatement::class]);
$pdo->beforeStatement=static function(string $sql)use($pdo):void{if(strpos($sql,'information_schema.COLUMNS')!==false||strpos($sql,'information_schema.STATISTICS')!==false){++$pdo->metadataExecutions;}};
$tables=['sosecurity_metadata_first','sosecurity_metadata_second','sosecurity_metadata_privileges'];$alternateDatabase=false;$outgoing=false;$incoming=false;$active=true;$clock=new TestClock();$reader=null;
$control=static function(string $sql)use($socket):void{
 $process=proc_open('mysql --no-defaults --protocol=SOCKET --socket='.escapeshellarg($socket).' --user=root --database=sosecurity_test --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($process)){throw new RuntimeException('Owned controller unavailable');}$input=$sql.';'.PHP_EOL;$written=fwrite($pipes[0],$input);fclose($pipes[0]);stream_get_contents($pipes[1],8192);fclose($pipes[1]);stream_get_contents($pipes[2],8192);fclose($pipes[2]);if(proc_close($process)!==0||$written!==strlen($input)){throw new RuntimeException('Owned controller failed');}
};
$read=static function(PDO $connection,string $sql,array $params)use($clock):array{$u=new SqlTransaction($connection,$clock,10000);return $u->run(static function()use($u,$sql,$params):array{return $u->metadataRows($sql,$params);});};
$sql='SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=:table ORDER BY ORDINAL_POSITION LIMIT 65';$params=['table'=>$tables[0]];
try{
 foreach($tables as $t){$pdo->exec('CREATE TABLE '.$t.'(id BIGINT UNSIGNED NOT NULL PRIMARY KEY,value BIGINT UNSIGNED NOT NULL) ENGINE=InnoDB');}
 $pdo->exec('ALTER TABLE '.$tables[1].' CHANGE value different BIGINT UNSIGNED NOT NULL');
 SqlStateAccess::bind($pdo,hash('sha256','owned-metadata'),hash('sha256','owned-binding'),static function()use(&$active):void{if(!$active){throw new SoSecurity\Storage\StorageException('Owned authority is inactive.','account.state_required');}});
 try{$pdo->getAttribute(PDO::ATTR_STRINGIFY_FETCHES);$cacheAvailable=true;}catch(Throwable $unsupported){$cacheAvailable=false;}echo 'CACHE_ELIGIBILITY '.($cacheAvailable?'reuse':'fresh').PHP_EOL;
 $first=$read($pdo,$sql,$params);Check::same(['id','value'],array_column($first,'COLUMN_NAME'));Check::same($first,$read($pdo,$sql,$params));Check::same($cacheAvailable?1:2,$pdo->metadataPrepares);
 $before=$pdo->metadataPrepares;Check::same(['id','different'],array_column($read($pdo,$sql,['table'=>$tables[1]]),'COLUMN_NAME'));Check::same($before+($cacheAvailable?0:1),$pdo->metadataPrepares);
 $before=$pdo->metadataPrepares;$error=null;try{$read($pdo,$sql,[]);}catch(Throwable $caught){$error=$caught;}Check::same(true,$error instanceof SoSecurity\Exception\SecurityException);Check::same($first,$read($pdo,$sql,$params));Check::same($before+($cacheAvailable?1:2),$pdo->metadataPrepares);
 $before=$pdo->metadataPrepares;Check::same([],$read($pdo,$sql,['table'=>str_repeat('x',512)]));Check::same([],$read($pdo,$sql,['table'=>str_repeat('x',512)]));Check::same($before+2,$pdo->metadataPrepares);
 $longSql=$sql.' /*'.str_repeat('x',17000).'*/';$before=$pdo->metadataPrepares;Check::same($first,$read($pdo,$longSql,$params));Check::same($first,$read($pdo,$longSql,$params));Check::same($before+2,$pdo->metadataPrepares);
 $before=$pdo->metadataPrepares;$pdo->exec('ALTER TABLE '.$tables[0].' ADD extra BIGINT UNSIGNED NOT NULL DEFAULT 0');Check::same(['id','value','extra'],array_column($read($pdo,$sql,$params),'COLUMN_NAME'));Check::same($before+($cacheAvailable?0:1),$pdo->metadataPrepares);
 $before=$pdo->metadataPrepares;$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[MetadataAlternateStatement::class,[$pdo]]);$read($pdo,$sql,$params);$read($pdo,$sql,$params);Check::same($before+2,$pdo->metadataPrepares);Check::same(2,MetadataAlternateStatement::$executions);
 $pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[PDOStatement::class]);$read($pdo,$sql,$params);
 $before=$pdo->metadataPrepares;$pdo->alternate=true;try{$read($pdo,$sql.' /* wrapped statement */',$params);$read($pdo,$sql.' /* wrapped statement */',$params);}finally{$pdo->alternate=false;}Check::same($before+2,$pdo->metadataPrepares);
 $emulated=new SqlTransaction($pdo,$clock,10000);$before=$pdo->metadataPrepares;
 // The execution policy now rejects drift before preparation; restoring it does not invalidate closed statements.
 $drift=null;try{$emulated->run(static function()use($pdo,$emulated,$sql,$params):void{try{$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES,true);$emulated->metadataRows($sql,$params);}finally{$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);}});}catch(SoSecurity\Exception\ConfigurationException $e){$drift=$e->reason();}Check::same('configuration.sql_transaction',$drift);Check::same($before,$pdo->metadataPrepares);
 $before=$pdo->metadataPrepares;$read($pdo,$sql,$params);$read($pdo,$sql,$params);Check::same($before+($cacheAvailable?0:2),$pdo->metadataPrepares);
 $hookClock=new MetadataHookClock();$u=new SqlTransaction($pdo,$hookClock,10000);$inside=null;
 $outer=$u->run(static function()use($u,$pdo,$hookClock,$sql,$params,$tables,$clock,&$inside):array{
  $hookClock->at=$hookClock->calls+2;$hookClock->hook=static function()use($pdo,$clock,$sql,$tables,&$inside):void{$nested=new SqlTransaction($pdo,$clock,10000);$inside=$nested->enlist(static function()use($nested,$sql,$tables):array{return $nested->metadataRows($sql,['table'=>$tables[1]]);});};
  return $u->metadataRows($sql,$params);
 });
 Check::same(['id','different'],array_column($inside,'COLUMN_NAME'));Check::same(['id','value','extra'],array_column($outer,'COLUMN_NAME'));
 $active=false;$before=$pdo->metadataPrepares;Check::throws(SoSecurity\Storage\StorageException::class,static function()use($read,$pdo,$sql,$params):void{$read($pdo,$sql,$params);});Check::same($before,$pdo->metadataPrepares);$active=true;
 for($i=0;$i<9;++$i){$read($pdo,$sql.' /* owned_'.$i.' */',$params);}$before=$pdo->metadataPrepares;$read($pdo,$sql.' /* owned_0 */',$params);Check::same($before+1,$pdo->metadataPrepares);
 $fresh=new MetadataCountConnection($dsn,'sosecurity_test','integration-only',$options);
 foreach([[PDO::ATTR_CASE,PDO::CASE_LOWER,PDO::CASE_NATURAL],[PDO::ATTR_STRINGIFY_FETCHES,true,false],[PDO::ATTR_ORACLE_NULLS,PDO::NULL_TO_STRING,PDO::NULL_NATURAL]] as $configuration){
  $attribute=$configuration[0];$original=$configuration[2];$freshOriginal=$original;$pdo->setAttribute($attribute,$original);$fresh->setAttribute($attribute,$original);
  $attributeSql=$attribute===PDO::ATTR_STRINGIFY_FETCHES?str_replace('SELECT COLUMN_NAME','SELECT ORDINAL_POSITION',$sql):($attribute===PDO::ATTR_ORACLE_NULLS?str_replace('SELECT COLUMN_NAME','SELECT COLUMN_DEFAULT',$sql):$sql);
  $read($pdo,$attributeSql,$params);
  try{$pdo->setAttribute($attribute,$configuration[1]);$fresh->setAttribute($attribute,$configuration[1]);Check::same($read($fresh,$attributeSql,$params),$read($pdo,$attributeSql,$params));}
  finally{$pdo->setAttribute($attribute,$original);$fresh->setAttribute($attribute,$freshOriginal);}
 }
 $control("REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'sosecurity_reader'@'localhost'");$control("GRANT SELECT,INSERT,UPDATE,DELETE,TRIGGER ON sosecurity_test.* TO 'sosecurity_reader'@'localhost'");
 $reader=new MetadataCountConnection($dsn,'sosecurity_reader','integration-read-only',$options);$reader->setAttribute(PDO::ATTR_STATEMENT_CLASS,[PDOStatement::class]);SqlStateAccess::bind($reader,hash('sha256','owned-reader'),hash('sha256','owned-reader-binding'),static function():void{});
 $checkCalls=0;$check=static function()use($reader,$clock,$tables,&$checkCalls):void{++$checkCalls;$unit=new SqlTransaction($reader,$clock,10000);$unit->run(static function()use($unit,$tables):void{SqlSchema::table($unit,$tables[2],['id'=>'int','value'=>'int'],['id']);});};
 $check();$check();Check::same($cacheAvailable?1:$checkCalls,$reader->metadataPrepares);
 $pdo->exec('CREATE TRIGGER owned_metadata_trigger BEFORE INSERT ON '.$tables[2].' FOR EACH ROW SET NEW.value=NEW.value');$control("REVOKE TRIGGER ON sosecurity_test.* FROM 'sosecurity_reader'@'localhost'");Check::throws(SoSecurity\Exception\ConfigurationException::class,$check);Check::same($cacheAvailable?1:$checkCalls,$reader->metadataPrepares);
 $control("GRANT TRIGGER ON sosecurity_test.* TO 'sosecurity_reader'@'localhost'");Check::throws(SoSecurity\Exception\ConfigurationException::class,$check);$pdo->exec('DROP TRIGGER owned_metadata_trigger');$check();Check::same($cacheAvailable?1:$checkCalls,$reader->metadataPrepares);
 $pdo->exec('ALTER TABLE '.$tables[2].' ENGINE=MyISAM');Check::throws(SoSecurity\Exception\ConfigurationException::class,$check);$pdo->exec('ALTER TABLE '.$tables[2].' ENGINE=InnoDB');$check();
 $pdo->exec('ALTER TABLE '.$tables[2].' ADD CONSTRAINT owned_metadata_outgoing FOREIGN KEY(value) REFERENCES '.$tables[0].'(id)');$outgoing=true;Check::throws(SoSecurity\Exception\ConfigurationException::class,$check);$pdo->exec('ALTER TABLE '.$tables[2].' DROP FOREIGN KEY owned_metadata_outgoing');$outgoing=false;$check();
 $pdo->exec('ALTER TABLE '.$tables[0].' ADD CONSTRAINT owned_metadata_incoming FOREIGN KEY(value) REFERENCES '.$tables[2].'(id)');$incoming=true;Check::throws(SoSecurity\Exception\ConfigurationException::class,$check);$pdo->exec('ALTER TABLE '.$tables[0].' DROP FOREIGN KEY owned_metadata_incoming');$incoming=false;$check();Check::same($cacheAvailable?1:$checkCalls,$reader->metadataPrepares);
 $control("REVOKE TRIGGER ON sosecurity_test.* FROM 'sosecurity_reader'@'localhost'");$control("GRANT TRIGGER ON *.* TO 'sosecurity_reader'@'localhost'");$check();$control('SET GLOBAL partial_revokes=ON');Check::throws(SoSecurity\Exception\ConfigurationException::class,$check);$control('SET GLOBAL partial_revokes=OFF');$control("REVOKE TRIGGER ON *.* FROM 'sosecurity_reader'@'localhost'");$control("GRANT TRIGGER ON sosecurity_test.* TO 'sosecurity_reader'@'localhost'");$check();Check::same($cacheAvailable?1:$checkCalls,$reader->metadataPrepares);
 // DATABASE() and the complete private-table contract must follow the current schema after USE.
 $schemaCheck=static function()use($pdo,$clock,$tables):void{$unit=new SqlTransaction($pdo,$clock,10000);$unit->run(static function()use($unit,$tables):void{SqlSchema::table($unit,$tables[0],['id'=>'int','value'=>'int','extra'=>'int'],['id']);});};$schemaCheck();
 $control('CREATE DATABASE sosecurity_metadata_alt');$alternateDatabase=true;$control('CREATE TABLE sosecurity_metadata_alt.'.$tables[0].'(elsewhere BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$control("GRANT SELECT,TRIGGER ON sosecurity_metadata_alt.* TO 'sosecurity_test'@'localhost'");
 try{$pdo->exec('USE sosecurity_metadata_alt');Check::same(['elsewhere'],array_column($read($pdo,$sql,$params),'COLUMN_NAME'));Check::throws(SoSecurity\Exception\ConfigurationException::class,$schemaCheck); $status=$pdo->query("SHOW GLOBAL STATUS LIKE 'Prepared_stmt_count'")->fetch(PDO::FETCH_NUM);Check::same(true,is_array($status)&&(int)$status[1]<=17);echo 'OWNED_SERVER_PREPARED_STATEMENTS '.(int)$status[1].PHP_EOL;
}finally{$pdo->exec('USE sosecurity_test');}
 Check::same(['id','value','extra'],array_column($read($pdo,$sql,$params),'COLUMN_NAME'));$schemaCheck();
 $source=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-metadata-snapshot',[$tables[0]=>['columns'=>['id'=>'int','value'=>'int','extra'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>2]],10000);
 $before=$pdo->metadataPrepares;$digest=$source->digest();Check::same($digest,$source->digest());Check::same($before+($cacheAvailable?1:4),$pdo->metadataPrepares);
 $pdo->exec('ALTER TABLE '.$tables[0].' MODIFY extra VARCHAR(32) NOT NULL');$failure=null;try{$source->digest();}catch(Throwable $caught){$failure=$caught;}Check::same(true,$failure instanceof SoSecurity\Storage\StorageException);Check::same('account.snapshot_corrupt',$failure->reason());
 $pdo->exec('ALTER TABLE '.$tables[0].' MODIFY extra BIGINT UNSIGNED NOT NULL DEFAULT 0');Check::same($digest,$source->digest());
 // Cleanup failure poisons the unit and cannot leave a reusable statement, even when results were fetched.
 foreach(['false','throw','double'] as $mode){
  $failedConnection=new MetadataCountConnection($dsn,'sosecurity_test','integration-only',$options);$failedConnection->setAttribute(PDO::ATTR_STATEMENT_CLASS,[MetadataCleanupStatement::class,[$failedConnection]]);
  SqlStateAccess::bind($failedConnection,hash('sha256','cleanup-'.$mode),hash('sha256','cleanup-binding-'.$mode),static function():void{});$failedUnit=new SqlTransaction($failedConnection,$clock,10000);MetadataCleanupStatement::$fault=$mode;
  $failure=null;try{$failedUnit->run(static function()use($failedUnit,$sql,$params):void{$failedUnit->metadataRows($sql,$params);});}catch(Throwable $caught){$failure=$caught;}
  Check::same(true,$failure instanceof SoSecurity\Storage\StorageException);Check::same('sql.cleanup',$failure->reason());$chain=$failure;$depth=0;while($chain!==null&&$depth++<8){Check::same(true,$chain instanceof SoSecurity\Storage\StorageException);Check::same('sql.cleanup',$chain->reason());$chain=$chain->getPrevious();}Check::same(null,$chain);Check::same(false,strpos((string)$failure,'PRIVATE-METADATA-')!==false);
  MetadataCleanupStatement::$fault='';Check::throws(SoSecurity\Storage\StorageException::class,static function()use($failedUnit):void{$failedUnit->run(static function():void{});});Check::same(1,$failedConnection->metadataPrepares);
 }
 // Unregistered connections keep their original lifetime; they do not enter the process cache.
 $unbound=new MetadataCountConnection($dsn,'sosecurity_test','integration-only',$options);$read($unbound,$sql,$params);$read($unbound,$sql,$params);Check::same(2,$unbound->metadataPrepares);
 $status=$pdo->query("SHOW GLOBAL STATUS LIKE 'Prepared_stmt_count'")->fetch(PDO::FETCH_NUM);Check::same(true,is_array($status)&&(int)$status[1]<=17);echo 'OWNED_SERVER_PREPARED_STATEMENTS '.(int)$status[1].PHP_EOL;
}finally{$pdo->exec('USE sosecurity_test');if($outgoing){$pdo->exec('ALTER TABLE '.$tables[2].' DROP FOREIGN KEY owned_metadata_outgoing');}if($incoming){$pdo->exec('ALTER TABLE '.$tables[0].' DROP FOREIGN KEY owned_metadata_incoming');}$control('SET GLOBAL partial_revokes=OFF');foreach(array_reverse($tables) as $t){$pdo->exec('DROP TABLE IF EXISTS '.$t);}if($alternateDatabase){$control('DROP DATABASE sosecurity_metadata_alt');}}
echo 'PASS metadata statement lifetime: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
