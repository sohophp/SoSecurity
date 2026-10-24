<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Account\SqlStateSnapshot;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ConfigurationException;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function textPoolControl(string $sql):string{$pipes=[];$p=proc_open('mysql --no-defaults --default-character-set=utf8mb4 --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned control unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$r=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}return trim($r);}
function textPoolCount(int $id,string $command,string $prefix):int{return (int)textPoolControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='".$command."' AND argument LIKE CONCAT(0x".bin2hex($prefix).",'%')");}
class TextPoolPdo extends PDO{}
class TextPoolUnknownPdo extends PDO{
 #[\ReturnTypeWillChange]
 public function getAttribute($attribute){if($attribute===PDO::ATTR_STRINGIFY_FETCHES){throw new RuntimeException('PRIVATE-GETTER');}return parent::getAttribute($attribute);}
}
class TextPoolStatement extends PDOStatement{
 public static $fault='';public static $rows=0;
 protected function __construct(){}
 private function metadata():bool{return strpos($this->queryString,"SELECT 'columns' AS section,")===0||strpos($this->queryString,'SELECT _sosecurity_snapshot_schema.section AS section,')===0;}
 public function execute($params=null):bool{if(strpos($this->queryString,'__sw_valid')!==false){++self::$rows;}return $params===null?parent::execute():parent::execute($params);}
 public function fetchAll($mode=null,$className=null,$constructorArgs=null,...$extra):array{if($this->metadata()&&self::$fault==='fetch-close'){throw new RuntimeException('PRIVATE-FETCH');}return parent::fetchAll(...func_get_args());}
 public function closeCursor():bool{$closed=parent::closeCursor();if($this->metadata()&&self::$fault!==''){if(self::$fault==='close-throw'){throw new RuntimeException('PRIVATE-CLOSE');}return false;}return $closed;}
}
function textPoolRefused(callable $body,?string $reason=null):void{$caught=null;try{$body();}catch(SecurityException|ConfigurationException $e){$caught=$e;}Check::same(true,$caught instanceof SecurityException||$caught instanceof ConfigurationException);if($reason!==null){Check::same($reason,$caught->reason());}$depth=0;for($link=$caught;$link!==null;$link=$link->getPrevious()){Check::same(true,++$depth<=8);Check::same(false,strpos((string)$link,'PRIVATE-')!==false);}}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4';$admin=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=[];$tables=[];$names=['snapshot_text_a','snapshot_text_b','snapshot_text_c','snapshot_text_d'];$columns=['id'=>'int'];$ddl='id BIGINT UNSIGNED NOT NULL PRIMARY KEY';for($i=1;$i<=12;++$i){$name='c'.str_pad((string)$i,2,'0',STR_PAD_LEFT);$columns[$name]='nullable_int';$ddl.=',`'.$name.'` BIGINT UNSIGNED NULL';}$failures=[];
try{
 foreach($names as $name){$admin->exec('CREATE TABLE `'.$name.'`('.$ddl.') ENGINE=InnoDB');$created[]=$name;$admin->exec('INSERT INTO `'.$name.'`(id) VALUES(7)');$tables[$name]=['columns'=>$columns,'primary'=>['id'],'where'=>[],'maximum_rows'=>2];}
 $cases=['normal','stringify','unregistered','custom-pdo','custom-stmt','custom-guard','unknown-custom','switch-db','temp','changed-schema','rights','wrong-sql','wrong-params','budget','format','close-false','close-throw','fetch-close'];if(isset($argv[1])){if(!in_array($argv[1],$cases,true)){throw new RuntimeException('Unknown focused mode');}$cases=[$argv[1]];}
 foreach($cases as $case){$directory=privateDirectory();mkdir($directory.'/witness',0700);$other=false;$temporary=false;$altered=false;$user=false;$pdo=null;
  try{
   if($case==='rights'){textPoolControl("CREATE USER 'sosecurity_text_pool'@'localhost' IDENTIFIED WITH mysql_native_password BY 'owned-text-only'");$user=true;foreach($names as $name){textPoolControl('GRANT SELECT ON sosecurity_test.`'.$name."` TO 'sosecurity_text_pool'@'localhost'");}}
   $class=$case==='custom-pdo'?TextPoolPdo::class:($case==='unknown-custom'?TextPoolUnknownPdo::class:PDO::class);$pdo=new $class($dsn,$user?'sosecurity_text_pool':'sosecurity_test',$user?'owned-text-only':'integration-only',$options);if($case==='custom-stmt'){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[TextPoolStatement::class,[]]);}
   $known=false;try{$pdo->getAttribute(PDO::ATTR_STRINGIFY_FETCHES);$known=true;}catch(Throwable $e){}
   $source=new SqlStateSnapshot($pdo,'owned-text-pool',$tables,10000);$expected=$source->digest();$keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);$witness=new SoSecurity\Account\LocalStateWitness($pdo,$directory.'/witness','owned-'.$case,'tenant',str_repeat('e',64),$keys,$source,new SoSecurity\Account\LocalStatePersistence($directory.'/witness',10000),10000,2);$witness->initialize($expected);$boundary=new SoSecurity\Account\StateBoundary($witness,static function():bool{return true;});
   if($case==='custom-guard'){SqlStateAccess::bind($pdo,hash('sha256','text-'.$case),$boundary->binding(),static function():void{});}elseif($case!=='unregistered'){SqlStateAccess::bind($pdo,hash('sha256','text-'.$case),$boundary->binding(),$boundary->sqlGuard($pdo),$boundary);}
   $q=$pdo->query('SELECT CONNECTION_ID()');$id=(int)$q->fetchColumn();$q->closeCursor();TextPoolStatement::$rows=0;textPoolControl("SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");
   if(in_array($case,['normal','unregistered','custom-pdo','custom-stmt','custom-guard','unknown-custom','stringify'],true)){
    Check::same($expected,$source->digest());if($case==='stringify'){$pdo->setAttribute(PDO::ATTR_STRINGIFY_FETCHES,true);}Check::same($expected,$source->digest());
   }elseif(in_array($case,['wrong-sql','wrong-params','format'],true)){
    $u=SqlTransaction::forObservation($pdo,new SoSecurity\Support\SystemClock(),10000);$query=SqlSchema::snapshotMetadataStatement($names,true);
    $u->run(static function()use($u,$query,$case,$names):void{
     if($case==='wrong-sql'){$query['sql'].=' /* unknown fixed code */';}if($case==='wrong-params'){$query['parameters']=array_reverse($query['parameters'],true);}
     $a=$u->metadataRows($query['sql'],$query['parameters']);$b=$u->metadataRows($query['sql'],$query['parameters']);Check::same($a,$b);
     if($case==='format'){$original=SqlSchema::snapshotMetadataStatement($names,false);$raw=$u->metadataRows($original['sql'],$original['parameters']);foreach($raw as &$row){foreach($row as &$value){if($value!==null){$value=(string)$value;}}unset($value);}unset($row);Check::same($raw,$a);foreach($a as $row){foreach($row as $value){Check::same(true,$value===null||is_string($value));}}Check::same(array_merge(['id'],array_map(static function(int $i):string{return 'c'.str_pad((string)$i,2,'0',STR_PAD_LEFT);},range(1,12))),array_column(array_slice($a,0,13),'name'));}
    });
   }elseif($case==='budget'){
    foreach([[],array_fill(0,5,'a'),['a','a'],[0],['bad-name'],[str_repeat('a',65)],["a\0b"],[new class{public function __toString():string{throw new RuntimeException('PRIVATE-OBJECT');}}]] as $bad){textPoolRefused(static function()use($bad):void{SqlSchema::snapshotMetadataStatement($bad,true);},'configuration.sql_schema');}
    for($n=1;$n<=4;++$n){foreach([false,true] as $text){SqlSchema::snapshotMetadataStatement(array_slice($names,0,$n),$text);}}$m=new ReflectionMethod(SqlSchema::class,'snapshotMetadataStatement');$templates=$m->getStaticVariables()['templates'];Check::same(8,count($templates));foreach($templates as $sql){Check::same(false,strpos($sql,'snapshot_text_')!==false);Check::same(true,strlen($sql)<=16384);}
   }elseif(in_array($case,['close-false','close-throw','fetch-close'],true)){
    $pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[TextPoolStatement::class,[]]);TextPoolStatement::$fault=$case;textPoolRefused(static function()use($source):void{$source->digest();},'sql.cleanup');Check::same(0,TextPoolStatement::$rows);
   }else{
    Check::same($expected,$source->digest());
    if($case==='switch-db'){textPoolControl("CREATE DATABASE `sosecurity_库池`; GRANT ALL ON `sosecurity_库池`.* TO 'sosecurity_test'@'localhost'");$other=true;foreach($names as $name){$admin->exec('CREATE TABLE `sosecurity_库池`.`'.$name.'` LIKE sosecurity_test.`'.$name.'`');$admin->exec('INSERT INTO `sosecurity_库池`.`'.$name.'`(id) VALUES(7)');}$admin->exec('ALTER TABLE `sosecurity_库池`.snapshot_text_a MODIFY id VARBINARY(8) NOT NULL');$pdo->exec('USE `sosecurity_库池`');$pdo->exec("SET SESSION character_set_results='latin1'");}
    elseif($case==='temp'){$pdo->exec('CREATE TEMPORARY TABLE snapshot_text_a(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$temporary=true;}
    elseif($case==='changed-schema'){$admin->exec('ALTER TABLE snapshot_text_a MODIFY id VARBINARY(8) NOT NULL');$altered=true;}
    else{textPoolControl("REVOKE SELECT ON sosecurity_test.snapshot_text_a FROM 'sosecurity_text_pool'@'localhost'");}
    textPoolRefused(static function()use($source):void{$source->digest();});
   }
   textPoolControl('SET GLOBAL general_log=OFF');$typed=textPoolCount($id,'Prepare','SELECT _sosecurity_snapshot_schema.section AS section,');$raw=textPoolCount($id,'Prepare',"SELECT 'columns' AS section,");$typedExec=textPoolCount($id,'Execute','SELECT _sosecurity_snapshot_schema.section AS section,');$rawExec=textPoolCount($id,'Execute',"SELECT 'columns' AS section,");
   if(in_array($case,['normal','unregistered','custom-pdo','custom-stmt','custom-guard','unknown-custom','stringify'],true)){$fallback=in_array($case,['custom-pdo','custom-stmt','custom-guard','unknown-custom'],true);$expectedTyped=!$known&&!$fallback;$expectedPrepare=$case==='unregistered'?2:($case==='custom-stmt'||(!$known&&$fallback)?4:($case==='stringify'&&$known?2:1));Check::same($expectedPrepare,$typed+$raw);Check::same($fallback?4:2,$typedExec+$rawExec);Check::same($expectedTyped?$typed+$raw:0,$typed);}
   if(in_array($case,['wrong-sql','wrong-params'],true)){Check::same($known?1:2,$typed);Check::same(2,$typedExec);}
   Check::same(false,$pdo->inTransaction());echo 'OBSERVATION snapshot text pool '.json_encode(['case'=>$case,'known_format'=>$known,'typed_prepares'=>$typed,'raw_prepares'=>$raw,'typed_executes'=>$typedExec,'raw_executes'=>$rawExec,'php'=>PHP_VERSION]).PHP_EOL;echo 'PASS snapshot text pool '.$case.' PHP '.PHP_VERSION.PHP_EOL;
  }catch(Throwable $e){$failures[]=$case;echo 'FAIL snapshot text pool '.$case.' '.get_class($e).' '.$e->getMessage().PHP_EOL;}
  finally{textPoolControl('SET GLOBAL general_log=OFF');TextPoolStatement::$fault='';if($pdo!==null){if($pdo->inTransaction()){$pdo->rollBack();}$pdo->exec('USE sosecurity_test');if($temporary){$pdo->exec('DROP TEMPORARY TABLE snapshot_text_a');}}if($altered){$admin->exec('ALTER TABLE snapshot_text_a MODIFY id BIGINT UNSIGNED NOT NULL');}if($other){textPoolControl('DROP DATABASE `sosecurity_库池`');}if($user){textPoolControl("DROP USER 'sosecurity_text_pool'@'localhost'");}$source=null;$boundary=null;$witness=null;$pdo=null;cleanDirectory($directory.'/witness');cleanDirectory($directory);}
 }
}finally{textPoolControl('SET GLOBAL general_log=OFF');foreach(array_reverse($created) as $name){$admin->exec('DROP TABLE `'.$name.'`');}}
if($failures){throw new RuntimeException('Snapshot text pool failures: '.implode(',',$failures));}echo 'PASS snapshot text pool complete '.count($cases).' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
