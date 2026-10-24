<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function fixedFormatControl(string $sql):string{$pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned control unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$s=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}return trim($s);}
function fixedFormatCount(int $id,string $command,string $sql):int{return (int)fixedFormatControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='".$command."' AND argument=0x".bin2hex($sql));}
class FixedFormatPdo extends PDO{}
class FixedFormatStatement extends PDOStatement{
 public static $fault='';
 protected function __construct(){}
 private function selected():bool{return $this->queryString==='SELECT @@GLOBAL.innodb_flush_log_at_trx_commit';}
 public function fetchAll($mode=null,$className=null,$constructorArgs=null,...$extra):array{if($this->selected()&&self::$fault==='fetch-close'){throw new RuntimeException('PRIVATE-FIXED-FETCH');}return parent::fetchAll(...func_get_args());}
 public function closeCursor():bool{$closed=parent::closeCursor();if($this->selected()&&self::$fault!==''){if(self::$fault==='close-throw'){throw new RuntimeException('PRIVATE-FIXED-CLOSE');}return false;}return $closed;}
}
function fixedFormatRefused(callable $body,string $reason):void{$caught=null;try{$body();}catch(SecurityException|ConfigurationException $e){$caught=$e;}Check::same(true,$caught instanceof SecurityException||$caught instanceof ConfigurationException);Check::same($reason,$caught->reason());$depth=0;for($link=$caught;$link!==null;$link=$link->getPrevious()){Check::same(true,++$depth<=8);Check::same(false,strpos((string)$link,'PRIVATE-')!==false);}}
$queries=['SELECT @@GLOBAL.innodb_flush_log_at_trx_commit','SELECT @@SESSION.innodb_lock_wait_timeout','SELECT @@SESSION.lock_wait_timeout','SELECT @@SESSION.innodb_lock_wait_timeout AS row_wait,@@SESSION.lock_wait_timeout AS metadata_wait'];$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$admin=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=false;$failures=[];
try{
 $admin->exec('CREATE TABLE fixed_variable_owner(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created=true;
 $cases=['normal','stringify','unregistered','pdo-adapter','statement-adapter','custom-clock','opaque','case-upper','zero','durability','close-false','close-throw','fetch-close','unknown-sql','shape'];if(isset($argv[1])){if(!in_array($argv[1],$cases,true)){throw new RuntimeException('Unknown owned mode');}$cases=[$argv[1]];}
 foreach($cases as $case){$directory=privateDirectory();mkdir($directory.'/witness',0700);$pdo=null;
  try{
   fixedFormatControl('SET GLOBAL general_log=OFF; TRUNCATE TABLE mysql.general_log; SET GLOBAL innodb_flush_log_at_trx_commit=1');$pdo=$case==='pdo-adapter'?new FixedFormatPdo($dsn,'sosecurity_test','integration-only',$options):new PDO($dsn,'sosecurity_test','integration-only',$options);$known=true;try{$pdo->getAttribute(PDO::ATTR_STRINGIFY_FETCHES);}catch(Throwable $e){$known=false;}
   $source=new SoSecurity\Account\SqlStateSnapshot($pdo,'owned-fixed-source',['fixed_variable_owner'=>['columns'=>['id'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>2]],10000);$keys=new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]);$witness=new SoSecurity\Account\LocalStateWitness($pdo,$directory.'/witness','owned-fixed-'.$case,'tenant',str_repeat('e',64),$keys,$source,new SoSecurity\Account\LocalStatePersistence($directory.'/witness',10000),10000,2);$witness->initialize($source->digest());$boundary=new SoSecurity\Account\StateBoundary($witness,static function():bool{return true;});$registered=$case!=='unregistered';$closeVerified=false;
   if($case==='opaque'){SqlStateAccess::bind($pdo,hash('sha256',$case),$boundary->binding(),static function():void{});}elseif($registered){SqlStateAccess::bind($pdo,hash('sha256',$case),$boundary->binding(),$boundary->sqlGuard($pdo),$boundary);}
   if($case==='statement-adapter'||in_array($case,['close-false','close-throw','fetch-close'],true)){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[FixedFormatStatement::class,[]]);}if($case==='case-upper'){$pdo->setAttribute(PDO::ATTR_CASE,PDO::CASE_UPPER);}
   $clock=$case==='custom-clock'?new TestClock():new SoSecurity\Support\SystemClock();$unit=SqlTransaction::forObservation($pdo,$clock,10000);$eligible=$registered&&$unit->canBatchLedgerReads();$q=$pdo->query('SELECT CONNECTION_ID()');$id=(int)$q->fetchColumn();$q->closeCursor();$executes=2;
   $unit->run(static function()use($unit,$pdo,$case,$queries,$known,$eligible,&$executes,&$closeVerified):void{
    $pdo->exec('SET SESSION innodb_lock_wait_timeout=17,lock_wait_timeout=19');fixedFormatControl("SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");
    if(in_array($case,['close-false','close-throw','fetch-close'],true)){FixedFormatStatement::$fault=$case;fixedFormatRefused(static function()use($unit,$queries):void{$unit->metadataRows($queries[0]);},'sql.cleanup');$closeVerified=true;return;}
    if($case==='shape'){
     $method=new ReflectionMethod(SqlStateAccess::class,'fixedVariableRows');if(PHP_VERSION_ID<80100){$method->setAccessible(true);}
     foreach([[],[[]],[[1],[2]],[[null]],[[false]],[[-1]],[[1.0]],[['01']],[['9223372036854775808']],[[new class{public function __toString():string{throw new RuntimeException('PRIVATE-NUMBER');}}]]] as $bad){fixedFormatRefused(static function()use($method,$queries,$bad):void{$method->invoke(null,$queries[0],$bad);},'sql.corrupt');}
     fixedFormatRefused(static function()use($method,$queries):void{$method->invoke(null,$queries[3],[['row_wait'=>1,'wrong'=>2]]);},'sql.corrupt');Check::same([['raw'=>'0']],$method->invoke(null,$queries[0],[['raw'=>0]]));Check::same([['row_wait'=>'1','metadata_wait'=>'9223372036854775807']],$method->invoke(null,$queries[3],[['row_wait'=>'1','metadata_wait'=>PHP_INT_MAX]]));return;
    }
    if($case==='unknown-sql'){$query=$queries[0].' /* unknown fixed read */';$unit->metadataRows($query);$unit->metadataRows($query);return;}
    foreach([0,1] as $round){if($round===1){$pdo->exec('SET SESSION innodb_lock_wait_timeout=23,lock_wait_timeout=29');if($case==='zero'){fixedFormatControl('SET GLOBAL innodb_flush_log_at_trx_commit=0');}if($case==='stringify'){$pdo->setAttribute(PDO::ATTR_STRINGIFY_FETCHES,true);}}foreach($queries as $index=>$sql){$rows=$unit->metadataRows($sql);$expected=$index===0?[$case==='zero'&&$round===1?0:1]:($index===1?[$round===0?17:23]:($index===2?[$round===0?19:29]:[$round===0?17:23,$round===0?19:29]));Check::same($expected,array_map('intval',array_values($rows[0])));if($eligible&&!$known){foreach($rows[0] as $value){Check::same(true,is_string($value));}}}}
    if($case==='durability'){fixedFormatControl('SET GLOBAL innodb_flush_log_at_trx_commit=2');try{fixedFormatRefused(static function()use($unit):void{SqlSchema::durable($unit);},'configuration.sql_durability');}finally{fixedFormatControl('SET GLOBAL innodb_flush_log_at_trx_commit=1');}$executes=3;}
   });
   FixedFormatStatement::$fault='';fixedFormatControl('SET GLOBAL general_log=OFF');$counts=[];
   if(!in_array($case,['unknown-sql','shape'],true)){
    foreach($queries as $index=>$sql){$prepare=fixedFormatCount($id,'Prepare',$sql);$execute=fixedFormatCount($id,'Execute',$sql);$counts[]=['prepare'=>$prepare,'execute'=>$execute];$expectExec=$index===0?$executes:2;$reuse=$registered&&($known&&$case!=='pdo-adapter'&&$case!=='statement-adapter'||$eligible);$expectPrepare=($reuse?($case==='stringify'&&$known?2:1):$expectExec)-($reuse&&in_array($index,[1,2],true)?1:0);Check::same($expectExec,$execute);Check::same($expectPrepare,$prepare);}
   }elseif($case==='unknown-sql'){Check::same(2,fixedFormatCount($id,'Prepare',$queries[0].' /* unknown fixed read */'));}
   Check::same(false,$pdo->inTransaction());echo 'OBSERVATION fixed variable format '.json_encode(['case'=>$case,'known'=>$known,'eligible'=>$eligible,'counts'=>$counts,'php'=>PHP_VERSION]).PHP_EOL;echo 'PASS fixed variable format '.$case.' PHP '.PHP_VERSION.PHP_EOL;
  }catch(Throwable $e){if(in_array($case,['close-false','close-throw','fetch-close'],true)&&$e instanceof SecurityException&&$e->reason()==='sql.cleanup'&&$closeVerified){Check::same(false,$pdo->inTransaction());echo 'PASS fixed variable format '.$case.' PHP '.PHP_VERSION.PHP_EOL;}else{$failures[]=$case;echo 'FAIL fixed variable format '.$case.' '.get_class($e).' '.$e->getMessage().PHP_EOL;}}
  finally{FixedFormatStatement::$fault='';fixedFormatControl('SET GLOBAL general_log=OFF; SET GLOBAL innodb_flush_log_at_trx_commit=1');if($pdo!==null&&$pdo->inTransaction()){$pdo->rollBack();}$source=null;$boundary=null;$witness=null;$pdo=null;cleanDirectory($directory.'/witness');cleanDirectory($directory);}
 }
}finally{fixedFormatControl('SET GLOBAL general_log=OFF; SET GLOBAL innodb_flush_log_at_trx_commit=1');if($created){$admin->exec('DROP TABLE fixed_variable_owner');}}
if($failures){throw new RuntimeException('Fixed variable format failures: '.implode(',',$failures));}echo 'PASS fixed variable format complete '.count($cases).' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
