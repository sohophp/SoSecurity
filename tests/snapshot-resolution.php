<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account\SqlStateSnapshot;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function resolutionControl(string $sql):void{$pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p)){throw new RuntimeException('Owned control unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}}
class ResolutionConnection extends PDO{}
class ResolutionStatement extends PDOStatement{
 public static $fault='';public static $closed=0;public static $rows=0;
 protected function __construct(){}
 public function execute($params=null):bool{if(strpos($this->queryString,'__sw_valid')!==false){++self::$rows;}return $params===null?parent::execute():parent::execute($params);}
 public function closeCursor():bool{$resolution=strpos($this->queryString,'SELECT 1 FROM `snapshot_resolve_')===0;if($resolution){++self::$closed;if(self::$fault!==''){parent::closeCursor();if(self::$fault==='throw'){throw new RuntimeException('PRIVATE-RESOLUTION-CLOSE');}return false;}}return parent::closeCursor();}
}
function resolutionCounter(PDO $pdo):int{$q=$pdo->query("SHOW SESSION STATUS LIKE 'Com_stmt_prepare'");$row=$q->fetch(PDO::FETCH_NUM);$q->closeCursor();if(!is_array($row)||count($row)!==2){throw new RuntimeException('Owned status unavailable');}return (int)$row[1];}
function resolutionSource(PDO $pdo,array $names):SqlStateSnapshot{$tables=[];foreach($names as $name){$tables[$name]=['columns'=>['id'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>2];}return new SqlStateSnapshot($pdo,'owned-resolution',$tables,10000);}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4';$admin=new PDO($dsn,'sosecurity_test','integration-only',$options);$names=['snapshot_resolve_a','snapshot_resolve_b','snapshot_resolve_c','snapshot_resolve_d'];$created=[];$user=false;$failures=[];$metrics=[];
try{
 foreach($names as $name){$admin->exec('CREATE TABLE `'.$name.'`(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created[]=$name;$admin->exec('INSERT INTO `'.$name.'` VALUES(7)');}
 resolutionControl("CREATE USER 'sosecurity_resolution'@'localhost' IDENTIFIED WITH mysql_native_password BY 'owned-resolution-only'");$user=true;foreach($names as $name){resolutionControl('GRANT SELECT,REFERENCES ON sosecurity_test.`'.$name."` TO 'sosecurity_resolution'@'localhost'");}
 $cases=['group1','group2','group3','group4','temp0','temp1','temp2','temp3','right0','right1','right2','right3','close-false','close-throw','custom-pdo','custom-statement','custom-guard'];if(isset($argv[1])){if(!in_array($argv[1],$cases,true)){throw new RuntimeException('Unknown owned case');}$cases=[$argv[1]];}
 foreach($cases as $case){$pdo=$case==='custom-pdo'?new ResolutionConnection($dsn,'sosecurity_test','integration-only',$options):new PDO($dsn,strpos($case,'right')===0?'sosecurity_resolution':'sosecurity_test',strpos($case,'right')===0?'owned-resolution-only':'integration-only',$options);if($case==='custom-statement'){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[ResolutionStatement::class,[]]);}if($case==='custom-guard'){SoSecurity\Support\SqlStateAccess::bind($pdo,hash('sha256','owned-resolution-context'),hash('sha256','owned-resolution-binding'),static function():void{});}$selected=null;$revoked=false;$temporary=false;
  try{
   $group=strpos($case,'group')===0?(int)substr($case,5):4;$source=resolutionSource($pdo,array_slice($names,0,$group));$expected=$source->digest();ResolutionStatement::$closed=0;ResolutionStatement::$rows=0;
   if(strpos($case,'group')===0||strpos($case,'custom-')===0){$before=resolutionCounter($pdo);Check::same($expected,$source->digest());$metrics[$case]=resolutionCounter($pdo)-$before;Check::same(false,(bool)$pdo->getAttribute(PDO::ATTR_EMULATE_PREPARES));if($case==='custom-statement'){Check::same(8,ResolutionStatement::$closed);Check::same(4,ResolutionStatement::$rows);}else{Check::same([PDOStatement::class],$pdo->getAttribute(PDO::ATTR_STATEMENT_CLASS));}Check::same(strpos($case,'custom-')!==0,(new SoSecurity\Support\SqlTransaction($pdo,new SoSecurity\Support\SystemClock(),10000))->canBatchLedgerReads());}
   else{
    if(strpos($case,'temp')===0){$selected=$names[(int)substr($case,4)];$pdo->exec('CREATE TEMPORARY TABLE `'.$selected.'`(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$temporary=true;}
    elseif(strpos($case,'right')===0){$selected=$names[(int)substr($case,5)];resolutionControl('REVOKE SELECT ON sosecurity_test.`'.$selected."` FROM 'sosecurity_resolution'@'localhost'");$revoked=true;}
    else{$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[ResolutionStatement::class,[]]);ResolutionStatement::$fault=substr($case,6);ResolutionStatement::$closed=0;ResolutionStatement::$rows=0;}
    $caught=null;try{$source->digest();}catch(SecurityException|ConfigurationException $e){$caught=$e;}Check::same(true,$caught instanceof SecurityException||$caught instanceof ConfigurationException);
    $depth=0;for($link=$caught;$link!==null;$link=$link->getPrevious()){Check::same(true,++$depth<=8);Check::same(false,strpos((string)$link,'PRIVATE-')!==false);}
    if(strpos($case,'close-')===0){Check::same('sql.cleanup',$caught->reason());Check::same(1,ResolutionStatement::$closed);Check::same(0,ResolutionStatement::$rows);}
    if($temporary){$pdo->exec('DROP TEMPORARY TABLE `'.$selected.'`');$temporary=false;}
    if($revoked){resolutionControl('GRANT SELECT ON sosecurity_test.`'.$selected."` TO 'sosecurity_resolution'@'localhost'");$revoked=false;}
    ResolutionStatement::$fault='';$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[PDOStatement::class]);Check::same($expected,$source->digest());
   }
   Check::same(false,$pdo->inTransaction());echo 'PASS snapshot resolution '.$case.' PHP '.PHP_VERSION.PHP_EOL;
  }catch(Throwable $e){$failures[]=$case;echo 'FAIL snapshot resolution '.$case.' '.get_class($e).' '.$e->getMessage().PHP_EOL;}
  finally{ResolutionStatement::$fault='';if($pdo->inTransaction()){$pdo->rollBack();}if($temporary){$pdo->exec('DROP TEMPORARY TABLE `'.$selected.'`');}if($revoked){resolutionControl('GRANT SELECT ON sosecurity_test.`'.$selected."` TO 'sosecurity_resolution'@'localhost'");}$source=null;$pdo=null;}
 }
 foreach($names as $name){Check::same(['7'],array_map('strval',$admin->query('SELECT id FROM `'.$name.'`')->fetchAll(PDO::FETCH_COLUMN)));}
 echo 'OBSERVATION snapshot resolution prepare '.json_encode(['php'=>PHP_VERSION,'counts'=>$metrics]).PHP_EOL;
}finally{if($user){resolutionControl("DROP USER 'sosecurity_resolution'@'localhost'");}foreach(array_reverse($created) as $name){$admin->exec('DROP TABLE `'.$name.'`');}}
if($failures){throw new RuntimeException('Snapshot resolution failures: '.implode(',',$failures));}echo 'PASS snapshot resolution complete '.count($cases).' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
