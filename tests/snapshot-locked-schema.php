<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account\SqlStateSnapshot;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ConfigurationException;

$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
function lockedControl(string $sql):string
{
    $pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    if(!is_resource($p)){throw new RuntimeException('Owned control unavailable');}
    fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$result=stream_get_contents($pipes[1]);$error=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
    if(proc_close($p)!==0){throw new RuntimeException('Owned control failed: '.$error);}return trim($result);
}
function lockedRefused(callable $body,?string $reason=null):void
{
    $caught=null;try{$body();}catch(SecurityException|ConfigurationException $error){$caught=$error;}
    Check::same(true,$caught!==null);if($reason!==null){Check::same($reason,$caught->reason());}
    foreach([(string)$caught,var_export($caught,true),print_r($caught,true)] as $dump){Check::same(false,strpos($dump,'PRIVATE-LOCKED')!==false);}
}
class LockedSnapshotPdo extends PDO{}
class LockedSnapshotStatement extends PDOStatement
{
    public static $fault='';public static $closes=0;protected function __construct(){}
    public function closeCursor():bool
    {
        $result=parent::closeCursor();
        if(self::$fault!==''&&strpos($this->queryString,'SELECT _sosecurity_left_0.')===0){++self::$closes;if(self::$fault==='throw'){throw new RuntimeException('PRIVATE-LOCKED-CLOSE');}return false;}
        return $result;
    }
}
$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$admin=new PDO($dsn,'sosecurity_test','integration-only',$options);
$created=[];$tables=[];$user=false;$failures=[];$cases=['group1','group2','group3','group4','group5','custom-pdo','custom-stmt','column-before','column-after','table-after','temp','locks-before-catalog','close-false','close-throw'];
if(isset($argv[1])){if(!in_array($argv[1],$cases,true)){throw new RuntimeException('Unknown owned case');}$cases=[$argv[1]];}
try{
    foreach(['a','b','c','d','e'] as $suffix){$name='snapshot_locked_owned_'.$suffix;$admin->exec('CREATE TABLE `'.$name.'`(id BIGINT UNSIGNED NOT NULL,tag BIGINT UNSIGNED NOT NULL,PRIMARY KEY(id)) ENGINE=InnoDB');$created[]=$name;$admin->exec('INSERT INTO `'.$name.'` VALUES(7,9)');$tables[$name]=['columns'=>['id'=>'int','tag'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>2];}
    lockedControl("CREATE USER 'sosecurity_locked_snapshot'@'localhost' IDENTIFIED WITH mysql_native_password BY 'owned-locked-only'");$user=true;
    foreach($created as $name){lockedControl('GRANT SELECT(id,tag),REFERENCES ON sosecurity_test.`'.$name."` TO 'sosecurity_locked_snapshot'@'localhost'");}
    foreach($cases as $case){
        $pdo=$case==='custom-pdo'?new LockedSnapshotPdo($dsn,'sosecurity_test','integration-only',$options):new PDO($dsn,strpos($case,'column')===0||$case==='table-after'?'sosecurity_locked_snapshot':'sosecurity_test',strpos($case,'column')===0||$case==='table-after'?'owned-locked-only':'integration-only',$options);
        $revoke=null;$temporary=false;
        try{
            if($case==='custom-stmt'||strpos($case,'close-')===0){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[LockedSnapshotStatement::class,[]]);}
            $group=strpos($case,'group')===0?(int)substr($case,5):1;$spec=array_slice($tables,0,$group,true);$source=new SqlStateSnapshot($pdo,'owned-locked-schema',$spec,15000);$expected=$source->digest();
            if(strpos($case,'group')===0||strpos($case,'custom-')===0){
                $id=(int)$pdo->query('SELECT CONNECTION_ID()')->fetchColumn();lockedControl("SET GLOBAL general_log=OFF; TRUNCATE mysql.general_log; SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");
                Check::same($expected,$source->digest());lockedControl('SET GLOBAL general_log=OFF');
                $observed=(int)lockedControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$id." AND command_type='Execute' AND (argument LIKE CONCAT(0x".bin2hex("SELECT 'columns' AS section,").",'%') OR argument LIKE CONCAT(0x".bin2hex('SELECT _sosecurity_snapshot_schema.section AS section,').",'%'))");
                $wanted=strpos($case,'custom-')===0?2:(int)ceil($group/4);echo 'OBSERVATION locked snapshot '.json_encode(['case'=>$case,'catalog_reads'=>$observed,'expected'=>$wanted,'php'=>PHP_VERSION]).PHP_EOL;Check::same($wanted,$observed);
            }elseif($case==='locks-before-catalog'){
                $observer=new PDO($dsn,'sosecurity_test','integration-only',$options);$observer->exec('SET SESSION lock_wait_timeout=1');$added=false;
                $unit=SqlTransaction::forObservation($pdo,new SystemClock(),15000);$access=new ReflectionMethod(SqlStateSnapshot::class,'mysqlAccess');if(PHP_VERSION_ID<80100){$access->setAccessible(true);}
                try{$unit->run(static function()use($unit,$access,$source,$spec,$observer,&$added):void{
                    $access->invoke($source,$unit,$spec,false);$blocked=false;
                    try{$observer->exec('ALTER TABLE snapshot_locked_owned_a ADD owned_added INT');$added=true;}catch(PDOException $error){$blocked=isset($error->errorInfo[1])&&(int)$error->errorInfo[1]===1205;}
                    Check::same(true,$blocked);
                });}finally{if($added){$observer->exec('ALTER TABLE snapshot_locked_owned_a DROP COLUMN owned_added');}}
                Check::same($expected,$source->digest());
            }elseif($case==='column-before'){
                $revoke='tag';lockedControl("REVOKE SELECT(tag) ON sosecurity_test.snapshot_locked_owned_a FROM 'sosecurity_locked_snapshot'@'localhost'");lockedRefused(static function()use($source):void{$source->digest();});
            }elseif($case==='temp'){
                $pdo->exec('CREATE TEMPORARY TABLE snapshot_locked_owned_a(id BIGINT UNSIGNED NOT NULL PRIMARY KEY,tag BIGINT UNSIGNED NOT NULL) ENGINE=InnoDB');$temporary=true;lockedRefused(static function()use($source):void{$source->digest();});
            }else{
                $unit=SqlTransaction::forObservation($pdo,new SystemClock(),15000);$schema=new ReflectionMethod(SqlStateSnapshot::class,'mysqlSchemas');$access=new ReflectionMethod(SqlStateSnapshot::class,'mysqlAccess');if(PHP_VERSION_ID<80100){$schema->setAccessible(true);$access->setAccessible(true);}
                if(strpos($case,'close-')===0){LockedSnapshotStatement::$fault=substr($case,6);LockedSnapshotStatement::$closes=0;lockedRefused(static function()use($unit,$access,$source,$spec):void{$unit->run(static function()use($unit,$access,$source,$spec):void{$access->invoke($source,$unit,$spec);});},'sql.cleanup');Check::same(1,LockedSnapshotStatement::$closes);}
                else{
                    lockedRefused(static function()use($unit,$schema,$access,$source,$spec,$case,&$revoke):void{$unit->run(static function()use($unit,$schema,$access,$source,$spec,$case,&$revoke):void{
                        $schema->invoke($source,$unit,$spec);$revoke=$case==='column-after'?'tag':'id,tag';lockedControl("REVOKE SELECT(".$revoke.") ON sosecurity_test.snapshot_locked_owned_a FROM 'sosecurity_locked_snapshot'@'localhost'");
                        $access->invoke($source,$unit,$spec);
                    });});
                }
            }
            Check::same(false,$pdo->inTransaction());echo 'PASS locked snapshot '.$case.' PHP '.PHP_VERSION.PHP_EOL;
        }catch(Throwable $error){$failures[]=$case;echo 'FAIL locked snapshot '.$case.' '.get_class($error).' '.$error->getMessage().PHP_EOL;}
        finally{
            lockedControl('SET GLOBAL general_log=OFF');LockedSnapshotStatement::$fault='';if($pdo->inTransaction()){$pdo->rollBack();}if($temporary){$pdo->exec('DROP TEMPORARY TABLE snapshot_locked_owned_a');}if($revoke!==null){lockedControl("GRANT SELECT(id,tag) ON sosecurity_test.snapshot_locked_owned_a TO 'sosecurity_locked_snapshot'@'localhost'");}$source=null;$unit=null;$pdo=null;
        }
    }
    Check::same([['7','9']],array_map(static function(array $row):array{return array_map('strval',$row);},$admin->query('SELECT id,tag FROM snapshot_locked_owned_a')->fetchAll(PDO::FETCH_NUM)));
}finally{lockedControl('SET GLOBAL general_log=OFF');if($user){lockedControl("DROP USER 'sosecurity_locked_snapshot'@'localhost'");}foreach(array_reverse($created) as $name){$admin->exec('DROP TABLE `'.$name.'`');}}
if($failures){throw new RuntimeException('Locked snapshot failures: '.implode(',',$failures));}echo 'PASS locked snapshot complete '.count($cases).' cases '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
