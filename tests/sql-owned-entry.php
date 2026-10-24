<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Support\SystemClock;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ConfigurationException;
final class OwnedEntryAdapter extends PDO {}
class OwnedEntryStatement extends PDOStatement {}
final class OwnedEntrySwitchStatement extends PDOStatement
{
    private $pdo;
    protected function __construct(PDO $pdo){$this->pdo=$pdo;}
    public function closeCursor():bool
    {
        $closed=parent::closeCursor();
        if($this->queryString==='SELECT @@SESSION.autocommit'){$this->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[PDOStatement::class]);}
        return $closed;
    }
}
final class OwnedEntryClock implements SoSecurity\Support\Clock
{
    public $hook;
    public function now():int{if($this->hook!==null){$hook=$this->hook;$this->hook=null;$hook();}return 1700000000;}
}
function ownedEntryControl(string $sql):string
{
    $pipes=[];$p=proc_open('mysql --no-defaults --socket='.escapeshellarg(getenv('SOSECURITY_TEST_MYSQL_SOCKET')).' -uroot --batch --skip-column-names',[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    if(!is_resource($p)){throw new RuntimeException('Owned control unavailable');}fwrite($pipes[0],$sql.';'.PHP_EOL);fclose($pipes[0]);$out=stream_get_contents($pipes[1]);stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0){throw new RuntimeException('Owned control failed');}return trim($out);
}
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];$observer=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=false;
$modes=['native-run','native-context','native-preflight','preflight-transaction','preflight-denied','custom-clock-run','custom-clock-context','pdo-run','pdo-context','statement-run','statement-context','switch-context','opaque-run','opaque-context','clock-transaction','host-context','sql-host-run','rollback-body'];
try{
    $observer->exec('CREATE TABLE sosecurity_owned_entry(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created=true;
    foreach($modes as $mode){
        $pdo=strpos($mode,'pdo-')===0?new OwnedEntryAdapter($dsn,'sosecurity_test','integration-only',$options):new PDO($dsn,'sosecurity_test','integration-only',$options);
        if(strpos($mode,'statement-')===0){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[OwnedEntryStatement::class]);}
        if($mode==='switch-context'){$pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[OwnedEntrySwitchStatement::class,[$pdo]]);}
        if(strpos($mode,'opaque-')===0){SqlStateAccess::bind($pdo,hash('sha256','owned-entry:'.$mode),hash('sha256','owned-entry-binding:'.$mode),static function():void{});}
        $clock=$mode==='clock-transaction'?new OwnedEntryClock():(strpos($mode,'custom-clock-')===0?new TestClock():new SystemClock());
        $unit=new SqlTransaction($pdo,$clock,10000);$body=0;$preflightCalls=0;$reason=null;$result=null;$method=strpos($mode,'context')!==false?'inContext':'run';
        $preflight=null;
        if(strpos($mode,'preflight')!==false){$preflight=static function()use($pdo,$mode,&$preflightCalls):bool{++$preflightCalls;if(strpos($mode,'transaction')!==false){$pdo->beginTransaction();$pdo->exec('INSERT INTO sosecurity_owned_entry VALUES(1)');}return strpos($mode,'denied')===false;};}
        if($mode==='clock-transaction'){$clock->hook=static function()use($pdo):void{$pdo->beginTransaction();$pdo->exec('INSERT INTO sosecurity_owned_entry VALUES(1)');};}
        if($mode==='host-context'){$pdo->beginTransaction();$pdo->exec('INSERT INTO sosecurity_owned_entry VALUES(1)');}
        if($mode==='sql-host-run'){$pdo->exec('START TRANSACTION');$pdo->exec('INSERT INTO sosecurity_owned_entry VALUES(1)');}
        $reportedActive=$pdo->inTransaction();$q=$pdo->query('SELECT CONNECTION_ID()');$thread=(int)$q->fetchColumn();$q->closeCursor();
        try{
            ownedEntryControl("SET GLOBAL log_output='TABLE'; SET GLOBAL general_log=ON");
            $operation=static function()use($unit,$pdo,$observer,$mode,&$body):int{++$body;Check::same(0,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_owned_entry')->fetchColumn());$unit->query('INSERT INTO sosecurity_owned_entry VALUES(2)')->closeCursor();if($mode==='rollback-body'){throw new SoSecurity\Storage\StorageException('Owned body abort.','test.body');}return 29;};
            try{
                    if($method==='inContext'){$result=$unit->inContext($operation);}
                else{$result=$unit->run($operation,$preflight);}
            }catch(SecurityException|ConfigurationException $error){$reason=$error->reason();}
            ownedEntryControl('SET GLOBAL general_log=OFF');
            $count=(int)ownedEntryControl("SELECT COUNT(*) FROM mysql.general_log WHERE thread_id=".$thread." AND command_type='Execute' AND argument='SELECT @@SESSION.autocommit'");
            echo 'OBSERVATION owned entry '.json_encode(['mode'=>$mode,'checks'=>$count,'body'=>$body,'preflight'=>$preflightCalls,'reason'=>$reason]).PHP_EOL;
            $fallback=strpos($mode,'custom-clock-')===0||strpos($mode,'pdo-')===0||strpos($mode,'statement-')===0||strpos($mode,'opaque-')===0||$mode==='switch-context';
            $expected=$fallback?($method==='inContext'?3:2):1;
            if($mode==='native-preflight'){$expected=2;}
            if($mode==='sql-host-run'){$expected=$reportedActive?0:1;}
            if($mode==='switch-context'){$expected=2;}
            Check::same($expected,$count);
            $denied=strpos($mode,'denied')!==false;$changed=strpos($mode,'transaction')!==false;
            if($mode==='sql-host-run'||$changed){Check::same(0,$body);Check::same('configuration.transaction',$reason);}
            elseif($mode==='rollback-body'){Check::same(1,$body);Check::same('test.body',$reason);}
            else{Check::same(null,$reason);Check::same($denied?0:1,$body);Check::same($denied?null:29,$result);}
            $pending=$changed||in_array($mode,['host-context','sql-host-run'],true);
            Check::same($pending?0:($body===1&&$mode!=='rollback-body'?1:0),(int)$observer->query('SELECT COUNT(*) FROM sosecurity_owned_entry')->fetchColumn());
            if($pending){Check::same(1,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_owned_entry WHERE id=1')->fetchColumn());$pdo->exec('ROLLBACK');}
            echo 'PASS SQL owned entry '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
        }finally{ownedEntryControl('SET GLOBAL general_log=OFF');try{$pdo->exec('ROLLBACK');}catch(Throwable $cleanup){}$observer->exec('DELETE FROM sosecurity_owned_entry');$pdo=null;}
    }
}finally{ownedEntryControl('SET GLOBAL general_log=OFF');if($created){$observer->exec('DROP TABLE sosecurity_owned_entry');}}
