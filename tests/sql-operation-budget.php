<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account\SqlStateSnapshot;
use SoSecurity\Account\LocalStateWitness;
use SoSecurity\Account\LocalStatePersistence;
use SoSecurity\Account\StateBoundary;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\SystemClock;
use SoSecurity\Storage\StorageException;
final class OperationBudgetConnection extends PDO
{
    public static $armed=false;
    public static $limit;
    public function exec($sql):int
    {
        if(self::$armed&&$sql==='BEGIN IMMEDIATE'){$q=$this->query('PRAGMA busy_timeout');self::$limit=(int)$q->fetchColumn();$q->closeCursor();}
        return parent::exec($sql);
    }
}
$backend=$argv[1]??'sqlite';$mysql=$backend==='mysql';if(!in_array($backend,['sqlite','mysql'],true)){throw new RuntimeException('Use an owned backend');}
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned MySQL required');}
$modes=['run','enlist','context','context-host','readIn','observation','no-budget','short-inner','long-inner','inner-error','inner-timeout','next-operation','outside-observation','outside-effect','opaque','locked','split-budget','split-expired','execution-shorter','split-inner'];
foreach($modes as $mode){
    if(isset($argv[2])&&$argv[2]!==$mode){continue;}
    $directory=privateDirectory();mkdir($directory.'/authority',0700);$pdo=null;$other=null;$created=false;$body=0;$limit=null;$afterLimit=null;$innerLimit=null;$innerReason=null;$reason=null;$status=null;$seconds=null;
    try{
        $dsn=$mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test':'sqlite:'.$directory.'/owned.sqlite';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];
        $pdo=!$mysql&&$mode==='locked'?new OperationBudgetConnection($dsn,null,null,$options):new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);$other=new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);
        if(!$mysql){$pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');}
        $pdo->exec('CREATE TABLE sosecurity_operation_budget(id '.($mysql?'BIGINT UNSIGNED':'INTEGER').' NOT NULL PRIMARY KEY,value '.($mysql?'BIGINT UNSIGNED':'INTEGER').' NOT NULL)'.($mysql?' ENGINE=InnoDB':''));$created=true;$pdo->exec('INSERT INTO sosecurity_operation_budget VALUES(1,1)');
        $source=new SqlStateSnapshot($pdo,'owned-budget',['sosecurity_operation_budget'=>['columns'=>['id'=>'int','value'=>'int'],'primary'=>['id'],'maximum_rows'=>2,'where'=>[]]],10000);
        $witness=new LocalStateWitness($pdo,$directory.'/authority','owned','tenant',str_repeat('e',64),new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]),$source,new LocalStatePersistence($directory.'/authority',10000),10000);
        $witness->initialize($source->digest());$boundary=new StateBoundary($witness,static function():bool{return true;});
        $guard=$mode==='opaque'?static function():void{}:$boundary->sqlGuard($pdo);
        SqlStateAccess::bind($pdo,hash('sha256','operation-budget:'.$backend.':'.$mode),hash('sha256','operation-budget-binding:'.$backend.':'.$mode),$guard,$mode==='opaque'?null:$boundary);
        $pdo->exec($mysql?'SET SESSION innodb_lock_wait_timeout=19':'PRAGMA busy_timeout=19000');
        $read=static function()use($mysql,$pdo):int{$q=$pdo->query($mysql?'SELECT @@SESSION.innodb_lock_wait_timeout':'PRAGMA busy_timeout');$v=(int)$q->fetchColumn();$q->closeCursor();return $v;};
        $clock=new SystemClock();$unit=new SqlTransaction($pdo,$clock,10000);
        $operation=static function()use($mode,$mysql,$pdo,$other,$unit,$clock,$read,$boundary,&$body,&$limit,&$afterLimit,&$innerLimit,&$innerReason,&$seconds):void{
            $run=static function(?SqlTransaction $target=null,string $method='run')use($unit,$read,&$body):int{$target=$target??$unit;return $target->$method(static function()use($read,&$body):int{++$body;return $read();});};
            if(in_array($mode,['enlist','context-host'],true)){$pdo->beginTransaction();try{$limit=$run(null,$mode==='enlist'?'enlist':'inContext');Check::same(true,$pdo->inTransaction());}finally{$pdo->rollBack();}}
            elseif($mode==='context'){$limit=$run(null,'inContext');}
            elseif($mode==='readIn'){$limit=$unit->run(static function()use($unit,$pdo,$clock,$read,&$body):int{$child=new SqlTransaction($pdo,$clock,10000);return $child->readIn($unit,static function()use($read,&$body):int{++$body;return $read();});});}
            elseif($mode==='observation'){$limit=$run(SqlTransaction::forObservation($pdo,$clock,10000));}
            elseif(in_array($mode,['short-inner','long-inner','inner-error','inner-timeout','split-inner'],true)){
                try{$boundary->run('owned.inner',static function()use($run,$mode,&$innerLimit):void{$innerLimit=$run();if($mode==='inner-timeout'){usleep(250000);}if($mode==='inner-error'){throw new StorageException('Owned inner abort.','test.inner');}},null,null,new Deadline($mode==='long-inner'?5000:200),$mode==='split-inner'?new Deadline(3000):null);}catch(StorageException $error){$innerReason=$error->reason();if(!in_array($mode,['inner-error','inner-timeout'],true)){throw $error;}}
                $limit=$run();
            }elseif($mode==='locked'){
                $other->exec($mysql?'START TRANSACTION':'BEGIN IMMEDIATE');$other->exec('UPDATE sosecurity_operation_budget SET value=2 WHERE id=1');$start=microtime(true);OperationBudgetConnection::$armed=true;
                try{$unit->run(static function()use($unit,$mysql,$read,&$body,&$limit):void{++$body;$limit=$read();$unit->query('SELECT value FROM sosecurity_operation_budget WHERE id=1'.($mysql?' FOR UPDATE':''))->closeCursor();});}
                catch(StorageException $error){$innerReason=$error->reason();throw $error;}
                finally{OperationBudgetConnection::$armed=false;if(!$mysql){$limit=OperationBudgetConnection::$limit;}$seconds=microtime(true)-$start;$other->exec('ROLLBACK');}
            }else{$limit=$run();}
            $afterLimit=$read();
        };
        try{
            if($mode==='outside-observation'){$u=SqlTransaction::forObservation($pdo,$clock,10000);$limit=$u->run($read);}
            elseif($mode==='outside-effect'){$unit->run(static function()use(&$body):void{++$body;});}
            else{$admission=$mode==='split-expired'?static function():bool{usleep(150000);return true;}:null;
                $admissionBudget=$mode==='no-budget'?null:new Deadline(in_array($mode,['short-inner','inner-error','inner-timeout','split-inner','execution-shorter'],true)?5000:($mode==='split-budget'?200:($mode==='split-expired'?100:1000)));
                $executionBudget=in_array($mode,['split-budget','split-expired'],true)?new Deadline(5000):($mode==='execution-shorter'?new Deadline(1000):null);
                $boundary->run('owned.operation',$operation,$admission,null,$admissionBudget,$executionBudget);
                if($mode==='next-operation'){$boundary->run('owned.next',static function()use($unit,$read,&$afterLimit):void{$afterLimit=$unit->run($read);});}}
        }catch(SoSecurity\Exception\SecurityException|SoSecurity\Exception\ConfigurationException $error){$reason=$error->reason();}
        $status=$witness->inspect(static function():bool{return true;},true)['status'];
        echo 'OBSERVATION operation budget '.json_encode(['backend'=>$backend,'mode'=>$mode,'limit'=>$limit,'inner_limit'=>$innerLimit,'restored'=>$afterLimit,'body'=>$body,'reason'=>$reason,'inner_reason'=>$innerReason,'status'=>$status,'wait_seconds'=>$seconds]).PHP_EOL;
        $scale=$mysql?1:1000;
        if(in_array($mode,['no-budget','outside-observation','opaque'],true)){Check::same(true,$limit>=9*$scale&&$limit<=10*$scale);}
        elseif($mode==='outside-effect'){Check::same('account.state_required',$reason);Check::same(0,$body);}
        elseif($mode==='split-expired'){Check::same('account.operation_timeout',$reason);Check::same(0,$body);}
        elseif($mode==='split-budget'){Check::same(true,$limit>=2*$scale&&$limit<=5*$scale);}
        elseif($mode==='split-inner'){Check::same(true,$innerLimit>=$scale*2&&$innerLimit<=3*$scale);Check::same(true,$limit>=2*$scale&&$limit<=5*$scale);}
        elseif(in_array($mode,['short-inner','inner-error','inner-timeout'],true)){Check::same(true,$innerLimit>0&&$innerLimit<=$scale);Check::same(true,$limit>=$scale*2&&$limit<=5*$scale);Check::same($mode==='inner-error'?'test.inner':($mode==='inner-timeout'?'account.operation_timeout':null),$innerReason);}
        else{Check::same(true,$limit>0&&$limit<=$scale);if($mode==='long-inner'){Check::same(true,$innerLimit>0&&$innerLimit<=$scale);}}
        if($mode==='locked'){Check::same('account.completion_unknown',$reason);Check::same('pending',$status);Check::same(true,in_array($innerReason,['sql.timeout','sql.unavailable'],true));Check::same(true,$seconds<3.0);}
        else{Check::same($mode==='outside-effect'?'account.state_required':($mode==='split-expired'?'account.operation_timeout':null),$reason);Check::same('current',$status);}
        if($mode==='next-operation'){Check::same(true,$afterLimit>=9*$scale&&$afterLimit<=10*$scale);}
        elseif(!in_array($mode,['outside-effect','outside-observation','locked','split-expired'],true)){Check::same(19*$scale,$afterLimit);}
        Check::same(1,(int)$other->query('SELECT value FROM sosecurity_operation_budget WHERE id=1')->fetchColumn());
        echo 'PASS SQL operation budget '.$mode.' '.$backend.' PHP '.PHP_VERSION.PHP_EOL;
    }finally{if($pdo instanceof PDO){try{$pdo->exec('ROLLBACK');}catch(Throwable $cleanup){}}if($other instanceof PDO){try{$other->exec('ROLLBACK');}catch(Throwable $cleanup){}}if($created){$other->exec('DROP TABLE sosecurity_operation_budget');}$pdo=null;$other=null;foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST) as $node){if($node->isDir()&&!$node->isLink()){rmdir($node->getPathname());}else{unlink($node->getPathname());}}rmdir($directory);}
}
