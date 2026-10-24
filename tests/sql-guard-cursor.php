<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlTransactionGuard;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\Deadline;
use SoSecurity\Exception\SecurityException;

final class GuardCursorConnection extends PDO
{
    public static $queries=0;
    #[\ReturnTypeWillChange]
    public function query($query,...$arguments)
    {
        if($query==='SELECT @@SESSION.autocommit'){
            ++self::$queries;
            if(GuardCursorStatement::$mode==='execute-false'){return false;}
            if(GuardCursorStatement::$mode==='execute-throw'){throw new RuntimeException('PRIVATE-GUARD-QUERY');}
        }
        return parent::query(...func_get_args());
    }
}

final class GuardCursorStatement extends PDOStatement
{
    public static $mode='normal';
    public static $closed=0;
    private function target():bool{return $this->queryString==='SELECT @@SESSION.autocommit';}
    public function execute($parameters=null):bool
    {
        if($this->target()&&self::$mode==='execute-false'){return false;}
        if($this->target()&&self::$mode==='execute-throw'){throw new RuntimeException('PRIVATE-GUARD-EXECUTE');}
        return parent::execute(...func_get_args());
    }
    #[\ReturnTypeWillChange]
    public function fetchColumn($column=0)
    {
        if($this->target()&&self::$mode==='fetch-throw'){throw new RuntimeException('PRIVATE-GUARD-FETCH');}
        return parent::fetchColumn($column);
    }
    public function closeCursor():bool
    {
        $closed=parent::closeCursor();if(!$this->target()){return $closed;}++self::$closed;
        if(self::$mode==='close-throw'){throw new RuntimeException('PRIVATE-GUARD-CLOSE');}
        return self::$mode==='close-false'?false:$closed;
    }
}
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$dsn='mysql:unix_socket='.$socket.';dbname=sosecurity_test';$options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false];
$observer=new PDO($dsn,'sosecurity_test','integration-only',$options);$created=false;
try{
    $observer->exec('CREATE TABLE sosecurity_guard_cursor(id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB');$created=true;
    foreach(['normal','close-false','close-throw','fetch-throw','execute-false','execute-throw'] as $mode){
        foreach(['assertIdle','active','assertActive','run','enlist','inContext'] as $method){
            $pdo=new GuardCursorConnection($dsn,'sosecurity_test','integration-only',$options);$host=!in_array($method,['assertIdle','run'],true);$body=0;$reason=null;$result=null;
            try{
                if($host){$pdo->beginTransaction();$pdo->exec('INSERT INTO sosecurity_guard_cursor VALUES(1)');}
                $pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[GuardCursorStatement::class]);GuardCursorStatement::$mode=$mode;GuardCursorStatement::$closed=0;GuardCursorConnection::$queries=0;
                try{
                    if($method==='assertIdle'){SqlTransactionGuard::assertIdle($pdo,'mysql',new Deadline(10000));}
                    elseif($method==='active'){$result=SqlTransactionGuard::active($pdo,'mysql',new Deadline(10000));}
                    elseif($method==='assertActive'){SqlTransactionGuard::assertActive($pdo,'mysql',new Deadline(10000));}
                    else{$unit=new SqlTransaction($pdo,new TestClock(),10000);$result=$unit->$method(static function()use(&$body):int{++$body;return 17;});}
                }catch(SecurityException|SoSecurity\Exception\ConfigurationException $error){$reason=$error->reason();if(!in_array($method,['enlist','inContext'],true)){Check::same(null,$error->getPrevious());}Check::same(false,strpos((string)$error,'PRIVATE-GUARD-')!==false);}
                echo 'OBSERVATION guard cursor '.json_encode(['mode'=>$mode,'method'=>$method,'reason'=>$reason,'body'=>$body,'closes'=>GuardCursorStatement::$closed]).PHP_EOL;
                if($mode==='normal'){
                    Check::same(null,$reason);Check::same(in_array($method,['run','enlist','inContext'],true)?1:0,$body);
                    if($method==='active'){Check::same(true,$result);}elseif(in_array($method,['run','enlist','inContext'],true)){Check::same(17,$result);}
                }else{Check::same(in_array($method,['enlist','inContext'],true)?'sql.cleanup':'storage.transaction_state',$reason);Check::same(0,$body);}
                Check::same($host?1:0,GuardCursorConnection::$queries);
                Check::same(true,$host&&in_array($mode,['execute-false','execute-throw'],true)?GuardCursorStatement::$closed===0:GuardCursorStatement::$closed>=1);
                GuardCursorStatement::$mode='normal';
                Check::same($host,$pdo->inTransaction());
                Check::same(0,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_guard_cursor')->fetchColumn());
                if($host){Check::same(1,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_guard_cursor')->fetchColumn());$pdo->rollBack();}
                echo 'PASS SQL guard cursor '.$mode.' '.$method.' PHP '.PHP_VERSION.PHP_EOL;
            }finally{GuardCursorStatement::$mode='normal';if($pdo->inTransaction()){$pdo->rollBack();}$pdo=null;}
        }
    }
}finally{if($created){$observer->exec('DROP TABLE sosecurity_guard_cursor');}}
