<?php
declare(strict_types=1);
require_once __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Support\SqlTransaction;
final class EnlistmentTestConnection extends InboxTestConnection
{
    public $beforeExec;
    public function exec($statement):int
    {
        if($this->beforeExec!==null){($this->beforeExec)($statement);}
        return parent::exec($statement);
    }
}

/** Real SQL, private tables and an independent observer. The only simulated parts are explicit failure hooks. */
final class EnlistmentEnvironment
{
    public $pdo;
    public $observer;
    public $clock;
    public $mysql;
    private $directory;
    private $dsn;
    private $idempotency=false;
    public function __construct(bool $mysql)
    {
        $this->mysql=$mysql;$this->clock=new TestClock();
        if($mysql){$this->dsn='mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4';}
        else{$this->directory=privateDirectory();$this->dsn='sqlite:'.$this->directory.'/enlistment.sqlite';}
        $options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}
        $this->pdo=new EnlistmentTestConnection($this->dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);
        $this->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$this->pdo]]);
        foreach(['enlistment_test_intents','enlistment_test_business'] as $table){
            $this->pdo->exec('DROP TABLE IF EXISTS '.$table);
            $this->pdo->exec('CREATE TABLE '.$table.'(id INT NOT NULL PRIMARY KEY)'.($mysql?' ENGINE=InnoDB':''));
        }
        if(!$mysql){chmod($this->directory.'/enlistment.sqlite',0600);}
        $this->observer=new PDO($this->dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);
    }
    public function unit(int $milliseconds=1000):SqlTransaction {return new SqlTransaction($this->pdo,$this->clock,$milliseconds);}
    public function begin(string $mode='sql'):void {if($mode==='native'){$this->pdo->beginTransaction();}else{$this->pdo->exec($this->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');}}
    public function rows(string $table,bool $observer=false):array
    {
        $pdo=$observer?$this->observer:$this->pdo;
        return array_map('intval',$pdo->query('SELECT id FROM enlistment_test_'.$table.' ORDER BY id')->fetchAll(PDO::FETCH_COLUMN));
    }
    public function business(int $id=1):void {$this->pdo->exec('INSERT INTO enlistment_test_business VALUES('.$id.')');}
    public function intent(SqlTransaction $unit,int $id=1):void {$unit->query('INSERT INTO enlistment_test_intents VALUES(:id)',['id'=>$id])->closeCursor();}
    public function installIdempotency():void
    {
        $this->idempotency=true;
        foreach(['sosecurity_idempotency_records','sosecurity_idempotency_roots'] as $table){$this->pdo->exec('DROP TABLE IF EXISTS '.$table);}
        $sql=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/idempotency-'.($this->mysql?'mysql':'sqlite').'.sql'));
        foreach(explode(';',$sql) as $statement){if(trim($statement)!==''){$this->pdo->exec($statement);}}
    }
    public function close():void
    {
        $this->pdo->beforeStatement=null;$this->pdo->afterStatement=null;$this->pdo->beforeExec=null;$this->pdo->afterExec=null;$this->pdo->afterCommit=null;$this->pdo->failRollback=false;
        try{$this->pdo->exec('ROLLBACK');}catch(Throwable $error){}
        if($this->idempotency){foreach(['sosecurity_idempotency_records','sosecurity_idempotency_roots'] as $table){$this->pdo->exec('DROP TABLE IF EXISTS '.$table);}}
        if($this->mysql){$this->pdo->exec('SET autocommit=1');foreach(['enlistment_test_intents','enlistment_test_business'] as $table){$this->pdo->exec('DROP TABLE '.$table);}}
        else{$this->observer=null;$this->pdo=null;cleanDirectory($this->directory);}
    }
}
function enlistCase(bool $mysql,callable $body):void
{
    $e=new EnlistmentEnvironment($mysql);try{$body($e);}finally{$e->close();}
}
function enlistRefused(string $reason,callable $body):void
{
    ++Check::$assertions;
    try{$body();}catch(SecurityException $error){Check::same($reason,$error->reason());Check::same(false,strpos($error->getMessage(),'SYNTHETIC-SECRET')!==false);return;}
    catch(ConfigurationException $error){Check::same($reason,$error->reason());return;}
    throw new RuntimeException('Expected '.$reason);
}
