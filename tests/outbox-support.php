<?php
declare(strict_types=1);
require_once __DIR__.'/webhook-inbox-support.php';

final class OutboxEnvironment
{
    public $pdo;
    public $observer;
    public $clock;
    public $policy;
    public $keys;
    public $epoch;
    public $mysql;
    public $directory;
    public $database;
    public $allowed=true;
    public $managed=true;
    public $calls=0;
    public $onAuthority;
    public $onManagement;
    public function __construct(bool $mysql=false,?SoSecurity\Outbox\Policy $policy=null)
    {
        $this->mysql=$mysql;$this->clock=new TestClock();$this->policy=$policy ?? new SoSecurity\Outbox\Policy();$this->keys=new SoSecurity\Support\HmacKeys('old',['old'=>str_repeat('o',32)]);$this->epoch=str_repeat('e',64);
        if($mysql){$dsn='mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4';}
        else{$this->directory=privateDirectory();$this->database=$this->directory.'/outbox.sqlite';$dsn='sqlite:'.$this->database;}
        $options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}
        $this->pdo=new InboxTestConnection($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);$this->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$this->pdo]]);
        foreach(['sosecurity_outbox_records','sosecurity_outbox_roots','outbox_test_business'] as $table){$this->pdo->exec('DROP TABLE IF EXISTS '.$table);}
        $ddl=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/outbox-'.($mysql?'mysql':'sqlite').'.sql'));
        foreach(explode(';',$ddl) as $sql){if(trim($sql)!==''){$this->pdo->exec($sql);}}
        $this->pdo->exec('CREATE TABLE outbox_test_business(id INT NOT NULL PRIMARY KEY)'.($mysql?' ENGINE=InnoDB':''));
        if(!$mysql){chmod($this->database,0600);}$this->observer=new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);
    }
    public function service(?SoSecurity\Support\HmacKeys $keys=null,?callable $authority=null,?callable $management=null,?string $site=null,?string $epoch=null,?SoSecurity\Outbox\Policy $policy=null):SoSecurity\Outbox\SqlOutbox
    {
        return new SoSecurity\Outbox\SqlOutbox($this->pdo,$site ?? 'outbox-test',$epoch ?? $this->epoch,$keys ?? $this->keys,$authority ?? function(string $action,string $phase,string $scope,string $producer,string $actor,array $metadata):bool{++$this->calls;return $this->onAuthority===null?$this->allowed:($this->onAuthority)($action,$phase,$scope,$producer,$actor,$metadata);},$policy ?? $this->policy,$this->clock,$management ?? function(string $action,string $phase,string $scope,string $producer,string $actor,array $metadata):bool{return $this->onManagement===null?$this->managed:($this->onManagement)($action,$phase,$scope,$producer,$actor,$metadata);});
    }
    public function message(string $reference='event-1',string $body='{"order":1}',string $aggregate='order-1',?int $created=null,string $scope='tenant',string $producer='orders'):SoSecurity\Outbox\Message
    {
        return new SoSecurity\Outbox\Message($scope,$producer,SoSecurity\Outbox\Message::identifier($reference,$created ?? $this->clock->time),'receiver','order.changed',$aggregate,$body);
    }
    public function append(SoSecurity\Outbox\SqlOutbox $service,SoSecurity\Outbox\Message $message,bool $commit=true):SoSecurity\Outbox\Status
    {
        $this->pdo->exec($this->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');
        try{$status=$service->enqueue($message,'alice');$this->pdo->exec($commit?'COMMIT':'ROLLBACK');return $status;}
        catch(Throwable $error){try{$this->pdo->exec('ROLLBACK');}catch(Throwable $ignored){}throw $error;}
    }
    public function count(bool $observer=false):int {return (int)($observer?$this->observer:$this->pdo)->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn();}
    public function rows():array {return $this->pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC);}
    public function business(bool $observer=false):int {return (int)($observer?$this->observer:$this->pdo)->query('SELECT COUNT(*) FROM outbox_test_business')->fetchColumn();}
    public function close():void
    {
        $this->pdo->beforeStatement=null;$this->pdo->afterStatement=null;$this->pdo->afterExec=null;$this->pdo->beforeCommit=null;$this->pdo->afterCommit=null;$this->pdo->failRollback=false;
        try{$this->pdo->exec('ROLLBACK');}catch(Throwable $error){}
        if($this->mysql){$this->pdo->exec('SET autocommit=1');foreach(['sosecurity_outbox_records','sosecurity_outbox_roots','outbox_test_business'] as $table){$this->pdo->exec('DROP TABLE IF EXISTS '.$table);}}
        else{$this->observer=null;$this->pdo=null;cleanDirectory($this->directory);}
    }
}
function outboxCase(bool $mysql,callable $body,?SoSecurity\Outbox\Policy $policy=null):void
{
    $e=new OutboxEnvironment($mysql,$policy);try{$body($e);}finally{$e->close();}
}
function outboxRefused(string $reason,callable $body):void
{
    ++Check::$assertions;try{$body();}catch(SoSecurity\Exception\SecurityException $error){Check::same($reason,$error->reason());return;}catch(SoSecurity\Exception\ConfigurationException $error){Check::same($reason,$error->reason());return;}throw new RuntimeException('Expected '.$reason);
}
