<?php
declare(strict_types=1);
require_once __DIR__.'/webhook-inbox-support.php';

final class IdempotencyEnvironment
{
    public $pdo;
    public $clock;
    public $keys;
    public $epoch;
    public $directory;
    public $database;
    public $mysql;
    public $allowed=true;
    public $managed=true;
    public $authorityCalls=0;
    public $managementCalls=0;
    public $handlerCalls=0;
    public $onAuthority;
    public $onManagement;
    public $policy;
    public function __construct(bool $mysql=false,?SoSecurity\Idempotency\Policy $policy=null)
    {
        $this->mysql=$mysql;$this->clock=new TestClock();$this->epoch=str_repeat('e',64);$this->keys=new SoSecurity\Support\HmacKeys('old',['old'=>str_repeat('i',32)]);$this->policy=$policy ?? new SoSecurity\Idempotency\Policy();
        if($mysql){$this->pdo=new InboxTestConnection('mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);}
        else{$this->directory=privateDirectory();$this->database=$this->directory.'/idempotency.sqlite';$this->pdo=new InboxTestConnection('sqlite:'.$this->database,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);chmod($this->database,0600);}
        $this->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$this->pdo]]);
        foreach(['sosecurity_idempotency_records','sosecurity_idempotency_roots','idempotency_test_business'] as $table){$this->pdo->exec('DROP TABLE IF EXISTS '.$table);}
        $schema=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/idempotency-'.($mysql?'mysql':'sqlite').'.sql'));
        foreach(explode(';',$schema) as $sql){if(trim($sql)!==''){$this->pdo->exec($sql);}}
        $this->pdo->exec('CREATE TABLE idempotency_test_business(tenant VARCHAR(64) NOT NULL,subject VARCHAR(64) NOT NULL,reference_id VARCHAR(64) NOT NULL,execution_id CHAR(32) NOT NULL,amount INT NOT NULL,PRIMARY KEY(tenant,subject,reference_id))'.($mysql?' ENGINE=InnoDB':''));
    }
    public function service(?SoSecurity\Support\HmacKeys $keys=null,?callable $authority=null,?callable $management=null,?string $site=null,?string $epoch=null,?SoSecurity\Idempotency\Policy $policy=null):SoSecurity\Idempotency\SqlExecutor
    {
        return new SoSecurity\Idempotency\SqlExecutor($this->pdo,$site ?? 'idem-test',$epoch ?? $this->epoch,$keys ?? $this->keys,$authority ?? function(string $phase,$request,array $metadata):bool{++$this->authorityCalls;if($this->onAuthority!==null){return ($this->onAuthority)($phase,$request,$metadata);}return $this->allowed;},$policy ?? $this->policy,$this->clock,$management ?? function(string $operation,string $scope,string $subject,string $action):bool{++$this->managementCalls;return $this->onManagement!==null?($this->onManagement)($operation,$scope,$subject,$action):$this->managed;});
    }
    public function request(string $key='request-key-00000001',string $reference='order-1',string $scope='tenant',string $subject='alice',string $operation='orders.create'):SoSecurity\Idempotency\Request
    {
        return new SoSecurity\Idempotency\Request($scope,$subject,$operation,$key,'POST','/orders',json_encode(['reference'=>$reference,'amount'=>5]),['content_type'=>'application/json']);
    }
    /**
     * Prepare synthetic empty state outside the operation whose short deadline is under test.
     * The real initializer uses a generous setup budget; only the empty test root is then sealed for the target policy.
     * This is trusted test-data provisioning, never a production policy migration or a deadline override in the service.
     */
    public function initializeTimingFixture():void
    {
        $setupPolicy=new SoSecurity\Idempotency\Policy(array_replace($this->policy->options(),['io_milliseconds'=>30000]));
        if(!$this->service(null,null,null,null,null,$setupPolicy)->initialize('tenant','alice','orders.create')){throw new RuntimeException('Timing tests require a fresh empty namespace.');}
        $namespace=SoSecurity\Idempotency\State::namespace('idem-test','tenant','alice','orders.create');
        $query=$this->pdo->prepare('SELECT '.implode(',',SoSecurity\Idempotency\State::rootFields()).' FROM sosecurity_idempotency_roots WHERE namespace=:namespace');$query->execute(['namespace'=>$namespace]);
        $row=SoSecurity\Idempotency\State::root($query->fetch(PDO::FETCH_ASSOC),$this->keys,$setupPolicy,$namespace,$this->epoch,$this->clock->now());$query->closeCursor();
        if($row['entries']!==0){throw new RuntimeException('Never reconfigure nonempty timing test data.');}
        $row['policy']=$this->policy->fingerprint();$row=SoSecurity\Idempotency\State::seal($row,$this->keys,true);
        $update=$this->pdo->prepare('UPDATE sosecurity_idempotency_roots SET policy=:policy,seal_key=:seal_key,seal=:seal WHERE namespace=:namespace AND entries=0');
        $update->execute(['policy'=>$row['policy'],'seal_key'=>$row['seal_key'],'seal'=>$row['seal'],'namespace'=>$namespace]);$update->closeCursor();
    }
    public function handler():callable
    {
        return function(PDO $pdo,SoSecurity\Idempotency\Request $request,string $execution):SoSecurity\Idempotency\Response{
            ++$this->handlerCalls;$body=json_decode($request->body(),true);$query=$pdo->prepare('INSERT INTO idempotency_test_business VALUES(:tenant,:subject,:reference,:execution,:amount)');$query->execute(['tenant'=>$request->scope(),'subject'=>$request->subject(),'reference'=>$body['reference'],'execution'=>$execution,'amount'=>$body['amount']]);
            return new SoSecurity\Idempotency\Response(201,json_encode(['execution'=>$execution,'reference'=>$body['reference']]));
        };
    }
    public function reconnect():void
    {
        // Recovery deliberately rebuilds the PDO, not only the service: old MySQL PDO can retain a stale transaction flag.
        $this->pdo=new InboxTestConnection($this->mysql?'mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$this->database,$this->mysql?'sosecurity_test':null,$this->mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);
        if($this->mysql){$this->pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);}
        $this->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$this->pdo]]);
    }
    public function count():int {return (int)$this->pdo->query('SELECT COUNT(*) FROM idempotency_test_business')->fetchColumn();}
    public function records():array {return $this->pdo->query('SELECT * FROM sosecurity_idempotency_records ORDER BY namespace,key_hash')->fetchAll(PDO::FETCH_ASSOC);}
    public function close():void
    {
        $this->pdo->beforeStatement=null;$this->pdo->afterStatement=null;$this->pdo->beforeCommit=null;$this->pdo->afterCommit=null;$this->pdo->afterExec=null;$this->pdo->failRollback=false;
        try{if($this->mysql){$this->pdo->exec('ROLLBACK');}else{try{$this->pdo->exec('ROLLBACK');}catch(Throwable $error){}}}finally{
            if($this->mysql){foreach(['sosecurity_idempotency_records','sosecurity_idempotency_roots','idempotency_test_business'] as $table){$this->pdo->exec('DROP TABLE IF EXISTS '.$table);}}
            else{foreach(new DirectoryIterator($this->directory) as $file){if(!$file->isDot()){unlink($file->getPathname());}}rmdir($this->directory);}
        }
    }
}
function idemCase(bool $mysql,callable $body,?SoSecurity\Idempotency\Policy $policy=null):void
{
    $e=new IdempotencyEnvironment($mysql,$policy);try{$body($e);}finally{$e->close();}
}
