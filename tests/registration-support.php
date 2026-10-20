<?php
declare(strict_types=1);
require_once dirname(__DIR__).'/examples/SqlAccounts.php';
require_once __DIR__.'/webhook-inbox-support.php';
if(($argv[1] ?? '')==='mysql'){
    $ownedSocket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
    if(!is_string($ownedSocket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$ownedSocket)||is_link(dirname($ownedSocket))||!is_file(dirname($ownedSocket).'/account-test-owner')){throw new RuntimeException('MySQL tests require the owned disposable local instance.');}
}

final class RegistrationEnvironment
{
    public $directory;
    public $pdo;
    public $observer;
    public $clock;
    public $accounts;
    public $policy;
    public $hasher;
    public $onAuthority;
    public $onManagement;
    public $onDelivery;
    public $onBudget;
    public $onHash;
    public $authorityCalls=0;
    public $managementCalls=0;
    public $deliveryCalls=0;
    public $budgetCalls=0;
    public $hashCalls=0;
    public $limiter;
    public $subjects;
    public $reservations=[];
    public $mysql=false;
    public function __construct(array $options=[],int $limit=1000)
    {
        $this->directory=privateDirectory();mkdir($this->directory.'/budgets',0700);$socket=$GLOBALS['registrationMySQLSocket'] ?? '';$this->mysql=$socket!=='';
        $dsn=$this->mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$this->directory.'/registration.sqlite';$pdoOptions=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION];if($this->mysql){$pdoOptions[PDO::ATTR_EMULATE_PREPARES]=false;}
        $this->pdo=new InboxTestConnection($dsn,$this->mysql?'sosecurity_test':null,$this->mysql?'integration-only':null,$pdoOptions);$this->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$this->pdo]]);
        foreach(['account_example','sosecurity_account_records','sosecurity_account_roots','sosecurity_outbox_records','sosecurity_outbox_roots'] as $table){$this->pdo->exec('DROP TABLE IF EXISTS '.$table);}
        if(!$this->mysql){$this->pdo->exec('PRAGMA synchronous=FULL');$this->pdo->exec('PRAGMA journal_mode=DELETE');}$suffix=$this->mysql?'mysql':'sqlite';
        foreach([dirname(__DIR__).'/resources/sql/account-'.$suffix.'.sql',dirname(__DIR__).'/resources/sql/account-example-'.$suffix.'.sql',dirname(__DIR__).'/resources/sql/outbox-'.$suffix.'.sql'] as $file){$ddl=preg_replace('/^--.*$/m','',file_get_contents($file));foreach(explode(';',$ddl) as $sql){if(trim($sql)!==''){$this->pdo->exec($sql);}}}
        if(!$this->mysql){chmod($this->directory.'/registration.sqlite',0600);}$this->observer=new PDO($dsn,$this->mysql?'sosecurity_test':null,$this->mysql?'integration-only':null,$pdoOptions);$this->clock=new TestClock();$this->policy=new SoSecurity\Account\Policy($options);$this->accounts=new SoSecurity\Account\Example\SqlAccounts($this->pdo);$this->hasher=new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]);
        $store=new SoSecurity\Storage\FileStore($this->directory.'/budgets','registration-budget',$this->clock);$limits=[];
        foreach(['site','source','target'] as $name){$limits[$name]=new SoSecurity\RateLimit\BudgetLimiter($store,new SoSecurity\RateLimit\BudgetPolicy('fixed_window',$limit,60),$this->clock);}
        $this->limiter=new SoSecurity\RateLimit\CompositeLimiter($limits,$this->clock);$this->subjects=new SoSecurity\RateLimit\BudgetLimiter($store,new SoSecurity\RateLimit\BudgetPolicy('fixed_window',$limit,60),$this->clock);
    }
    public function service(?PDO $connection=null,?SoSecurity\Account\Repository $accounts=null,string $scope='tenant',string $epoch='',?SoSecurity\Support\HmacKeys $seals=null,?SoSecurity\Account\Notifications $notices=null):SoSecurity\Account\Registration
    {
        $authority=function(string $action,string $phase,string $scope,?SoSecurity\Account\AccountRecord $record):bool{++$this->authorityCalls;return $this->onAuthority===null?true:($this->onAuthority)($action,$phase,$scope,$record);};
        $management=function(string $action,string $phase,string $scope,?SoSecurity\Account\AccountRecord $record):bool{++$this->managementCalls;return $this->onManagement===null?true:($this->onManagement)($action,$phase,$scope,$record);};
        $delivery=function(string $action,string $phase,string $scope,?SoSecurity\Account\AccountRecord $record):bool{++$this->deliveryCalls;return $this->onDelivery===null?true:($this->onDelivery)($action,$phase,$scope,$record);};
        $budget=function(string $action,string $phase,string $scope,string $source,?SoSecurity\Account\Address $address,?string $subject):bool{
            ++$this->budgetCalls;if($this->onBudget!==null&&($this->onBudget)($action,$phase,$scope,$source,$address,$subject)!==true){return false;}
            if($phase==='public'){
                $bindings=['site'=>'all','source'=>hash_hmac('sha256',$source,str_repeat('b',32)),'target'=>hash_hmac('sha256',$action.':'.($address===null?'confirmation':$address->value()),str_repeat('b',32))];
                $decision=$this->limiter->consume('registration-'.$scope,$bindings);$this->reservations[$action.':'.$source]=$decision->reservedUntil();return $decision->allowed();
            }
            if($phase==='subject'){$decision=$this->subjects->consume('registration-subject-'.$scope,$subject);$this->reservations[$action.':'.$source]=min($this->reservations[$action.':'.$source],$decision->reservedUntil());return $decision->allowed();}
            return $phase==='final'&&isset($this->reservations[$action.':'.$source])&&$this->clock->time<$this->reservations[$action.':'.$source];
        };
        $passwords=SoSecurity\Password\PasswordPolicy::forHasher($this->hasher,15,null,null,function(string $password):bool{++$this->hashCalls;if($this->onHash!==null){($this->onHash)($password);}return false;});
        return new SoSecurity\Account\Registration($connection ?? $this->pdo,'account-test',$scope,$epoch===''?str_repeat('e',64):$epoch,$seals ?? new SoSecurity\Support\HmacKeys('account',['account'=>str_repeat('a',32)]),new SoSecurity\Support\HmacKeys('outbox',['outbox'=>str_repeat('o',32)]),$accounts ?? $this->accounts,$notices ?? new SoSecurity\Account\Notifications('mail',['mail'=>str_repeat('m',32)],$this->clock),$this->hasher,$passwords,$authority,$budget,$this->policy,$this->clock,$management,$delivery);
    }
    public function notices():array {return $this->pdo->query('SELECT payload_body FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_COLUMN);}
    public function flow(string $selector):array {$q=$this->pdo->prepare('SELECT payload FROM sosecurity_account_records WHERE record_id=:id');$q->execute(['id'=>$selector]);return json_decode($q->fetchColumn(),true);}
    public function account():array {return $this->observer->query('SELECT * FROM account_example')->fetch(PDO::FETCH_ASSOC);}
    public function count(string $table):int {return (int)$this->observer->query('SELECT COUNT(*) FROM '.$table)->fetchColumn();}
    public function close():void
    {
        $this->pdo->beforeStatement=null;$this->pdo->afterStatement=null;$this->pdo->beforeCommit=null;$this->pdo->afterCommit=null;$this->pdo->afterExec=null;
        $this->onAuthority=null;$this->onManagement=null;$this->onDelivery=null;$this->onBudget=null;$this->onHash=null;$this->observer=null;$this->accounts=null;$this->pdo=null;$this->limiter=null;$this->subjects=null;
        cleanDirectory($this->directory.'/budgets');cleanDirectory($this->directory);
    }
}
function registrationCase(callable $operation,array $options=[],int $limit=1000):void {$e=new RegistrationEnvironment($options,$limit);try{$operation($e);}finally{$e->close();}}
