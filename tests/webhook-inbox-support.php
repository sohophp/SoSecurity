<?php
declare(strict_types=1);
// Private synthetic data, real PDO statements/transactions; fault hooks exist only in this test connection.
class InboxTestConnection extends PDO
{
    public $afterStatement;
    public $beforeStatement;
    public $beforeCommit;
    public $afterCommit;
    public $afterExec;
    public $failRollback=false;
    public $queries=0;
    public function exec($statement):int
    {
        ++$this->queries;$command=strtoupper(trim($statement));if($command==='ROLLBACK'&&$this->failRollback){throw new RuntimeException('PRIVATE-ROLLBACK-FAILURE');}
        if($command==='COMMIT'&&$this->beforeCommit!==null){($this->beforeCommit)();}$value=parent::exec($statement);if($value===false){throw new RuntimeException('Test SQL failed.');}
        if($command==='COMMIT'&&$this->afterCommit!==null){($this->afterCommit)();}if($this->afterExec!==null){($this->afterExec)($statement);}return $value;
    }
    public function commit():bool {if($this->beforeCommit!==null){($this->beforeCommit)();}$result=parent::commit();if($this->afterCommit!==null){($this->afterCommit)();}return $result;}
    public function rollBack():bool {if($this->failRollback){throw new RuntimeException('PRIVATE-ROLLBACK-FAILURE');}return parent::rollBack();}
}
class InboxTestStatement extends PDOStatement
{
    private $connection;
    protected function __construct(InboxTestConnection $connection){$this->connection=$connection;}
    public function execute($params=null):bool
    {
        if($this->connection->beforeStatement!==null){($this->connection->beforeStatement)($this->queryString);}
        ++$this->connection->queries;$result=$params===null?parent::execute():parent::execute($params);
        if($result&&$this->connection->afterStatement!==null){($this->connection->afterStatement)($this->queryString);}return $result;
    }
}
final class InboxEnvironment
{
    public $pdo;
    public $clock;
    public $endpoint;
    public $verifier;
    public $inbox;
    public $keys;
    public $seals;
    public $signingSecret;
    public $keyCalls=0;
    public $associationCalls=0;
    public $mapCalls=0;
    public $keyOnline=true;
    public $association=true;
    public $onKey;
    public $onAssociation;
    public $mysql;
    public $directory;
    public $database;
    public function __construct(bool $mysql=false,string $protocol='standard-hmac',array $policy=[])
    {
        $this->mysql=$mysql;$this->clock=new TestClock();
        if($mysql){$this->pdo=new InboxTestConnection('mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);}
        else{$this->directory=privateDirectory();$this->database=$this->directory.'/inbox.sqlite';$this->pdo=new InboxTestConnection('sqlite:'.$this->database,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);chmod($this->database,0600);}
        $this->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$this->pdo]]);$this->install();
        $this->pdo->exec('DROP TABLE IF EXISTS webhook_test_resources');$this->pdo->exec('CREATE TABLE webhook_test_resources(tenant VARCHAR(64) NOT NULL,id VARCHAR(64) NOT NULL,account VARCHAR(64) NOT NULL,enabled INT NOT NULL,version VARCHAR(64) NOT NULL,PRIMARY KEY(tenant,id))'.($mysql?' ENGINE=InnoDB':''));
        $this->pdo->exec("INSERT INTO webhook_test_resources VALUES('tenant','a','provider-account',1,'1'),('tenant','b','provider-account',1,'1'),('other','a','another-account',1,'1')");
        $this->endpoint=new SoSecurity\Webhook\Endpoint('inbox','tenant','provider-account','https://hooks.example/events',$protocol,$policy+($protocol==='github-sha256'?['allow_untimed'=>true]:[]));
        $this->signingSecret=str_repeat('k',32);$verificationKey=$this->signingSecret;if($protocol==='standard-ed25519'){$pair=sodium_crypto_sign_seed_keypair(str_repeat('q',32));$verificationKey=sodium_crypto_sign_publickey($pair);$this->signingSecret=sodium_crypto_sign_secretkey($pair);}$this->keys=new SoSecurity\Webhook\KeySet($this->endpoint,['test'=>$verificationKey]);$this->seals=new SoSecurity\Support\HmacKeys('old',['old'=>str_repeat('s',32)]);
        $this->verifier=new SoSecurity\Webhook\Verifier($this->endpoint,function(){++$this->keyCalls;if($this->onKey!==null){($this->onKey)($this->keyCalls);}if(!$this->keyOnline){return null;}return $this->keys;},static function(){return true;},$this->clock);$this->inbox=$this->service();
    }
    public function install():void
    {
        $this->pdo->exec('DROP TABLE IF EXISTS sosecurity_webhook_inbox');$sql=file_get_contents(dirname(__DIR__).'/resources/sql/webhook-'.($this->mysql?'mysql':'sqlite').'.sql');
        foreach(explode(';',$sql) as $statement){if(trim($statement)!==''){$this->pdo->exec($statement);}}
    }
    public function service(?SoSecurity\Support\HmacKeys $seals=null,?SoSecurity\Webhook\Verifier $verifier=null):SoSecurity\Webhook\SqlInbox
    {
        return new SoSecurity\Webhook\SqlInbox($this->pdo,'inbox-test-site',$verifier ?? $this->verifier,$seals ?? $this->seals,function(SoSecurity\Webhook\Endpoint $endpoint,SoSecurity\Webhook\Message $message){++$this->associationCalls;if($this->onAssociation!==null){($this->onAssociation)($this->associationCalls);}if($this->association!==true){return $this->association;}$query=$this->pdo->prepare('SELECT account,enabled,version FROM webhook_test_resources WHERE tenant=:tenant AND id=:id'.($this->mysql&&$this->pdo->inTransaction()?' FOR UPDATE':''));$query->execute(['tenant'=>$endpoint->scope(),'id'=>$message->resource()]);$row=$query->fetch(PDO::FETCH_ASSOC);return is_array($row)&&$row['account']===$endpoint->account()&&(int)$row['enabled']===1&&($message->context()['version'] ?? null)===$row['version'];},$this->clock);
    }
    public function body(array $overrides=[]):string {return json_encode($overrides+['id'=>'msg_test','type'=>'document.changed','resource'=>'a','account'=>'provider-account','version'=>'1']);}
    public function request(?string $body=null,?int $timestamp=null,array $extraHeaders=[]):SoSecurity\Webhook\Request
    {
        $body=$body ?? $this->body();$time=$timestamp ?? $this->clock->time;$protocol=$this->endpoint->protocol();
        if($protocol==='github-sha256'){$headers=['X-Hub-Signature-256'=>'sha256='.hash_hmac('sha256',$body,str_repeat('k',32)),'X-GitHub-Delivery'=>'untrusted-original','X-GitHub-Event'=>'unsigned-type'];}
        elseif($protocol==='stripe-v1'){$headers=['Stripe-Signature'=>'t='.$time.',v1='.hash_hmac('sha256',$time.'.'.$body,str_repeat('k',32))];}
        else{$message='msg_test.'.$time.'.'.$body;$signature=$protocol==='standard-ed25519'?sodium_crypto_sign_detached($message,$this->signingSecret):hash_hmac('sha256',$message,$this->signingSecret,true);$headers=['Webhook-Id'=>'msg_test','Webhook-Timestamp'=>(string)$time,'Webhook-Signature'=>($protocol==='standard-ed25519'?'v1a,':'v1,').base64_encode($signature)];}
        return new SoSecurity\Webhook\Request('POST',$this->endpoint->url(),$body,$extraHeaders+$headers);
    }
    public function mapper():callable
    {
        return function(SoSecurity\Webhook\VerifiedWebhook $proof):?SoSecurity\Webhook\Message{++$this->mapCalls;$body=json_decode($proof->body(),true,8);if(!is_array($body)||count($body)!==5){return null;}foreach(['id','type','resource','account','version'] as $field){if(!is_string($body[$field] ?? null)){return null;}}if($body['account']!==$proof->endpoint()->account()){return null;}$id=$proof->endpoint()->protocol()==='github-sha256'?'body:'.$proof->bodyDigest():$body['id'];return new SoSecurity\Webhook\Message($id,$body['type'],$body['resource'],['version'=>$body['version']]);};
    }
    public function receive(?SoSecurity\Webhook\Request $request=null):?SoSecurity\Webhook\Receipt {return $this->inbox->accept($request ?? $this->request(),$this->mapper());}
    public function count():int {return (int)$this->pdo->query('SELECT COUNT(*) FROM sosecurity_webhook_inbox')->fetchColumn();}
    public function snapshot():array {return $this->pdo->query('SELECT * FROM sosecurity_webhook_inbox ORDER BY endpoint_key,event_key')->fetchAll(PDO::FETCH_ASSOC);}
    public function close():void
    {
        $this->pdo->afterStatement=null;$this->pdo->beforeStatement=null;$this->pdo->beforeCommit=null;$this->pdo->afterCommit=null;$this->pdo->afterExec=null;
        if($this->mysql){foreach(['sosecurity_webhook_inbox','webhook_test_resources'] as $table){$this->pdo->exec('DROP TABLE IF EXISTS '.$table);}}
        else{foreach(new DirectoryIterator($this->directory) as $entry){if(!$entry->isDot()){unlink($entry->getPathname());}}rmdir($this->directory);}
    }
}
function inboxCase(bool $mysql,callable $operation,string $protocol='standard-hmac',array $policy=[]):void
{
    $e=new InboxEnvironment($mysql,$protocol,$policy);try{$operation($e);}finally{$e->close();}
}
