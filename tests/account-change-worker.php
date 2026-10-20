<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';
require dirname(__DIR__).'/examples/SqlAccounts.php';

// Observe only private test-driver failures; never accept an arbitrary cleanup error as contention.
final class ChangeRaceConnection extends InboxTestConnection {public $firstSqlFailure;}
final class ChangeRaceStatement extends InboxTestStatement
{
    private $raceConnection;
    protected function __construct(ChangeRaceConnection $connection){parent::__construct($connection);$this->raceConnection=$connection;}
    public function execute($params=null):bool
    {
        try{return parent::execute($params);}catch(PDOException $error){if($this->raceConnection->firstSqlFailure===null){$this->raceConnection->firstSqlFailure=[$error->errorInfo[0] ?? '',$error->errorInfo[1] ?? 0];}throw $error;}
    }
}

$backend=$argv[6] ?? '';if(!in_array($backend,['sqlite','mysql'],true)){throw new RuntimeException('Select the local test backend explicitly.');}
$directory=$argv[1] ?? '';$mode=$argv[2] ?? '';$actor=$argv[3] ?? '';$index=$argv[4] ?? '';$option=$argv[5] ?? '';
if(!preg_match('~\A/tmp/change-race-[A-Za-z0-9_-]+\z~D',$directory)||is_link($directory)||!is_file($directory.'/test-owner')||file_get_contents($directory.'/test-owner')!=="owned address-change concurrency test\n"||!in_array($mode,['setup','old','new','cancel','ready','approve','complete','inspect','expire','maintain'],true)||!in_array($actor,['alice','bob'],true)||!preg_match('/\A[0-9]{1,2}\z/D',$index)||!in_array($option,['','single','unique','kill-before','kill-after'],true)){throw new RuntimeException('Expected the owned disposable address-change test directory.');}
try{
    $contextFile=$directory.'/context.json';$setup=$mode==='setup';
    if($setup){
        if(is_file($directory.'/race.sqlite')||is_file($contextFile)){throw new RuntimeException('Refuse to replace an existing test database.');}
        $context=['now'=>100000,'target'=>$option==='unique'?'shared@example.com':'new@example.com','actors'=>[]];
    }else{
        if(is_link($contextFile)){throw new RuntimeException('Refuse linked private test context.');}
        $context=json_decode(file_get_contents($contextFile,false,null,0,16385),true,8);
        if(!is_array($context)||array_keys($context)!==['now','target','actors']||!is_int($context['now'])||$context['now']<100000||$context['now']>1000000||!in_array($context['target'],['new@example.com','shared@example.com'],true)||!is_array($context['actors'])||!isset($context['actors'][$actor])){throw new RuntimeException('Invalid bounded private test context.');}
    }
    $clock=new TestClock();$clock->time=$context['now'];$password='owned-address-race-password';
    if($backend==='mysql'){
        $socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
        if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||is_link(dirname($socket))||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Expected the owned no-TCP MySQL instance.');}
        $pdo=new ChangeRaceConnection('mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false,PDO::ATTR_TIMEOUT=>5]);
    }else{$pdo=new ChangeRaceConnection('sqlite:'.$directory.'/race.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>5]);$pdo->exec('PRAGMA synchronous=FULL');}
    $pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[ChangeRaceStatement::class,[$pdo]]);
    $hasher=new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]);
    if($setup){
        if($backend==='mysql'){foreach(['sosecurity_account_records','sosecurity_account_roots','sosecurity_outbox_records','sosecurity_outbox_roots','account_example'] as $table){$pdo->exec('DROP TABLE IF EXISTS '.$table);}}
        else{$pdo->exec('PRAGMA journal_mode=DELETE');}
        $suffix=$backend==='mysql'?'mysql':'sqlite';
        foreach(['account','account-example','outbox'] as $name){foreach(explode(';',preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/'.$name.'-'.$suffix.'.sql'))) as $sql){if(trim($sql)!==''){$pdo->exec($sql);}}}
        if($backend==='sqlite'){chmod($directory.'/race.sqlite',0600);}
        foreach($option==='unique'?['alice','bob']:['alice'] as $subject){
            $hash=$hasher->hash($password);$address=$subject.'@original.example';
            $q=$pdo->prepare("INSERT INTO account_example VALUES('tenant',:subject,'initial-version','initial-address',:address,:password,'active',1,0,'[\"member\"]')");$q->execute(['subject'=>$subject,'address'=>$address,'password'=>$hash]);
            $context['actors'][$subject]=['session'=>'','selector'=>'','proofs'=>[],'grant'=>'','initial_password'=>hash('sha256',$hash),'initial_address'=>$address];
        }
    }
    $accounts=new SoSecurity\Account\Example\SqlAccounts($pdo);
    $passwordRecord=static function(string $scope,string $subject)use($accounts){$row=$accounts->find($scope,$subject);return $row===null?null:$accounts->passwordRecord($row);};
    $provider=new SoSecurity\Auth\PasswordIdentityProvider(
        static function(string $scope,string $identifier)use($accounts){$row=$accounts->findAddress($scope,new SoSecurity\Account\Address($identifier));return $row===null?null:$accounts->passwordRecord($row);},$passwordRecord,$hasher,$passwordRecord('tenant','alice')->hash());
    $sessions=new SoSecurity\Auth\SessionRegistry(new SoSecurity\Storage\FileStore($directory.'/sessions','change-race-sessions',$clock,5000),$provider,null,$clock);
    $authentication=new SoSecurity\Auth\AuthenticationFlow(new SoSecurity\Storage\FileStore($directory.'/authentication','change-race-authentication',$clock,5000),$provider,$sessions,static function():bool{return true;},null,$clock);
    $rule=['type'=>'account','roles'=>['member'],'fields'=>['address'],'owner_attribute'=>'owner'];
    $authorizer=new SoSecurity\Authorization\Authorizer($provider,new SoSecurity\Authorization\RolePolicy(['account.address.request'=>$rule,'account.address.complete'=>$rule]));
    $grants=new SoSecurity\Operation\Grants(new SoSecurity\Storage\FileStore($directory.'/grants','change-race-grants',$clock,5000),$sessions,$authorizer,static function():bool{return true;},new SoSecurity\Operation\Policy(120,8,300,1,['password']),$clock);
    $budgetStore=new SoSecurity\Storage\FileStore($directory.'/budgets','change-race-budgets',$clock,5000);$limits=[];
    foreach(['site','source','target'] as $name){$limits[$name]=new SoSecurity\RateLimit\BudgetLimiter($budgetStore,new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60),$clock);}
    $publicBudgets=new SoSecurity\RateLimit\CompositeLimiter($limits,$clock);$subjectBudgets=new SoSecurity\RateLimit\BudgetLimiter($budgetStore,new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60),$clock);$reservations=[];
    $budget=static function(string $action,string $phase,string $scope,string $source,?SoSecurity\Account\Address $address,?string $subject)use($clock,$publicBudgets,$subjectBudgets,&$reservations):bool{
        $key=$action.':'.$source;
        if($phase==='public'){$result=$publicBudgets->consume('change-race-'.$scope,['site'=>'all','source'=>hash('sha256',$source),'target'=>hash('sha256',$address===null?'proof':$address->value())]);$reservations[$key]=$result->reservedUntil();return $result->allowed();}
        if($phase==='subject'){$result=$subjectBudgets->consume('change-race-subject-'.$scope,$subject);$reservations[$key]=min($reservations[$key],$result->reservedUntil());return $result->allowed();}
        return $phase==='final'&&isset($reservations[$key])&&$clock->time<$reservations[$key];
    };
    $guard=static function():bool{return true;};
    $service=new SoSecurity\Account\AddressChange($pdo,'account-test','tenant',str_repeat('e',64),new SoSecurity\Support\HmacKeys('account',['account'=>str_repeat('a',32)]),new SoSecurity\Support\HmacKeys('outbox',['outbox'=>str_repeat('o',32)]),$accounts,new SoSecurity\Account\Notifications('mail',['mail'=>str_repeat('m',32)],$clock),$sessions,$grants,$guard,$budget,null,$clock,$guard,$guard);
    $save=static function()use(&$context,$contextFile,$clock):void{$context['now']=$clock->time;$json=json_encode($context);if(strlen($json)>16384||file_put_contents($contextFile,$json)!==strlen($json)||!chmod($contextFile,0600)){throw new RuntimeException('Cannot save the bounded private test context.');}};
    $approve=static function(string $subject,SoSecurity\Operation\Intent $intent)use(&$context,$grants,$authentication,$accounts,$clock,$password):string{
        $token=$context['actors'][$subject]['session'];$pending=$grants->begin('tenant',$subject,$token,$intent);++$clock->time;$address=$accounts->find('tenant',$subject)->address()->value();
        $result=$authentication->password('tenant','change-race-'.$subject,$address,$password,'Race session',$token);
        if($result->status()!=='authenticated'){throw new RuntimeException('Actual reauthentication failed.');}$token=$result->credential()->token();$context['actors'][$subject]['session']=$token;
        $grant=$grants->confirm('tenant',$subject,$token,$intent,$pending->token());if($grant===null){throw new RuntimeException('Actual operation confirmation failed.');}return $grant->token();
    };
    if($setup){
        $service->initialize();
        foreach(array_keys($context['actors']) as $subject){
            $login=$authentication->password('tenant','change-race-'.$subject,$context['actors'][$subject]['initial_address'],$password,'Race session');if($login->status()!=='authenticated'){throw new RuntimeException('Actual initial authentication failed.');}
            $context['actors'][$subject]['session']=$login->credential()->token();$intent=$service->proposal($subject,$context['target'],$context['actors'][$subject]['session'],'race-source');$grant=$approve($subject,$intent);$service->request($subject,$context['target'],$context['actors'][$subject]['session'],$grant,'race-source');
        }
        foreach($pdo->query('SELECT payload_body FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_COLUMN) as $id){
            $delivery=$service->notification($id);if($delivery===null){throw new RuntimeException('Expected a current private challenge.');}
            $selector=$delivery->selector();$q=$pdo->prepare('SELECT payload FROM sosecurity_account_records WHERE record_id=:id');$q->execute(['id'=>$selector]);$flow=json_decode($q->fetchColumn(),true,6);$subject=$flow['subject'];
            $side=array_search($delivery->notice()->type(),['old'=>'verify_address_old','new'=>'verify_address_new','cancel'=>'cancel_change'],true);
            if($side===false||!isset($context['actors'][$subject])){throw new RuntimeException('Invalid owned challenge mapping.');}$context['actors'][$subject]['selector']=$selector;$context['actors'][$subject]['proofs'][$side]=$delivery->notice()->token();
        }
        foreach($context['actors'] as $data){if(count($data['proofs'])!==3){throw new RuntimeException('Expected three isolated challenges.');}}$save();echo json_encode(['setup'=>true,'actors'=>count($context['actors'])])."\n";exit;
    }
    $data=$context['actors'][$actor];$selector=$data['selector'];
    if($mode==='expire'){$clock->time=(int)$pdo->query('SELECT MAX(retire_at) FROM sosecurity_account_records')->fetchColumn()+1;$save();echo "{\"expired\":true}\n";exit;}
    if($mode==='ready'){foreach(['old','new'] as $side){if(!$service->confirm($selector,$side,$data['proofs'][$side],'race-source')){throw new RuntimeException('Mailbox confirmation failed.');}}echo "{\"ready\":true}\n";exit;}
    if($mode==='approve'){$intent=$service->completionProposal($actor,$selector,$data['session'],'race-source');$context['actors'][$actor]['grant']=$approve($actor,$intent);$save();echo "{\"approved\":true}\n";exit;}
    if($mode==='inspect'){
        $actors=[];foreach($context['actors'] as $subject=>$saved){
            $q=$pdo->prepare('SELECT * FROM account_example WHERE scope=:scope AND subject=:subject');$q->execute(['scope'=>'tenant','subject'=>$subject]);$row=$q->fetch(PDO::FETCH_ASSOC);$q=$pdo->prepare('SELECT payload FROM sosecurity_account_records WHERE record_id=:id');$q->execute(['id'=>$saved['selector']]);$raw=$q->fetchColumn();$flow=$raw===false?null:json_decode($raw,true,6);
            $actors[$subject]=['changed'=>$row['address']===$context['target'],'state'=>$flow===null?null:$flow['state'],'password_preserved'=>hash_equals($saved['initial_password'],hash('sha256',$row['password'])),'version_advanced'=>$row['credential_version']!=='initial-version','address_version_advanced'=>$row['address_version']!=='initial-address','old_confirmed'=>($flow['proofs']['old']['confirmed'] ?? false),'new_confirmed'=>($flow['proofs']['new']['confirmed'] ?? false),'attempts_old'=>($flow['proofs']['old']['attempts'] ?? null),'attempts_new'=>($flow['proofs']['new']['attempts'] ?? null),'cancel_attempts'=>($flow['proofs']['cancel']['attempts'] ?? null),'old_session_rejected'=>$sessions->verify('tenant',$subject,$saved['session'])===null];
        }
        echo json_encode(['actors'=>$actors,'records'=>(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn(),'notices'=>(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn(),'root_revision'=>(int)$pdo->query('SELECT revision FROM sosecurity_account_roots')->fetchColumn()])."\n";exit;
    }
    if($option==='kill-before'||$option==='kill-after'){
        if($mode!=='complete'||!function_exists('posix_kill')){throw new RuntimeException('Expected an owned POSIX completion termination.');}
        $kill=static function()use($pdo,$actor,$context):void{$q=$pdo->prepare('SELECT address FROM account_example WHERE subject=:subject');$q->execute(['subject'=>$actor]);if($q->fetchColumn()===$context['target']){posix_kill(getmypid(),9);throw new RuntimeException('Owned SIGKILL was not delivered.');}};
        if($option==='kill-before'){$pdo->beforeCommit=$kill;}else{$pdo->afterCommit=$kill;}
    }
    $marker=$directory.'/ready-'.$mode.'-'.$actor.'-'.$index;file_put_contents($marker,'ready');chmod($marker,0600);$until=microtime(true)+30;
    while(!is_file($directory.'/go-'.$mode)){if(microtime(true)>=$until){throw new RuntimeException('Owned process barrier timed out.');}usleep(5000);}
    if($mode==='maintain'){$result=$service->maintain(50);echo json_encode(['removed'=>$result['removed']])."\n";exit;}
    if($mode==='old'||$mode==='new'){$result=$service->confirm($selector,$mode,$data['proofs'][$mode],'race-source');}
    elseif($mode==='cancel'){$result=$service->cancel($selector,$data['proofs']['cancel'],'race-source');}
    else{$result=$service->complete($actor,$selector,$data['session'],$data['grant'],'race-source');}
    echo json_encode(['result'=>$result])."\n";
}catch(Throwable $error){
    $result=['error'=>get_class($error),'reason'=>$error instanceof SoSecurity\Exception\SecurityException?$error->reason():'test.failure'];
    if(isset($pdo)&&$pdo instanceof ChangeRaceConnection&&$pdo->firstSqlFailure!==null){$result['sql_failure']=$pdo->firstSqlFailure;}
    echo json_encode($result)."\n";exit(2);
}
