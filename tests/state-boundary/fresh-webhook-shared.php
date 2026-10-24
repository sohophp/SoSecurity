<?php
declare(strict_types=1);
require dirname(__DIR__).'/bootstrap.php';
require dirname(__DIR__,2).'/examples/SqlAccounts.php';
use SoSecurity\Account as A;
use SoSecurity\Storage\StorageException;
$directory=privateDirectory();$mysql=($argv[1]??'')==='mysql';$created=[];$pdo=null;
try {
    foreach(['witness','fence','files','scratch','budget'] as $name){mkdir($directory.'/'.$name,0700);}
    $socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
    if($mysql&&(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket)))){throw new RuntimeException('Owned private MySQL required.');}
    $pdo=new PDO($mysql?'mysql:unix_socket='.$socket.';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$directory.'/fresh.sqlite',$mysql?'sosecurity_test':null,$mysql?'integration-only':null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
    if(!$mysql){$pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');}
    foreach(['account','account-example','outbox','webhook','webhook-processing'] as $name){
        $ddl=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__,2).'/resources/sql/'.$name.'-'.($mysql?'mysql':'sqlite').'.sql'));
        foreach(explode(';',$ddl) as $statement){if(trim($statement)===''){continue;}$pdo->exec($statement);if(preg_match('/CREATE TABLE\s+(\w+)/i',$statement,$match)){$created[]=$match[1];}}
    }
    $inbox=['endpoint_key'=>'digest','event_key'=>'digest','receipt_id'=>'bytes:32','event_id'=>'bytes:256','event_type'=>'bytes:128','resource_id'=>'bytes:256','descriptor'=>'digest','body_digest'=>'digest','payload'=>'blob:1048576','created_at'=>'int','seen_at'=>'int','source_key'=>'bytes:64','source_time'=>'nullable_int','seal_key'=>'bytes:64','seal'=>'digest'];
    $processing=['endpoint_key'=>'digest','receipt_id'=>'bytes:32','event_key'=>'digest','body_digest'=>'digest','descriptor'=>'digest','policy'=>'digest','status'=>'bytes:16','attempt'=>'int','total_attempts'=>'int','manual_retries'=>'int','revision'=>'int','due_at'=>'int','lease_until'=>'int','claim_digest'=>'bytes:64','worker_digest'=>'bytes:64','error_code'=>'bytes:64','created_at'=>'int','updated_at'=>'int','seal_key'=>'bytes:64','seal'=>'digest'];
    $definitions=[
        'sosecurity_webhook_inbox'=>['columns'=>$inbox,'primary'=>['endpoint_key','event_key']],
        'sosecurity_webhook_processing'=>['columns'=>$processing,'primary'=>['endpoint_key','receipt_id']],
        'sosecurity_outbox_roots'=>['columns'=>SoSecurity\Outbox\Schema::rootTypes(),'primary'=>['namespace']],
        'sosecurity_outbox_records'=>['columns'=>SoSecurity\Outbox\Schema::recordTypes(),'primary'=>['namespace','key_hash']],
        'account_example'=>['columns'=>['scope'=>'bytes:256','subject'=>'bytes:256','credential_version'=>'bytes:256','address_version'=>'bytes:256','address'=>'bytes:320','password'=>'nullable_bytes:4096','status'=>'bytes:16','verified'=>'int','mfa_required'=>'int','roles'=>'bytes:4096'],'primary'=>['scope','subject']],
        'sosecurity_account_roots'=>['columns'=>A\Ledger::rootTypes(),'primary'=>['namespace']],
        'sosecurity_account_records'=>['columns'=>A\Ledger::recordTypes(),'primary'=>['namespace','record_id']],
    ];
    $definitions['sosecurity_outbox_records']['columns']['payload_body']='blob:1048576';
    $definitions['sosecurity_account_records']['columns']['payload']='blob:16384';
    foreach($definitions as &$definition){$definition['where']=[];$definition['maximum_rows']=1000;}unset($definition);
    $sql=new A\SqlStateSnapshot($pdo,'fresh-auth-sql',$definitions,30000);
    $files=new A\FileStateSnapshot($pdo,'fresh-auth-files',$directory.'/files',$directory.'/scratch',1000,30000);
    $fences=new A\FenceStateSnapshot($pdo,'fresh-auth-fence',$directory.'/fence',2,30000);
    $hookEndpoint=new SoSecurity\Webhook\Endpoint('hook','tenant','provider','https://hooks.example/events','standard-hmac');$hookKeys=new SoSecurity\Webhook\KeySet($hookEndpoint,['hook'=>str_repeat('h',32)]);$hookSeals=new SoSecurity\Support\HmacKeys('hook',['hook'=>str_repeat('s',32)]);$hookPolicy=new SoSecurity\Webhook\ProcessingPolicy();
    $hookConfiguration=new A\WebhookStateSnapshot($pdo,'fresh-hook',$hookEndpoint,$hookKeys,$hookSeals,$hookPolicy);
    $source=new A\CompositeStateSnapshot($pdo,['sql'=>$sql,'files'=>$files,'fences'=>$fences,'webhook'=>$hookConfiguration],30000);
    $keys=new SoSecurity\Support\HmacKeys('fresh',['fresh'=>str_repeat('k',32)]);
    $epoch=str_repeat('e',64);$clock=new TestClock();
    $witness=new A\LocalStateWitness($pdo,$directory.'/witness','fresh-site','tenant',$epoch,$keys,$source,new A\LocalStatePersistence($directory.'/witness',30000),30000,2);
    Check::same('0',$pdo->query('SELECT COUNT(*) FROM account_example')->fetchColumn().'');
    Check::same('0',$pdo->query('SELECT COUNT(*) FROM sosecurity_account_roots')->fetchColumn().'');
    Check::same([],glob($directory.'/fence/*.fence'));Check::same([],glob($directory.'/files/*.json'));
    $witness->initialize($source->digest());
    $boundary=new A\StateBoundary($witness,static function():bool{return true;});
    $fence=new A\LocalEpochFence($directory.'/fence','fresh-site','tenant',$epoch,$keys,new A\LocalStatePersistence($directory.'/fence',30000),30000,$boundary);
    $store=new SoSecurity\Storage\FileStore($directory.'/files','fresh-auth',$clock);
    $raw=new SoSecurity\Mfa\TotpFactors($store,new SoSecurity\Crypto\Cipher('fresh',['fresh'=>str_repeat('c',32)],'fresh-site'),'Fresh test',$clock);
    $raw->bindStateBoundary($boundary);
    // Only first worker-root provisioning. No account recovery callback may execute.
    $unused=static function(){throw new RuntimeException('Recovery callbacks are outside this test.');};
    $initialAuthority=static function(string $action,string $phase):bool{return $action==='initialize'&&in_array($phase,['before','commit'],true);};
    $provision=new A\FactorRecovery($pdo,'fresh-site','tenant',$epoch,$keys,$raw,$unused,$unused,$initialAuthority,$unused,$unused,$unused,new A\Policy(),$clock,$unused,$fence);
    $boundary->run('fresh.provision',static function()use($fence,$provision):void{$fence->initialize();$provision->initialize();});
    $accounts=new A\Example\SqlAccounts($pdo);$hasher=new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]);
    $password='Owned fresh first account password 49!';
    $lookups=0;
    $provider=new SoSecurity\Auth\PasswordIdentityProvider(
        static function(string $scope,string $address)use($accounts,&$lookups){++$lookups;$record=$accounts->findAddress($scope,new A\Address($address));return $record===null?null:$accounts->passwordRecord($record);},
        static function(string $scope,string $subject)use($accounts,&$lookups){++$lookups;$record=$accounts->find($scope,$subject);return $record===null?null:$accounts->passwordRecord($record);},
        $hasher,$hasher->hash('Owned fresh dummy account password 49!'));
    $allowed=true;$requests=new A\StateRequests(static function()use(&$allowed):bool{return $allowed;},static function()use(&$allowed):bool{return $allowed;});
    $config=['site'=>'fresh-site','storage'=>['driver'=>'file','directory'=>$directory.'/budget'],
        'authentication'=>['identity_provider'=>'identity','request_guard'=>'request','managed_factors'=>true,'state_boundary'=>['authority'=>'boundary','store'=>'auth_store','scope'=>'tenant','epoch'=>$epoch]],
        'account_factors'=>['connection'=>'db','scope'=>'tenant','epoch'=>$epoch,'repository'=>'accounts','integrity_keys'=>'keys','totp'=>'raw','fence'=>'fence','worker_guard'=>'worker','read_guard'=>'read','management_guard'=>'manage']];
    $services=['boundary'=>$boundary,'auth_store'=>$store,'identity'=>$provider,'request'=>$requests,'db'=>$pdo,'accounts'=>$accounts,'keys'=>$keys,'raw'=>$raw,'fence'=>$fence];
    foreach(['worker','read','manage'] as $name){$services[$name]=static function():bool{return true;};}
    $sdk=SoSecurity\Security::fromArray($config,$services,$clock);$before=$source->digest();
    $registry=$sdk->accountFactors();$auth=$sdk->authentication();$sessions=$sdk->sessions();
    Check::same($before,$source->digest());Check::same(0,$lookups);
    $columns=array_keys($definitions['account_example']['columns']);
    $accountConnection=new A\StateAccountConnection($boundary,$witness,$source,$sql,'sql',$accounts,'account_example',array_combine($columns,$columns),'fresh-site','tenant',$epoch,$clock,new A\Policy(),$sessions);
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($boundary,$witness,$source,$sql,$hookConfiguration,$epoch,$hookEndpoint,$hookKeys,$hookSeals,$hookPolicy):void{new A\StateWebhookConnection($boundary,$witness,$source,$sql,'sql',$hookConfiguration,'webhook','fresh-site',$epoch,$hookEndpoint,$hookKeys,$hookSeals,$hookPolicy);});
    $hookState=new A\StateWebhookConnection($boundary,$witness,$source,$sql,'sql',$hookConfiguration,'webhook','fresh-site',$epoch,$hookEndpoint,$hookKeys,$hookSeals,$hookPolicy,$accountConnection);
    $hookConfig=$config;$hookConfig['webhooks']=['hook'=>['scope'=>'tenant','account'=>'provider','url'=>'https://hooks.example/events','protocol'=>'standard-hmac','key_provider'=>'hook_keys','request_guard'=>'hook_guard','state_connection'=>'hook_state','inbox'=>['connection'=>'db','integrity_keys'=>'hook_seals','association_guard'=>'hook_guard']]];
    $hookServices=$services+['hook_state'=>$hookState,'hook_keys'=>$hookKeys,'hook_seals'=>$hookSeals,'hook_guard'=>static function():bool{return true;}];
    $hookSdk=SoSecurity\Security::fromArray($hookConfig,$hookServices,$clock);$hookInbox=$hookSdk->webhookInbox('hook');
    $body='{}';$message='fresh-message.'.$clock->time.'.'.$body;$hookRequest=new SoSecurity\Webhook\Request('POST',$hookEndpoint->url(),$body,['Webhook-Id'=>'fresh-message','Webhook-Timestamp'=>(string)$clock->time,'Webhook-Signature'=>'v1,'.base64_encode(hash_hmac('sha256',$message,str_repeat('h',32),true))]);
    $hookMapper=static function(){return new SoSecurity\Webhook\Message('fresh-message','created','fresh-user');};
    $legacyHook=new SoSecurity\Webhook\SqlInbox($pdo,'fresh-site',new SoSecurity\Webhook\Verifier($hookEndpoint,static function()use($hookKeys){return $hookKeys;},static function():bool{return true;},$clock),$hookSeals,static function():bool{return true;},$clock);
    Check::throws(StorageException::class,static function()use($legacyHook,$hookRequest,$hookMapper):void{$legacyHook->accept($hookRequest,$hookMapper);});
    $hookReceipt=$hookInbox->accept($hookRequest,$hookMapper);Check::same(true,$hookReceipt instanceof SoSecurity\Webhook\Receipt);
    $missing=$hookConfig;$missing['webhooks']['hook']['state_connection']=null;
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($missing,$hookServices,$clock):void{SoSecurity\Security::fromArray($missing,$hookServices,$clock)->webhookInbox('hook');});
    $firstFactor=$raw->managedRegistered('fresh-site','tenant',$epoch,$keys,$fence,new A\FactorWorkerAuthority($pdo,'fresh-site','tenant',$epoch,$keys,$fence,static function(string $action,string $phase,string $scope,string $subject):bool{return $action==='adoptManaged'&&$scope==='tenant'&&$subject==='fresh-user';},new A\Policy(),$clock));
    // Host explicitly provisions the empty factor slot for this new account only.
    // Missing slots at authentication time still fail closed.
    // Host provisions a genuinely new account, never reactivates an existing disabled one.
    $boundary->run('fresh.account',static function()use($accounts,$hasher,$password,$registry,$firstFactor):void{
        $pending=$accounts->createPending('tenant','fresh-user',new A\Address('fresh@example.test'));
        Check::same(true,$accounts->activate($pending,$hasher->hash($password))!==null);
        Check::same(false,$firstFactor->adoptManaged('tenant','fresh-user',null)['enabled']);
        Check::same(true,$registry->initialize('fresh-user'));
    });
    $allowed=false;$before=$source->digest();$reads=$lookups;
    Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($auth,$password):void{$auth->password('tenant','fresh-browser','fresh@example.test',$password);});
    Check::same($reads,$lookups);Check::same($before,$source->digest());$allowed=true;
    $login=$auth->password('tenant','fresh-browser','fresh@example.test',$password);
    Check::same('authenticated',$login->status());$token=$login->credential()->token();
    Check::same(true,$sessions->verify('tenant','fresh-user',$token)!==null);
    Check::same('current',$witness->inspect(static function():bool{return true;})['status']);
    $sessions->revokeAll('tenant','fresh-user');Check::same(null,$sessions->verify('tenant','fresh-user',$token));
    $legacyStore=new SoSecurity\Storage\FileStore($directory.'/files','fresh-site:shared',$clock);
    $legacyState=new A\StateApiKeyConnection($boundary,$witness,$source,$files,'files',$legacyStore,'fresh-site','tenant',$epoch,$clock,static function(string $action,string $scope,string $subject){return $scope==='tenant'&&$subject==='fresh-client'?'host-operator':null;});
    $keySdk=SoSecurity\Security::fromArray($hookConfig,$hookServices,$clock);Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($keySdk):void{$keySdk->apiKeys();});
    $legacyKeys=$keySdk->apiKeys($legacyState);$legacyCredential=$legacyKeys->issue('fresh-client',['read'],60);Check::same('fresh-client',$legacyKeys->authenticate($legacyCredential->token())->subject());Check::same(true,$legacyKeys->revoke($legacyCredential->identity()->id()));Check::same(null,$legacyKeys->authenticate($legacyCredential->token()));
    Check::same($source->digest(),$witness->inspect(static function():bool{return true;})['digest']);
    echo 'PASS shared account and Webhook state: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').'; empty authority, new account, factory login/session/revocation; no rotation or recovery activation'.PHP_EOL;
} finally {
    if($mysql&&$pdo instanceof PDO){foreach(array_reverse($created) as $table){$pdo->exec('DROP TABLE '.$table);}}
    foreach(['witness','fence','files','scratch','budget'] as $name){if(is_dir($directory.'/'.$name)){cleanDirectory($directory.'/'.$name);}}
    cleanDirectory($directory);
}
