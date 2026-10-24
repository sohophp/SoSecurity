<?php
declare(strict_types=1);
require dirname(__DIR__).'/bootstrap.php';
require dirname(__DIR__,2).'/examples/SqlAccounts.php';
use SoSecurity\Account as A;
use SoSecurity\Storage\StorageException;
final class NativeMaintenanceClock implements SoSecurity\Support\Clock
{
    public $time=100000;
    public $fail=false;
    public $delayCalls=0;
    public $delayMicroseconds=0;
    public function now():int{if($this->delayCalls>0&&--$this->delayCalls===0){usleep($this->delayMicroseconds);}if($this->fail){throw new RuntimeException('private-permission-clock-detail');}return $this->time;}
}
if(($argv[3]??'')==='audit_delegation'&&($argv[4]??'')==='profile-defaults'){require __DIR__.'/native-audit-timing.php';}
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
    if(in_array($argv[3]??'',['idempotency','idempotency_request'],true)){
        $ddl=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__,2).'/resources/sql/idempotency-'.($mysql?'mysql':'sqlite').'.sql'));foreach(explode(';',$ddl) as $statement){if(trim($statement)===''){continue;}$pdo->exec($statement);if(preg_match('/CREATE TABLE\s+(\w+)/i',$statement,$match)){$created[]=$match[1];}}
    }
    if(in_array($argv[3]??'',['audit_source','audit_write','audit_delegation'],true)){
        $ddl=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__,2).'/resources/sql/audit-'.($mysql?'mysql':'sqlite').'.sql'));foreach(explode(';',$ddl) as $statement){if(trim($statement)===''){continue;}$pdo->exec($statement);if(preg_match('/CREATE TABLE\s+(\w+)/i',$statement,$match)){$created[]=$match[1];}}
    }
    $mapping=($argv[3]??'')==='mapping';
    if($mapping){$ddl=str_replace('account_example','account_shadow',preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__,2).'/resources/sql/account-example-'.($mysql?'mysql':'sqlite').'.sql')));foreach(explode(';',$ddl) as $statement){if(trim($statement)!==''){$pdo->exec($statement);}}$created[]='account_shadow';}
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
    if($mapping){$definitions['account_shadow']=$definitions['account_example'];}
    foreach($definitions as &$definition){$definition['where']=[];$definition['maximum_rows']=1000;}unset($definition);
    if(in_array($argv[3]??'',['idempotency','idempotency_request'],true)){$recordTypes=SoSecurity\Idempotency\Schema::recordTypes();$recordTypes['response_body']='blob:1048576';$definitions['sosecurity_idempotency_roots']=['columns'=>SoSecurity\Idempotency\Schema::rootTypes(),'primary'=>['namespace'],'where'=>[],'maximum_rows'=>1];$definitions['sosecurity_idempotency_records']=['columns'=>$recordTypes,'primary'=>['namespace','key_hash'],'where'=>[],'maximum_rows'=>8];}
    if(($argv[3]??'')==='idempotency_request'){$pdo->exec(($mysql?'CREATE TABLE owned_idempotent_business (reference_id VARBINARY(64) NOT NULL PRIMARY KEY, amount BIGINT NOT NULL) ENGINE=InnoDB':'CREATE TABLE owned_idempotent_business (reference_id TEXT NOT NULL PRIMARY KEY, amount INTEGER NOT NULL)'));$created[]='owned_idempotent_business';$definitions['owned_idempotent_business']=['columns'=>['reference_id'=>'bytes:64','amount'=>'int'],'primary'=>['reference_id'],'where'=>[],'maximum_rows'=>4];$definitions['sosecurity_idempotency_records']['maximum_rows']=2;}
    if(in_array($argv[3]??'',['audit_source','audit_write','audit_delegation'],true)){
        $definitions['sosecurity_audit_roots']=['columns'=>['site'=>'digest','policy'=>'digest','next_sequence'=>'int','observed_at'=>'int'],'primary'=>['site'],'where'=>[],'maximum_rows'=>(($argv[3]??'')==='audit_write'?2:1)];
        $definitions['sosecurity_audit_records']=['columns'=>['site'=>'digest','sequence_no'=>'int','recorded_at'=>'int','expires_at'=>'int','record'=>'blob:4096'],'primary'=>['site','sequence_no'],'where'=>[],'maximum_rows'=>(($argv[3]??'')==='audit_delegation'?16:4)];
    }
    if(($argv[3]??'')==='audit_delegation'&&strpos($argv[4]??'','business-')===0){
        $pdo->exec($mysql?'CREATE TABLE owned_native_business (id VARBINARY(64) NOT NULL PRIMARY KEY, amount BIGINT NOT NULL) ENGINE=InnoDB':'CREATE TABLE owned_native_business (id TEXT NOT NULL PRIMARY KEY, amount INTEGER NOT NULL)');$created[]='owned_native_business';
        $definitions['owned_native_business']=['columns'=>['id'=>'bytes:64','amount'=>'int'],'primary'=>['id'],'where'=>[],'maximum_rows'=>4];
    }
    if(($argv[3]??'')==='audit_delegation'&&(strpos($argv[4]??'','captured-permission-')===0||strpos($argv[4]??'','policy-business-')===0||strpos($argv[4]??'','operation-return-')===0||strpos($argv[4]??'','hmac-return-')===0||strpos($argv[4]??'','link-return-')===0||strpos($argv[4]??'','reset-proof-return-')===0)){
        $pdo->exec($mysql?'CREATE TABLE owned_policy_business (scope VARBINARY(256) NOT NULL,id VARBINARY(64) NOT NULL,owner VARBINARY(256) NOT NULL,amount BIGINT NOT NULL,PRIMARY KEY(scope,id)) ENGINE=InnoDB':'CREATE TABLE owned_policy_business (scope TEXT NOT NULL,id TEXT NOT NULL,owner TEXT NOT NULL,amount INTEGER NOT NULL,PRIMARY KEY(scope,id))');$created[]='owned_policy_business';
        $definitions['owned_policy_business']=['columns'=>['scope'=>'bytes:256','id'=>'bytes:64','owner'=>'bytes:256','amount'=>'int'],'primary'=>['scope','id'],'where'=>[],'maximum_rows'=>4];
    }
    if(($argv[3]??'')==='address_actions'&&strpos($argv[4]??'','captured-')===0){
        $pdo->exec($mysql?'CREATE TABLE owned_address_permissions(scope VARBINARY(256) NOT NULL,subject VARBINARY(256) NOT NULL,allowed BIGINT NOT NULL,PRIMARY KEY(scope,subject)) ENGINE=InnoDB':'CREATE TABLE owned_address_permissions(scope TEXT NOT NULL,subject TEXT NOT NULL,allowed INTEGER NOT NULL,PRIMARY KEY(scope,subject))');$created[]='owned_address_permissions';
        $definitions['owned_address_permissions']=['columns'=>['scope'=>'bytes:256','subject'=>'bytes:256','allowed'=>'int'],'primary'=>['scope','subject'],'where'=>[],'maximum_rows'=>4];
    }
    $sql=new A\SqlStateSnapshot($pdo,'fresh-auth-sql',$definitions,30000);
    $files=new A\FileStateSnapshot($pdo,'fresh-auth-files',$directory.'/files',$directory.'/scratch',1000,30000);
    $fences=new A\FenceStateSnapshot($pdo,'fresh-auth-fence',$directory.'/fence',2,30000);
    $hookEndpoint=new SoSecurity\Webhook\Endpoint('hook','tenant','provider','https://hooks.example/events','standard-hmac');$hookKeys=new SoSecurity\Webhook\KeySet($hookEndpoint,['hook'=>str_repeat('h',32)]);$hookSeals=new SoSecurity\Support\HmacKeys('hook',['hook'=>str_repeat('s',32)]);$hookPolicy=new SoSecurity\Webhook\ProcessingPolicy();
    $hookConfiguration=new A\WebhookStateSnapshot($pdo,'fresh-hook',$hookEndpoint,$hookKeys,$hookSeals,$hookPolicy);
    $parts=['sql'=>$sql,'files'=>$files,'fences'=>$fences,'webhook'=>$hookConfiguration];
    if(($argv[3]??'')==='quarantine'){foreach(['spool','web'] as $name){mkdir($directory.'/'.$name,0700);}$uploadPolicy=new SoSecurity\Upload\Policy(['extensions'=>['txt'],'maximum_bytes'=>1024,'require_scan'=>true]);$spoolSource=new A\QuarantineStateSnapshot($pdo,'fresh-spool',$directory.'/spool',$directory.'/web',$uploadPolicy,2,2048,30000);$parts['spool']=$spoolSource;}
    if(($argv[3]??'')==='audit_delegation'&&strpos($argv[4]??'','hmac-return-')===0){
        $ownedSigningKey=new SoSecurity\Api\SigningKey('owned-key',str_repeat('n',32),'fresh-user',['records:write']);$ownedSigningRing=new SoSecurity\Api\KeyRing([$ownedSigningKey]);$ownedSignaturePolicy=new SoSecurity\Api\SignaturePolicy(['origin'=>'https://api.example.test','clock_skew'=>0]);$ownedSignatureSource=new A\KeyRingStateSnapshot($pdo,'owned-signature-profile',$ownedSigningRing,$ownedSignaturePolicy);$parts['owned-signature']=$ownedSignatureSource;
    }
    $source=new A\CompositeStateSnapshot($pdo,$parts,30000);
    $keys=new SoSecurity\Support\HmacKeys('fresh',['fresh'=>str_repeat('k',32)]);
    $epoch=str_repeat('e',64);$clock=new NativeMaintenanceClock();
    if(in_array($argv[3]??'',['audit_source','audit_write','audit_delegation'],true)){$auditSink=new SoSecurity\Audit\SqlSink($pdo,'fresh-site',($argv[3]??'')==='audit_delegation'?16:(($argv[3]??'')==='audit_write'?3:4),3600,$clock,((($argv[3]??'')==='audit_delegation'&&in_array($argv[4]??'',['defaults','profile-defaults','post-audit-delay','post-audit-denial','post-audit-timeout','audit-admission-timeout'],true))||(($argv[3]??'')==='audit_write'&&($argv[4]??'')==='sink-budget'))?1000:10000);$auditSink->initialize();$auditLogger=new SoSecurity\Audit\AuditLogger($auditSink,str_repeat('a',32));if(($argv[3]??'')==='audit_write'){$otherAuditSink=new SoSecurity\Audit\SqlSink($pdo,'other-site',3,3600,$clock,10000);$otherAuditSink->initialize();}}
    $witness=new A\LocalStateWitness($pdo,$directory.'/witness','fresh-site','tenant',$epoch,$keys,$source,new A\LocalStatePersistence($directory.'/witness',30000),30000,2);
    Check::same('0',$pdo->query('SELECT COUNT(*) FROM account_example')->fetchColumn().'');
    Check::same('0',$pdo->query('SELECT COUNT(*) FROM sosecurity_account_roots')->fetchColumn().'');
    Check::same([],glob($directory.'/fence/*.fence'));Check::same([],glob($directory.'/files/*.json'));
    $witness->initialize($source->digest());
    $nativeFinalHook=null;$boundary=new A\StateBoundary($witness,static function(string $phase,string $action)use(&$nativeFinalHook):bool{if($phase==='final'&&$nativeFinalHook!==null){$run=$nativeFinalHook;$nativeFinalHook=null;$run();}return true;});
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
    $authenticationCurrentHook=null;$allowed=true;$requests=new A\StateRequests(static function()use(&$allowed):bool{return $allowed;},static function()use(&$allowed,&$authenticationCurrentHook):bool{if($authenticationCurrentHook!==null){($authenticationCurrentHook)();}return $allowed;});
    $managementAllowed=true;$phases=[];$late=false;$nested=null;
    $manager=static function(string &$action,string &$phase,string &$scope)use(&$managementAllowed,&$phases,&$late,&$nested,$pdo):bool{$phases[]=$phase;if($late&&$phase==='complete'){$pdo->prepare('UPDATE account_example SET roles=? WHERE subject=?')->execute(['[]','fresh-user']);}if($phase==='admission'){if($nested!==null){$run=$nested;$nested=null;$run();}$action='owned-mutated';$scope='owned-mutated';$phase='owned-mutated';}return $managementAllowed;};
    $notices=new A\Notifications('fresh',['fresh'=>str_repeat('n',32)],$clock);
    $config=['site'=>'fresh-site','storage'=>['driver'=>'file','directory'=>$directory.'/budget'],
        'authentication'=>['identity_provider'=>'identity','request_guard'=>'request','managed_factors'=>true,'state_boundary'=>['authority'=>'boundary','store'=>'auth_store','scope'=>'tenant','epoch'=>$epoch]],
        'account_factors'=>['connection'=>'db','scope'=>'tenant','epoch'=>$epoch,'repository'=>'accounts','integrity_keys'=>'keys','totp'=>'raw','fence'=>'fence','worker_guard'=>'worker','read_guard'=>'read','management_guard'=>'manage']];
    $services=['boundary'=>$boundary,'auth_store'=>$store,'identity'=>$provider,'request'=>$requests,'db'=>$pdo,'accounts'=>$accounts,'keys'=>$keys,'raw'=>$raw,'fence'=>$fence];
    foreach(['worker','read','manage'] as $name){$services[$name]=static function():bool{return true;};}
    $factory=($argv[2]??'direct')==='factory';$expired=in_array($argv[3]??'',['recovery','mailbox_recovery'],true);if($expired&&!$factory){throw new RuntimeException('Expired request tests require the public factory');}
    if($factory){
        $config['authorization']=['identity_provider'=>'identity'];$config['operations']=['request_guard'=>'operation_request'];
        $config['accounts']=['connection'=>'db','scope'=>'tenant','epoch'=>$epoch,'repository'=>'accounts','integrity_keys'=>'keys','outbox_keys'=>'keys','notifications'=>'account_notices','request_budget'=>'account_budget','registration_authority'=>'account_allow','request_guard'=>'account_allow','management_guard'=>'account_management'];
        $budgetPolicies=[];foreach(['site','source','target','subject'] as $name){$budgetPolicies[$name]=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60);}
        $services['account_budget']=new A\RequestBudgets(new SoSecurity\Storage\FileStore($directory.'/budget','native-maintenance-budgets',$clock),'fresh-site',str_repeat('b',32),$budgetPolicies,$clock);
        if($expired){$config['accounts']['recovery_authority']='history_request';$config['accounts']['mailbox_authority']='history_request';$config['accounts']['mailbox_approval']='history_approval';$services['history_request']=static function(string $action):bool{return in_array($action,['request','outbox.enqueue'],true);};$services['history_approval']=static function(){throw new RuntimeException('Approval and final activation are outside this test');};}
        $services['account_notices']=$notices;$services['account_management']=$manager;$services['account_allow']=static function():bool{return true;};$services['operation_request']=static function():bool{return true;};
    }
    if(in_array($argv[3]??'',['address_proofs','address_actions'],true)){
        $addressRequestAllowed=true;$addressCurrentAllowed=true;$addressBusinessLate=false;$addressRequestPhases=[];$addressReentry=null;$addressGuardFailure='';$addressActionHook=null;
        $addressRequests=new A\StateRequests(static function(string $action,string $scope)use(&$addressRequestAllowed,&$addressRequestPhases,&$addressReentry,&$addressGuardFailure):bool{if($addressGuardFailure==='public'){throw new RuntimeException('private-address-guard-detail');}if($addressReentry!==null){$run=$addressReentry;$addressReentry=null;$run();}$addressRequestPhases[]=['public',$action,$scope];return $addressRequestAllowed;},static function(string $action,string $scope)use(&$addressCurrentAllowed,&$addressRequestPhases,&$addressGuardFailure):bool{if($addressGuardFailure==='current'){throw new RuntimeException('private-address-guard-detail');}$addressRequestPhases[]=['current',$action,$scope];return $addressCurrentAllowed;});
        $rule=['type'=>'account','roles'=>['member'],'fields'=>['address'],'owner_attribute'=>'owner'];$services['address_roles']=new SoSecurity\Authorization\RolePolicy(['account.address.request'=>$rule,'account.address.complete'=>$rule]);$config['authorization']['policy']='address_roles';$config['operations']['minimum_strength']=1;$config['operations']['methods']=['password','totp'];
        $config['accounts']['state_request_guard']='address_requests';$config['accounts']['delivery_guard']='account_allow';$services['address_requests']=$addressRequests;$services['account_allow']=static function(string &$action,string &$phase,string &$scope,?A\AccountRecord &$record=null,?A\Address &$target=null)use(&$addressBusinessLate,&$addressActionHook):bool{if($addressActionHook!==null){return $addressActionHook($action,$phase,$scope,$record,$target);}return !($addressBusinessLate&&$action==='confirm'&&$phase==='complete');};
    }
    if(($argv[3]??'')==='address_actions'&&strpos($argv[4]??'','captured-')===0){
        require __DIR__.'/address-captured-support.php';$capturedAddressEvaluator=new AddressCapturedEvaluator(substr($argv[4],strlen('captured-')));$capturedAddressPolicy=new SoSecurity\Authorization\SnapshotPolicy($capturedAddressEvaluator,$sql,hash('sha256','owned-address-permission-v1:'.$argv[4]));
        $services['address_captured_policy']=$capturedAddressPolicy;if(($argv[4]??'')!=='captured-role'){$config['authorization']['policy']='address_captured_policy';}
    }
    if(($argv[3]??'')==='leases'){$config['leases']=['maximum'=>1,'ttl'=>30,'maximum_lifetime'=>300];}
    if(($argv[3]??'')==='quarantine'){$config['upload_quarantine']=['directory'=>$directory.'/spool','document_root'=>$directory.'/web','scanner'=>'scanner','policy'=>$uploadPolicy->options(),'queue'=>['maximum_entries'=>2,'maximum_total_bytes'=>2048,'scan_milliseconds'=>1000]];$services['scanner']=new class implements SoSecurity\Upload\Scanner{public function scan(SoSecurity\Upload\Candidate $candidate):bool{return true;}};}
    if(($argv[3]??'')==='idempotency_factory'){
        $foreign=new PDO('sqlite:'.$directory.'/foreign.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
        $config['idempotency']=['connection'=>'foreign','epoch'=>$epoch,'integrity_keys'=>'keys','authority'=>'idem_authority','management_guard'=>'idem_authority'];$config['outbox']=$config['idempotency'];$idemCalls=0;$services['foreign']=$foreign;$services['idem_authority']=static function()use(&$idemCalls):bool{++$idemCalls;return true;};
    }
    if(($argv[3]??'')==='audit_delegation'){
        $bearerRequestFault=false;$bearerScopeFault=false;$bearerScopeReentry=null;$auditAdmissionHook=null;$auditRequestAllowed=true;$auditCurrentAllowed=true;$auditReturnAllowed=true;$auditGuardFault=false;$auditScopes=['records:read','records:write'];$auditCalls=[];
        $auditGuard=static function(string &$action,?SoSecurity\Auth\Account &$actor,array &$metadata)use(&$auditAdmissionHook,&$auditRequestAllowed,&$auditCurrentAllowed,&$auditReturnAllowed,&$auditGuardFault,&$auditCalls,&$bearerRequestFault):bool{
            if($bearerRequestFault&&$action==='authenticate'){throw new RuntimeException('PRIVATE-BEARER-GUARD');}
            if($auditAdmissionHook!==null&&in_array($action,['audit_current','management_current'],true)&&($metadata['phase']??'')==='admission'){$auditAdmissionHook();}
            if(class_exists('NativeAuditTiming',false)){NativeAuditTiming::mark($action,$metadata['phase']??'request');}$auditCalls[]=[$action,$metadata['phase']??null];if($auditGuardFault&&in_array($action,['audit_current','management_current'],true)&&($metadata['phase']??'')==='return'){throw new RuntimeException('private-audit-guard-error');}
            $allowed=$auditRequestAllowed&&(!in_array($action,['audit_current','management_current'],true)||($auditCurrentAllowed&&(($metadata['phase']??'')!=='return'||$auditReturnAllowed)));$action='mutated';$actor=null;$metadata=[];return $allowed;
        };
        $auditRoleRules=[];foreach(['issue','all','rotate','replace','revoke','revoke_all'] as $action){$auditRoleRules['api.credentials.'.$action]=['type'=>'api_credential_owner','roles'=>['operator'],'fields'=>[]];}
        $auditAuthorizer=new SoSecurity\Authorization\Authorizer($provider,new SoSecurity\Authorization\RolePolicy($auditRoleRules),$auditLogger);
        if(strpos($argv[4]??'','custom-')===0){
            $customState=(object)['allowed'=>true,'fail'=>false,'failAt'=>0,'calls'=>0,'write'=>null,'selectorMode'=>$argv[4],'selectorWrite'=>null];
            $customProvider=new class(new SoSecurity\Authorization\RolePolicy($auditRoleRules),$customState) implements SoSecurity\Authorization\SnapshotEvaluator{
                private $base;private $state;
                public function __construct($base,$state){$this->base=$base;$this->state=$state;}
                public function selectors(SoSecurity\Auth\Account $actor,string $action,SoSecurity\Authorization\Resource $resource,array $requestedFields):array{if($this->state->selectorMode==='custom-selector-fault'){throw new RuntimeException('PRIVATE-SELECTOR');}if($this->state->selectorWrite!==null){$run=$this->state->selectorWrite;$this->state->selectorWrite=null;$run();}return ['owner'=>['table'=>$this->state->selectorMode==='custom-selector-invalid'?'undeclared_table':'account_example','key'=>['scope'=>$resource->scope(),'subject'=>$resource->id()],'columns'=>['roles']]];}
                public function decide(SoSecurity\Auth\Account $actor,string $action,SoSecurity\Authorization\Resource $resource,array $requestedFields,array $facts):?SoSecurity\Authorization\Decision{
                    ++$this->state->calls;if($this->state->fail||$this->state->calls===$this->state->failAt){throw new RuntimeException('PRIVATE-CUSTOM-POLICY');}if($this->state->write!==null){$run=$this->state->write;$this->state->write=null;$run();}
                    return $this->state->allowed&&isset($facts['owner'])&&$facts['owner']['roles']==='[]'?$this->base->decide($actor,$action,$resource,$requestedFields):SoSecurity\Authorization\Decision::deny();
                }
            };
            $customPolicy=new SoSecurity\Authorization\SnapshotPolicy($customProvider,$sql,hash('sha256','owned-custom-policy-v1'));
            $customAudit=strpos($argv[4],'plain')===false;
            $auditAuthorizer=new SoSecurity\Authorization\Authorizer($provider,$customPolicy,$customAudit?$auditLogger:null);
        }
        $config['api_credentials']=['keys'=>'keys','request_guard'=>'api_audit_guard','scope_provider'=>'api_audit_scopes','management_authorization'=>'api_audit_authorizer','management_subject'=>'api_audit_actor','policy'=>['allowed_scopes'=>['records:read','records:write'],'io_milliseconds'=>30000]];
        if(in_array($argv[4]??'',['defaults','profile-defaults'],true)){unset($config['api_credentials']['policy']['io_milliseconds']);}
        if(in_array($argv[4]??'',['post-audit-delay','post-audit-denial','post-audit-timeout','audit-admission-timeout','business-budget-before','business-budget-after','bearer-auth-budget','bearer-header-budget'],true)){$config['api_credentials']['policy']['io_milliseconds']=5000;}
        $services['api_audit_guard']=$auditGuard;$services['api_audit_scopes']=static function()use(&$auditScopes,&$bearerScopeFault,&$bearerScopeReentry):array{if($bearerScopeFault){throw new RuntimeException('PRIVATE-BEARER-SCOPES');}if($bearerScopeReentry!==null){$run=$bearerScopeReentry;$bearerScopeReentry=null;$run();}return $auditScopes;};$services['api_audit_authorizer']=$auditAuthorizer;$services['api_audit_actor']=static function():string{return 'fresh-user';};
    }
    if(strpos($argv[4]??'','captured-permission-')===0){
        require __DIR__.'/captured-permission-support.php';list($capturedFeature,$capturedCase)=explode('-',substr($argv[4],strlen('captured-permission-')),2);
        $capturedEvaluator=new CapturedPermissionEvaluator($capturedFeature,$capturedCase);$capturedPolicy=new SoSecurity\Authorization\SnapshotPolicy($capturedEvaluator,$sql,hash('sha256','owned-captured-native-v1:'.$capturedFeature.':'.$capturedCase));
        $services['captured_policy']=$capturedPolicy;$config['authorization']['policy']='captured_policy';$config['signed_links']=['keys'=>'keys','request_guard'=>'captured_link_guard','origin'=>'https://links.example.test','ttl'=>60];$services['captured_link_guard']=static function():bool{return true;};
    }
    $sdk=SoSecurity\Security::fromArray($config,$services,$clock);$before=$source->digest();
    if(($argv[3]??'')==='idempotency_factory'){require __DIR__.'/idempotency-factory-boundary.php';return;}
    if(($argv[3]??'')==='quarantine'){require __DIR__.'/native-quarantine-factory.php';return;}
    if(($argv[3]??'')==='leases'){require __DIR__.'/native-leases.php';return;}
    if(($argv[3]??'')==='proofs'){
        foreach(['csrf','captcha'] as $method){Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($sdk,$method){$sdk->$method();});}
        Check::same($before,$source->digest());
        $proofStore=new SoSecurity\Storage\FileStore($directory.'/files','fresh-site:tokens',$clock);
        $proofState=new A\StateProofConnection($boundary,$witness,$source,$files,'files',$proofStore,'fresh-site','tenant',$epoch,$clock,static function(string $action,string $authorityScope,string $scope,string $binding){return $authorityScope==='tenant'&&$scope==='form'&&$binding==='owned-browser'?'owned-browser':null;});
        $csrf=$sdk->csrf($proofState);$captcha=$sdk->captcha($proofState);
        $token=$csrf->issue('form','owned-browser');Check::same(true,$csrf->verify('form','owned-browser',$token,true));Check::same(false,$csrf->verify('form','owned-browser',$token,true));
        $challenge=$captcha->arithmetic('form','owned-browser');preg_match('/^(\d+) \+ (\d+)/',$challenge->prompt,$parts);
        Check::same(true,$captcha->verify('form','owned-browser',$challenge->id,(string)($parts[1]+$parts[2])));
        Check::same(false,$captcha->verify('form','owned-browser',$challenge->id,(string)($parts[1]+$parts[2])));
        Check::same($source->digest(),$witness->inspect(static function():bool{return true;})['digest']);Check::same(0,$lookups);
        echo 'PASS protected authentication proof factory: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;return;
    }
    $registry=$sdk->accountFactors();$auth=$sdk->authentication();$sessions=$sdk->sessions();
    Check::same($before,$source->digest());Check::same(0,$lookups);
    $columns=array_keys($definitions['account_example']['columns']);
    if(in_array($argv[3]??'',['dispatch_budgets','native_dispatch'],true)){require __DIR__.'/native-dispatch-before-bind.php';}
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
    $authColumns=['scope','subject','credential_version','status','verified','mfa_required','roles','password'];
    $policy=$sdk->stateAccountPolicy($witness,$source,$sql,$files,'sql','files','account_example',array_combine($authColumns,$authColumns));
    if($factory){$accountConnection=$sdk->stateAccountConnection($policy,'address','address_version');$registration=$sdk->registration();$address=$sdk->addressChange();}
    else{
    $registration=new A\Registration($pdo,'fresh-site','tenant',$epoch,$keys,$keys,$accounts,$notices,$hasher,SoSecurity\Password\PasswordPolicy::forHasher($hasher),static function():bool{return true;},static function():bool{return true;},new A\Policy(),$clock,$manager,null,$accountConnection);
    $authorizer=new SoSecurity\Authorization\Authorizer($provider,new SoSecurity\Authorization\RolePolicy([]));
    $grants=new SoSecurity\Operation\Grants($store,$sessions,$authorizer,static function():bool{return true;},null,$clock,$boundary);
    $address=new A\AddressChange($pdo,'fresh-site','tenant',$epoch,$keys,$keys,$accounts,$notices,$sessions,$grants,static function():bool{return true;},static function():bool{return true;},new A\Policy(),$clock,$manager,null,$accountConnection);
    }
    if(($argv[3]??'')==='address_actions'&&strpos($argv[4]??'','captured-')===0){require __DIR__.'/address-captured-policy.php';return;}
    if(($argv[3]??'')==='address_actions'){require __DIR__.'/native-address-actions.php';return;}
    if(($argv[3]??'')==='address_proofs'){require __DIR__.'/native-address-proofs.php';return;}
    if(in_array($argv[3]??'',['dispatch_budgets','native_dispatch'],true)){require __DIR__.'/native-dispatch-budgets.php';return;}
    if(($argv[3]??'')==='outbox_initial'){require __DIR__.'/native-outbox-initial.php';return;}
    if(($argv[3]??'')==='outbox_rotation'){require __DIR__.'/native-outbox-rotation.php';return;}
    if(($argv[3]??'')==='audit_missing'){$missingLogger=new SoSecurity\Audit\AuditLogger(new SoSecurity\Audit\SqlSink($pdo,'fresh-site',4,3600,$clock,10000),str_repeat('a',32));$beforeAudit=$source->digest();Check::same(null,$policy->credentialAuditContext($missingLogger));Check::same($beforeAudit,$source->digest());echo 'PASS missing audit source '.Check::$assertions.PHP_EOL;return;}
    if(($argv[3]??'')==='audit_delegation'){require __DIR__.'/native-audit-delegation.php';return;}
    if(($argv[3]??'')==='audit_write'){require __DIR__.'/native-audit-write.php';return;}
    if(($argv[3]??'')==='audit_source'){require __DIR__.'/native-audit-source.php';return;}
    if(($argv[3]??'')==='idempotency'){require __DIR__.'/native-idempotency-maintenance.php';return;}
    if(($argv[3]??'')==='idempotency_request'){require __DIR__.'/native-idempotency-request.php';return;}
    $factorNotices=($argv[3]??'')==='factor_notices';
    $maintenanceServices=['registration'=>$registration,'address_change'=>$address];if($expired){$maintenanceServices['recovery']=$sdk->recovery();$maintenanceServices['mailbox_recovery']=$sdk->mailboxRecovery();}
    if($factorNotices){$maintenanceServices['factor_notices']=new A\FactorNotices($pdo,'fresh-site','tenant',$epoch,$keys,$keys,$accounts,$notices,$manager,static function():bool{return true;},static function():bool{return true;},new A\Policy(),$clock,$accountConnection);}
    $boundary->run('fresh.maintenance.initialize',static function()use($maintenanceServices):void{foreach($maintenanceServices as $service){$service->initialize();}});
    foreach($maintenanceServices as $purpose=>$service){foreach(['maintain','rotate'] as $action){
        $target=$accountConnection->maintenanceTarget($purpose,$action,1,'');
        $permission=new A\StatePermission('account.'.$purpose.'.'.$action,'tenant','fresh-user',$target,$token,['maintainer'],1,300,true,false,['password']);
        $before=$witness->inspect(static function():bool{return true;});$reads=$lookups;
        Check::same(null,$service->{$action.'For'}($policy,$permission,1));Check::same($before,$witness->inspect(static function():bool{return true;}));Check::same($reads,$lookups);
    }}
    $boundary->run('fresh.maintenance.roles',static function()use($pdo):void{$pdo->prepare('UPDATE account_example SET roles=?')->execute(['["maintainer"]']);});
    $boundary->run('fresh.maintenance.seed',static function()use($registration,$maintenanceServices,$expired,$factorNotices,$pdo):void{$registration->request('pending@example.test','owned-maintenance');if($factorNotices){$pdo->beginTransaction();try{foreach(['1','2'] as $digit){$maintenanceServices['factor_notices']->publish('factor_management_completed','fresh-user',str_repeat($digit,64));}$pdo->commit();}catch(Throwable $error){if($pdo->inTransaction()){$pdo->rollBack();}throw $error;}}if($expired){$maintenanceServices['recovery']->request('fresh@example.test','owned-password-history');$maintenanceServices['mailbox_recovery']->request('fresh@example.test','requested@example.test','owned-mailbox-history');}});$clock->time+=172800;
    $login=$auth->password('tenant','fresh-maintainer-browser','fresh@example.test',$password);Check::same('authenticated',$login->status());$token=$login->credential()->token();
    $accountSnapshot=$pdo->query('SELECT * FROM account_example ORDER BY scope,subject')->fetchAll(PDO::FETCH_ASSOC);$queueSnapshot=$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY namespace,order_no')->fetchAll(PDO::FETCH_ASSOC);
    foreach($maintenanceServices as $purpose=>$service){foreach(['maintain','rotate'] as $action){
        $target=$accountConnection->maintenanceTarget($purpose,$action,1,'');
        $permission=new A\StatePermission('account.'.$purpose.'.'.$action,'tenant','fresh-user',$target,$token,['maintainer'],1,300,true,false,['password']);
        $managementAllowed=false;$before=$witness->inspect(static function():bool{return true;});
        Check::same(null,$service->{$action.'For'}($policy,$permission,1));Check::same($before,$witness->inspect(static function():bool{return true;}));
        $managementAllowed=true;
        Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($service,$policy,$permission,$action):void{$service->{$action.'For'}($policy,$permission,2);});
        $nested=static function()use($service,$policy,$permission,$action):void{Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($service,$policy,$permission,$action):void{$service->{$action.'For'}($policy,$permission,1);});};
        $result=$service->{$action.'For'}($policy,$permission,1);Check::same(null,$nested);Check::same(true,is_array($result));if($purpose==='factor_notices'){Check::same(true,isset($result['next']));}else{Check::same(true,$result['examined']<=1);}if(in_array($purpose,['registration','recovery','mailbox_recovery','factor_notices'],true)&&$action==='maintain'){Check::same(true,$result['removed']>0);}
        $after=$witness->inspect(static function():bool{return true;});Check::same('current',$after['status']);Check::same('account.'.$purpose.'.'.$action,$after['intent']['action']);
    }}
    Check::same($accountSnapshot,$pdo->query('SELECT * FROM account_example ORDER BY scope,subject')->fetchAll(PDO::FETCH_ASSOC));Check::same($queueSnapshot,$pdo->query('SELECT * FROM sosecurity_outbox_records ORDER BY namespace,order_no')->fetchAll(PDO::FETCH_ASSOC));
    $finalPurpose=($expired||$factorNotices)?$argv[3]:'registration';$finalService=$maintenanceServices[$finalPurpose];
    $before=$witness->inspect(static function():bool{return true;});
    $target=$accountConnection->maintenanceTarget($finalPurpose,'maintain',50,'');
    $permission=new A\StatePermission('account.'.$finalPurpose.'.maintain','tenant','fresh-user',$target,$token,['maintainer'],1,300,true,false,['password']);
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($finalService,$policy,$permission):void{$finalService->maintainFor($policy,$permission,51);});
    Check::same($before,$witness->inspect(static function():bool{return true;}));
    if(($argv[3]??'')==='clock'){
        $validTime=$clock->time;$unchanged=$witness->inspect(static function():bool{return true;});$phaseCount=count($phases);
        foreach(['throw','type','negative','overflow'] as $fault){
            $clock->fail=$fault==='throw';$clock->time=$fault==='type'?'private-clock-type':($fault==='negative'?-1:($fault==='overflow'?PHP_INT_MAX:$validTime));
            foreach([static function()use($policy):void{$policy->now();},static function()use($finalService,$policy,$permission):void{$finalService->maintainFor($policy,$permission,50);}] as $operation){
                try{$operation();throw new RuntimeException('Invalid permission clock accepted');}
                catch(SoSecurity\Storage\StorageException $error){Check::same('account.clock',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'private-')!==false);}
            }
            $clock->fail=false;$clock->time=$validTime;
            Check::same($unchanged,$witness->inspect(static function():bool{return true;}));Check::same($phaseCount,count($phases));
        }
        Check::same(true,is_array($finalService->maintainFor($policy,$permission,50)));Check::same('current',$witness->inspect(static function():bool{return true;})['status']);
        echo 'PASS native permission clock failures: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').PHP_EOL;return;
    }
    if($mapping){
        $shadow=$sdk->stateAccountPolicy($witness,$source,$sql,$files,'sql','files','account_shadow',array_combine($authColumns,$authColumns));
        $boundary->run('fresh.mapping.copy',static function()use($pdo):void{$pdo->exec('INSERT INTO account_shadow SELECT * FROM account_example');$pdo->prepare('UPDATE account_example SET roles=? WHERE subject=?')->execute(['[]','fresh-user']);});
        $unchanged=$witness->inspect(static function():bool{return true;});Check::same(null,$finalService->maintainFor($policy,$permission,50));Check::same($unchanged,$witness->inspect(static function():bool{return true;}));
        try{$finalService->maintainFor($shadow,$permission,50);throw new RuntimeException('Different account mapping accepted for native maintenance');}
        catch(SoSecurity\Exception\ConfigurationException $error){Check::same('configuration.state_connection',$error->reason());}
        Check::same($unchanged,$witness->inspect(static function():bool{return true;}));
        echo 'PASS native maintenance account mapping: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').PHP_EOL;return;
    }
    $late=true;
    try{$finalService->maintainFor($policy,$permission,50);throw new RuntimeException('Late permission change returned success');}
    catch(SoSecurity\Storage\StorageException $error){Check::same('account.completion_unknown',$error->reason());}
    Check::same('pending',$witness->inspect(static function():bool{return true;})['status']);
    // No continuation, reset or recovery activation is attempted.
    Check::same(true,in_array('admission',$phases,true));Check::same(true,in_array('complete',$phases,true));
    echo 'PASS native account maintenance: '.Check::$assertions.' assertions PHP '.PHP_VERSION.' '.($mysql?'mysql':'sqlite').'; '.($factory?'public factory':'direct constructor').', current-generation maintenance, fresh account, no handoff or recovery activation'.PHP_EOL;
} finally {
    if($mysql&&$pdo instanceof PDO){foreach(array_reverse($created) as $table){$pdo->exec('DROP TABLE '.$table);}}
    foreach(['witness','fence','files','scratch','budget','spool','web'] as $name){if(is_dir($directory.'/'.$name)){cleanDirectory($directory.'/'.$name);}}
    cleanDirectory($directory);
}
