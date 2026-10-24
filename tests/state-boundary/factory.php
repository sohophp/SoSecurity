<?php
declare(strict_types=1);
require __DIR__.'/permission-support.php';

function stateFactoryConfiguration(callable $body,?string $reason=null):void
{
    ++Check::$assertions;try{$body();}catch(SoSecurity\Exception\ConfigurationException $error){if($reason!==null){Check::same($reason,$error->reason());}return;}throw new RuntimeException('Expected protected factory configuration refusal.');
}

managedCase(static function(ManagedEnvironment $e):void{
    $source=new class($e->pdo) implements SoSecurity\Account\StateStoreSource {
        private $pdo;public $calls=0;
        public function __construct(PDO $pdo){$this->pdo=$pdo;}
        public function connection():PDO{++$this->calls;return $this->pdo;}
        public function fingerprint():string{++$this->calls;return hash('sha256','owned-weak-factor-source');}
        public function digest():string{++$this->calls;return hash('sha256','owned-weak-factor-state');}
        public function coversStore(SoSecurity\Storage\AtomicStore $store):bool{++$this->calls;return true;}
    };
    $directory=$e->directory.'/weak-factor-witness';mkdir($directory,0700);$persists=0;
    $witness=new SoSecurity\Account\LocalStateWitness($e->pdo,$directory,'managed-test','tenant',str_repeat('e',64),$e->keys,$source,static function()use(&$persists):bool{++$persists;return true;},5000,1);
    $boundary=new SoSecurity\Account\StateBoundary($witness,static function():bool{return true;});$source->calls=0;
    stateFactoryConfiguration(static function()use($e,$boundary):void{lifecycleRaw($e)->bindStateBoundary($boundary);},'configuration.state_boundary');
    Check::same(0,$source->calls);Check::same(0,$persists);Check::same([],glob($directory.'/*'));
    Check::same(false,SoSecurity\Storage\FileStateBoundary::protects(new SoSecurity\Storage\FileStore($e->directory.'/factors','managed-factor-test',$e->clock)));
});

entryCase(static function(EntryEnvironment $x):void{
    $e=$x->e;$fence=entryPromote($x);$x->boundary->run('owned.factory.roles',static function()use($e):void{$e->pdo->exec("UPDATE account_example SET roles='[\"operator\"]'");});
    mkdir($e->directory.'/public-budget',0700);$calls=['worker'=>0,'read'=>0,'manage'=>0,'grant'=>0,'risk'=>0];
    $config=['site'=>'managed-test','storage'=>['driver'=>'file','directory'=>$e->directory.'/public-budget'],
        'authentication'=>['identity_provider'=>'identity','request_guard'=>'request','managed_factors'=>true,'state_boundary'=>['authority'=>'boundary','store'=>'auth_store','scope'=>'tenant','epoch'=>str_repeat('e',64)]],
        'account_factors'=>['connection'=>'db','scope'=>'tenant','epoch'=>str_repeat('e',64),'repository'=>'accounts','integrity_keys'=>'keys','totp'=>'raw','fence'=>'fence','worker_guard'=>'worker','read_guard'=>'read','management_guard'=>'manage'],
        'authorization'=>['policy'=>'role_policy'],'operations'=>['request_guard'=>'grant_guard'],'remember'=>['keys'=>'keys','risk_guard'=>'risk'],'budgets'=>['public'=>[]]];
    $services=['boundary'=>$x->boundary,'auth_store'=>$x->store,'identity'=>$x->provider,'request'=>$x->guard,'db'=>$e->pdo,'accounts'=>$e->accounts,'keys'=>$e->keys,'raw'=>lifecycleRaw($e),'fence'=>$fence,
        'role_policy'=>new SoSecurity\Authorization\RolePolicy(['account.review'=>['type'=>'account','roles'=>['operator'],'fields'=>[]]])];
    foreach(['worker','read','manage'] as $name){$services[$name]=static function()use(&$calls,$name):bool{++$calls[$name];return true;};}
    $services['grant_guard']=static function()use(&$calls):bool{++$calls['grant'];return true;};
    $services['risk']=static function()use(&$calls):SoSecurity\Auth\DeviceRiskDecision{++$calls['risk'];return new SoSecurity\Auth\DeviceRiskDecision('allow','none');};
    $root=$x->inspect();$files=entryFiles($x);$queries=$e->pdo->queries;$lookups=$x->lookups;$beforeCalls=$calls;
    $sdk=SoSecurity\Security::fromArray($config,$services,$e->clock);
    $checks=array_column($sdk->diagnose(),null,'check');
    foreach(['authority','store','coverage','request_guard','identity','worker_fence','persistence','all_writers','independent_backup','final_recovery'] as $name){Check::same('manual',$checks['authentication.state_boundary.'.$name]['status']);}
    $sessions=$sdk->sessions();$auth=$sdk->authentication();$remember=$sdk->rememberedLogin();$grants=$sdk->operations();
    foreach(['sessions','authentication','rememberedLogin','operations','authorization','accountFactors','managedSecondFactor'] as $method){Check::same($sdk->$method(),$sdk->$method());}
    $columns=['scope','subject','credential_version','status','verified','mfa_required','roles','password'];
    $policy=$sdk->stateAccountPolicy($x->witness,$x->source,$x->sources['sql'],$x->sources['files'],'complete-sql','sessions-and-factors','account_example',array_combine($columns,$columns));
    Check::same(true,$grants->recoveryContext($sessions,$x->boundary,$policy));
    Check::same($queries,$e->pdo->queries);Check::same($lookups,$x->lookups);Check::same($beforeCalls,$calls);Check::same($files,entryFiles($x));Check::same($root,$x->inspect());
    Check::same(true,$sdk->budgetLimiter('public')->consume('factory','request')->allowed());Check::same($root,$x->inspect());

    foreach(['authority','store','scope','epoch'] as $name){$bad=$config;unset($bad['authentication']['state_boundary'][$name]);stateFactoryConfiguration(static function()use($bad):void{SoSecurity\Security::fromArray($bad);});}
    foreach([false,[],['unknown'=>true]] as $state){$bad=$config;$bad['authentication']['state_boundary']=$state;stateFactoryConfiguration(static function()use($bad):void{SoSecurity\Security::fromArray($bad);});}
    $bad=$config;$bad['authentication']['state_boundary']['scope']='foreign';stateFactoryConfiguration(static function()use($bad):void{SoSecurity\Security::fromArray($bad);},'configuration.state_boundary');
    foreach(['boundary','auth_store','request','fence','identity'] as $name){
        $badServices=$services;$badServices[$name]=new stdClass();$bad=SoSecurity\Security::fromArray($config,$badServices,$e->clock);$queries=$e->pdo->queries;$beforeCalls=$calls;
        stateFactoryConfiguration(static function()use($bad):void{$bad->sessions();},'configuration.state_boundary');
        Check::same($queries,$e->pdo->queries);Check::same($beforeCalls,$calls);Check::same($root,$x->inspect());
    }
    $badServices=$services;$badServices['boundary']=new SoSecurity\Account\StateBoundary($x->witness,static function():bool{return true;});$bad=SoSecurity\Security::fromArray($config,$badServices,$e->clock);
    stateFactoryConfiguration(static function()use($bad):void{$bad->sessions();},'configuration.state_boundary');
    mkdir($e->directory.'/uncovered-factory',0700);$outside=new SoSecurity\Storage\FileStore($e->directory.'/uncovered-factory','outside',$e->clock);
    $badServices=$services;$badServices['auth_store']=$outside;$bad=SoSecurity\Security::fromArray($config,$badServices,$e->clock);stateFactoryConfiguration(static function()use($bad):void{$bad->sessions();},'configuration.state_boundary');
    Check::same('fail',array_column($bad->diagnose(),null,'check')['authentication.state_boundary.coverage']['status']);
    $badServices=$services;$badServices['raw']=new SoSecurity\Mfa\TotpFactors($outside,new SoSecurity\Crypto\Cipher('test',['test'=>str_repeat('t',32)],'managed-test'),'Managed test',$e->clock);
    $bad=SoSecurity\Security::fromArray($config,$badServices,$e->clock);stateFactoryConfiguration(static function()use($bad):void{$bad->sessions();},'configuration.state_coverage');
    $alias='boundary';$aliased=$config;$aliased['authentication']['state_boundary']['authority']=&$alias;$immutable=SoSecurity\Security::fromArray($aliased,$services,$e->clock);$alias='wrong';
    Check::same('boundary',$immutable->config()->authentication()['state_boundary']['authority']);
    $badServices=$services;$badServices['request']=static function():bool{return true;};$bad=SoSecurity\Security::fromArray($config,$badServices,$e->clock);
    Check::same('fail',array_column($bad->diagnose(),null,'check')['authentication.state_boundary.request_guard']['status']);
    stateFactoryConfiguration(static function()use($bad):void{$bad->authentication();},'configuration.state_boundary');
    $badServices=$services;$badServices['fence']=$x->fence;$bad=SoSecurity\Security::fromArray($config,$badServices,$e->clock);stateFactoryConfiguration(static function()use($bad):void{$bad->sessions();},'configuration.state_boundary');
    $badConfig=$config;$badConfig['storage']['directory']=$e->directory.'/factors';$bad=SoSecurity\Security::fromArray($badConfig,$services,$e->clock);stateFactoryConfiguration(static function()use($bad):void{$bad->budgetLimiter('public');},'configuration.state_budget_overlap');
    $badConfig=$config;$badConfig['operations']['request_guard']='request';$bad=SoSecurity\Security::fromArray($badConfig,$services,$e->clock);stateFactoryConfiguration(static function()use($bad):void{$bad->operations();},'configuration.operation_guard');
    stateFactoryConfiguration(static function()use($sdk):void{$sdk->resetTokens();},'configuration.state_entry_unsupported');
    stateFactoryConfiguration(static function()use($sdk):void{$sdk->apiKeys();},'configuration.state_entry_unsupported');
    stateFactoryConfiguration(static function()use($sdk):void{$sdk->registration();},'configuration.state_entry_unsupported');

    $e->clock->time+=30;$first=$auth->password('tenant','owned-factory-browser','owned@example.test',$e->password);Check::same('mfa_required',$first->status());
    $login=$auth->secondFactor('tenant','owned-factory-browser',$first->challenge(),normalFactor($e));Check::same('authenticated',$login->status());$token=$login->credential()->token();
    Check::same(true,$sessions->verify('tenant','user',$token,2)!==null);
    $credential=$remember->issue('tenant','user',$token);Check::same(true,$credential!==null);$resumed=$remember->resume('tenant',$credential->token());Check::same('authenticated',$resumed->status());Check::same(true,$calls['risk']>0);
    $oldPermission=new SoSecurity\Account\StatePermission('account.review','tenant','user','user',$token,['operator']);permissionRefuse($x,$policy,$oldPermission);
    $e->clock->time+=30;$again=$auth->password('tenant','owned-factory-browser','owned@example.test',$e->password,'',$resumed->session()->token());Check::same('mfa_required',$again->status());
    $fresh=$auth->secondFactor('tenant','owned-factory-browser',$again->challenge(),normalFactor($e));Check::same('authenticated',$fresh->status());$token=$fresh->credential()->token();
    $permission=new SoSecurity\Account\StatePermission('account.review','tenant','user','user',$token,['operator']);$intent=new SoSecurity\Operation\Intent('account.review',new SoSecurity\Authorization\Resource('tenant','account','user','1'));
    $beforeCalls=$calls;$before=entryFiles($x);$root=$x->inspect();witnessReason('account.state_required',static function()use($grants,$token,$intent):void{$grants->begin('tenant','user',$token,$intent);});Check::same($beforeCalls,$calls);Check::same($before,entryFiles($x));Check::same($root,$x->inspect());
    $confirmation=$x->boundary->authorized('account.review','tenant','user',$policy,$permission,static function()use($grants,$token,$intent){return $grants->begin('tenant','user',$token,$intent);});Check::same(true,$confirmation instanceof SoSecurity\Operation\Confirmation);
    $backup=entryFiles($x);$sessions->revokeAll('tenant','user');$current=$x->inspect();entryRestore($x,$backup);$lookups=$x->lookups;
    witnessReason('account.witness_stale',static function()use($sessions,$token):void{$sessions->verify('tenant','user',$token,2);});
    witnessReason('account.witness_stale',static function()use($remember,$resumed):void{$remember->resume('tenant',$resumed->nextCredential()->token());});
    Check::same($lookups,$x->lookups);Check::same($current,$x->inspect());
});
echo 'PASS explicit protected authentication factory: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; exact cached services/pure policy, effect-free construction and diagnostics, live password/MFA/session/remember/grants, independent budgets, unsupported entries fail closed, restored old files refused before provider',PHP_EOL;
