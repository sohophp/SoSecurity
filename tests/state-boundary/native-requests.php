<?php
declare(strict_types=1);
require __DIR__.'/permission-support.php';
function nativeReason(string $reason,callable $body):void
{
    ++Check::$assertions;try{$body();}catch(SoSecurity\Exception\SecurityException $e){Check::same($reason,$e->reason());return;}catch(SoSecurity\Exception\ConfigurationException $e){Check::same($reason,$e->reason());return;}catch(SoSecurity\Exception\ValidationException $e){Check::same($reason,$e->reason());return;}throw new RuntimeException('Expected native lifecycle refusal: '.$reason);
}
function nativeNotice(EntryEnvironment $x,$service,string $type,string $recipient='')
{
    $ids=$x->e->observer->query("SELECT record_id FROM sosecurity_account_records WHERE kind='notice'")->fetchAll(PDO::FETCH_COLUMN);
    foreach($ids as $id){$delivery=$x->boundary->run('owned.native.notice',static function()use($service,$id){return $service->notification($id);});if($delivery!==null&&$delivery->notice()->type()===$type&&($recipient===''||$delivery->notice()->recipient()->value()===$recipient)){return $delivery;}}
    throw new RuntimeException('Expected owned notice purpose.');
}
managedCase(static function(ManagedEnvironment $e):void{
    $x=new EntryEnvironment($e,true);$fence=entryPromote($x);mkdir($e->directory.'/public-budget',0700);
    $state=(object)['public'=>true,'current'=>true,'business'=>0,'events'=>[],'hook'=>null,'persist'=>0,'fault'=>false];
    $request=new SoSecurity\Account\StateRequests(static function(string $action,string $scope)use($state,$x):bool{$state->events[]=['public',$action,$scope,$x->boundary->active()];return $state->public;},static function(string $action,string $scope)use($state,$x):bool{$state->events[]=['current',$action,$scope,$x->boundary->active()];if($state->hook!==null){($state->hook)();}return $state->current;});
    $authority=static function()use($state,$x):bool{++$state->business;Check::same(true,$x->boundary->active());if($state->fault){throw new RuntimeException('Owned synthetic authority fault.');}return true;};
    $config=['site'=>'managed-test','storage'=>['driver'=>'file','directory'=>$e->directory.'/public-budget'],
        'authentication'=>['identity_provider'=>'identity','request_guard'=>'request','managed_factors'=>true,'state_boundary'=>['authority'=>'boundary','store'=>'auth_store','scope'=>'tenant','epoch'=>str_repeat('e',64)]],
        'account_factors'=>['connection'=>'db','scope'=>'tenant','epoch'=>str_repeat('e',64),'repository'=>'accounts','integrity_keys'=>'keys','totp'=>'raw','fence'=>'fence','worker_guard'=>'authority','read_guard'=>'authority','management_guard'=>'authority'],
        'accounts'=>['connection'=>'db','scope'=>'tenant','epoch'=>str_repeat('e',64),'repository'=>'accounts','integrity_keys'=>'keys','outbox_keys'=>'keys','notifications'=>'notifications','request_budget'=>'budgets','registration_authority'=>'authority','recovery_authority'=>'authority','mailbox_authority'=>'authority','mailbox_approval'=>'authority','management_guard'=>'authority','delivery_guard'=>'authority','state_request_guard'=>'native']];
    $policy=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60);
    $services=['boundary'=>$x->boundary,'auth_store'=>$x->store,'identity'=>$x->provider,'request'=>$x->guard,'native'=>$request,'db'=>$e->pdo,'accounts'=>$e->accounts,'keys'=>$e->keys,'raw'=>lifecycleRaw($e),'fence'=>$fence,'authority'=>$authority,
        'notifications'=>new SoSecurity\Account\Notifications('test',['test'=>str_repeat('n',32)],$e->clock),
        'budgets'=>new SoSecurity\Account\RequestBudgets(new SoSecurity\Storage\FileStore($e->directory.'/public-budget','native-budget',$e->clock),'managed-test',str_repeat('b',32),array_fill_keys(['site','source','target','subject'],$policy),$e->clock)];
    $sdk=SoSecurity\Security::fromArray($config,$services,$e->clock);$columns=['scope','subject','credential_version','status','verified','mfa_required','roles','password'];
    $permissions=$sdk->stateAccountPolicy($x->witness,$x->source,$x->sources['sql'],$x->sources['files'],'complete-sql','sessions-and-factors','account_example',array_combine($columns,$columns));$connection=$sdk->stateAccountConnection($permissions,'address','address_version');
    $registration=$sdk->registration();$recovery=$sdk->recovery();$mailbox=$sdk->mailboxRecovery();
    Check::same('manual',array_column($sdk->diagnose(),null,'check')['accounts.state_request_guard']['status']);
    $wrong=$services;$wrong['native']=static function():bool{return true;};$wrong['plan']=$connection;$badConfig=$config;$badConfig['accounts']['state_connection']='plan';$bad=SoSecurity\Security::fromArray($badConfig,$wrong,$e->clock);Check::same('fail',array_column($bad->diagnose(),null,'check')['accounts.state_request_guard']['status']);nativeReason('configuration.state_request',static function()use($bad):void{$bad->registration();});
    $x->boundary->run('owned.native.initialize',static function()use($registration,$recovery,$mailbox):void{$registration->initialize();$recovery->initialize();$mailbox->initialize();});
    $x->persistHook=static function()use($state):bool{++$state->persist;return true;};
    $before=permissionState($x);$queries=$e->pdo->queries;$business=$state->business;
    foreach([$registration,$recovery] as $service){
        nativeReason('account.address',static function()use($service):void{$service->request('bad-address','owned-source');});
        nativeReason('account.proof',static function()use($service):void{$service->confirm('bad-selector',str_repeat('a',64),'Owned new password 49!','owned-source');});
        nativeReason('password.encoding',static function()use($service):void{$service->confirm(str_repeat('a',64),str_repeat('b',64),'','owned-source');});
        nativeReason('account.proof',static function()use($service):void{$service->cancel('bad-selector',str_repeat('a',64),'owned-source');});
    }
    nativeReason('account.address',static function()use($mailbox):void{$mailbox->request('owned@example.test','bad-address','owned-source');});
    nativeReason('account.recovery_proof',static function()use($mailbox):void{$mailbox->confirm(str_repeat('a',64),str_repeat('b',64),'owned-source',[]);});
    nativeReason('account.recovery_proof',static function()use($recovery):void{$recovery->confirm(str_repeat('a',64),str_repeat('b',64),'Owned new password 49!','owned-source',['type'=>'approved','code'=>[]]);});
    Check::same($queries,$e->pdo->queries);Check::same($business,$state->business);Check::same(0,$state->persist);Check::same($before,permissionState($x));
    $state->public=false;nativeReason('account.request_denied',static function()use($registration):void{$registration->request('new-owner@example.test','owned-source');});$state->public=true;
    $state->current=false;nativeReason('account.request_denied',static function()use($registration):void{$registration->request('new-owner@example.test','owned-source');});$state->current=true;
    Check::same(0,$state->persist);Check::same($before,permissionState($x));Check::same($business,$state->business);
    $smallPolicy=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1,60);
    $smallBudget=new SoSecurity\Account\RequestBudgets(new SoSecurity\Storage\FileStore($e->directory.'/public-budget','native-small',$e->clock),'managed-test',str_repeat('b',32),array_fill_keys(['site','source','target','subject'],$smallPolicy),$e->clock);
    $limited=new SoSecurity\Account\Registration($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->keys,$e->accounts,$services['notifications'],new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]),new SoSecurity\Password\PasswordPolicy(),$authority,$smallBudget,null,$e->clock,$authority,$authority,$connection,$request);
    $limited->request('limited-owner@example.test','owned-limited-source');$state->persist=0;$limitedBefore=permissionState($x);$queries=$e->pdo->queries;$calls=$state->business;
    nativeReason('account.budget',static function()use($limited):void{$limited->request('another-owner@example.test','owned-limited-source');});
    Check::same($queries,$e->pdo->queries);Check::same(0,$state->persist);Check::same($calls,$state->business);Check::same($limitedBefore,permissionState($x));
    // The real formal budget adapter is reused across public, subject and final stages.
    $state->events=[];$registration->request('new-owner@example.test','owned-source');
    Check::same([['public','registration.request','tenant',false],['current','registration.request','tenant',false]],$state->events);
    $d=nativeNotice($x,$registration,'verify_registration','new-owner@example.test');
    Check::same(false,$registration->confirm($d->selector(),str_repeat('0',64),'Owned new password 49!','owned-source'));
    Check::same('current',$x->inspect()['status']);
    Check::same(false,$registration->confirm($d->selector(),$d->notice()->token(),'short','owned-source'));
    Check::same('current',$x->inspect()['status']);
    Check::same(true,$registration->confirm($d->selector(),$d->notice()->token(),'Owned new password 49!','owned-source'));
    // Real managed recovery code is consumed; the account is not logged in implicitly.
    $recovery->request('owned@example.test','owned-source');$d=nativeNotice($x,$recovery,'recover_account');
    $code=$e->codes[0];$proof=['type'=>'recovery','code'=>&$code];$state->hook=static function()use(&$code):void{$code='changed-after-preflight';};
    Check::same(true,$recovery->confirm($d->selector(),$d->notice()->token(),'Owned changed password 49!','owned-source',$proof));$state->hook=null;Check::same('changed-after-preflight',$code);
    Check::same('current',$x->inspect()['status']);
    $mailbox->request('owned@example.test','recovered@example.test','owned-source');$d=nativeNotice($x,$mailbox,'recover_address');
    Check::same(true,$mailbox->confirm($d->selector(),$d->notice()->token(),'owned-source',['type'=>'approved','code'=>'owned-test-approval']));
    Check::same('recovered@example.test',$e->observer->query("SELECT address FROM account_example WHERE subject='user' AND scope='tenant'")->fetchColumn());
    Check::same('current',$x->inspect()['status']);Check::same(false,$x->boundary->active());
    $state->fault=true;nativeReason('account.completion_unknown',static function()use($registration):void{$registration->request('fault-owner@example.test','owned-source');});
    Check::same('pending',$x->inspect()['status']);$calls=$state->business;$state->fault=false;
    nativeReason('account.witness_pending',static function()use($registration):void{$registration->request('blocked-owner@example.test','owned-source');});Check::same($calls,$state->business);$x->persistHook=null;
});
echo 'PASS native lifecycle admission: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; pure malformed-input/public/current request refusal, real shared budget admission, actual registration, managed recovery and mailbox recovery; no HTTP/SMTP/external approval acceptance',PHP_EOL;
