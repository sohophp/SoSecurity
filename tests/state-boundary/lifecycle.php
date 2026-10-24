<?php
declare(strict_types=1);
require __DIR__.'/permission-support.php';

function lifecycleReason(string $reason,callable $body):void
{
    ++Check::$assertions;
    try{$body();}catch(SoSecurity\Exception\SecurityException $e){Check::same($reason,$e->reason());return;}catch(SoSecurity\Exception\ConfigurationException $e){Check::same($reason,$e->reason());return;}
    throw new RuntimeException('Expected lifecycle refusal: '.$reason);
}
managedCase(static function(ManagedEnvironment $e):void{
    $x=new EntryEnvironment($e,true);$calls=0;
    $authority=static function()use(&$calls,$x):bool{++$calls;Check::same(true,$x->boundary->active());return true;};
    $grants=new SoSecurity\Operation\Grants($x->store,$x->sessions,new SoSecurity\Authorization\Authorizer($x->provider),$authority,null,$e->clock,$x->boundary);
    $policy=new SoSecurity\Account\Policy();$notifications=new SoSecurity\Account\Notifications('test',['test'=>str_repeat('n',32)],$e->clock);
    $hasher=new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]);$passwords=new SoSecurity\Password\PasswordPolicy();
    $build=static function($state=null)use($e,$x,$authority,$grants,$policy,$notifications,$hasher,$passwords):array{
        $common=[$e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->keys,$e->accounts,$notifications];
        return [
            new SoSecurity\Account\Registration(...array_merge($common,[$hasher,$passwords,$authority,$authority,$policy,$e->clock,$authority,$authority,$state])),
            new SoSecurity\Account\Recovery(...array_merge($common,[$hasher,$passwords,$authority,$authority,$policy,$e->clock,$authority,$authority,$x->factorAdapter,null,$state])),
            new SoSecurity\Account\MailboxRecovery(...array_merge($common,[$authority,$authority,$authority,$policy,$e->clock,$authority,$authority,$x->factorAdapter,$state])),
            new SoSecurity\Account\AddressChange(...array_merge($common,[$x->sessions,$grants,$authority,$authority,$policy,$e->clock,$authority,$authority,$state]))
        ];
    };
    $legacy=$build();$snapshot=$x->source->digest();$root=$x->inspect();$queries=$e->pdo->queries;
    lifecycleReason('configuration.state_connection',static function()use($x,$e,$policy):void{permissionPolicy($x)->accountConnection($x->boundary,$e->accounts,$policy,'address','password');});
    $state=permissionPolicy($x)->accountConnection($x->boundary,$e->accounts,$policy,'address','address_version');
    Check::same($queries,$e->pdo->queries);Check::same($root,$x->inspect());Check::same($snapshot,$x->source->digest());Check::same(0,$calls);
    $bound=$build($state);
    lifecycleReason('configuration.state_connection',static function()use($build):void{$build();});
    $before=permissionState($x);$queries=$e->pdo->queries;$reads=$e->reads;
    foreach(array_merge($legacy,$bound) as $service){
        lifecycleReason('account.state_required',static function()use($service):void{$service->initialize();});
        lifecycleReason('account.state_required',static function()use($service):void{$service->notification(str_repeat('a',64));});
        lifecycleReason('account.state_required',static function()use($service):void{$service->maintain();});
    }
    lifecycleReason('account.state_required',static function()use($e):void{$e->accounts->find('tenant','user');});
    $unit=new SoSecurity\Support\SqlTransaction($e->pdo,$e->clock,30000);
    lifecycleReason('account.state_required',static function()use($unit,&$calls):void{$unit->run(static function()use(&$calls):void{++$calls;});});
    Check::same($queries,$e->pdo->queries);Check::same($reads,$e->reads);Check::same(0,$calls);Check::same($before,permissionState($x));
    $observation=SoSecurity\Support\SqlTransaction::forObservation($e->pdo,$e->clock,30000);
    lifecycleReason('configuration.state_observation',static function()use($observation):void{$observation->run(static function()use($observation):void{$observation->query('UPDATE account_example SET verified=0');});});
    lifecycleReason('configuration.state_observation',static function()use($observation,&$calls):void{$observation->run(static function()use($observation,&$calls):void{$observation->invoke(static function()use(&$calls):void{++$calls;},[],'owned.callback');});});
    lifecycleReason('configuration.state_observation',static function()use($observation):void{$observation->run(static function()use($observation):void{$observation->query('PRAGMA user_version=42');});});
    Check::same(0,$calls);Check::same($before,permissionState($x));
    $x->boundary->run('owned.lifecycle.initialize',static function()use($bound):void{foreach($bound as $service){$service->initialize();}});
    Check::same('current',$x->inspect()['status']);
    $x->boundary->run('owned.legacy.refuse',static function()use($legacy):void{foreach($legacy as $service){lifecycleReason('account.state_required',static function()use($service):void{$service->initialize();});}});
    $registration=$bound[0];
    $x->boundary->run('owned.registration.request',static function()use($registration):void{$registration->request('new-owner@example.test','owned-source');});
    $ids=$e->observer->query("SELECT record_id FROM sosecurity_account_records WHERE kind='notice'")->fetchAll(PDO::FETCH_COLUMN);$delivery=null;
    foreach($ids as $id){$candidate=$x->boundary->run('owned.registration.notice',static function()use($registration,$id){return $registration->notification($id);});if($candidate!==null&&$candidate->notice()->type()==='verify_registration'){$delivery=$candidate;}}
    Check::same(true,$delivery instanceof SoSecurity\Account\Delivery);
    Check::same(false,$x->boundary->run('owned.registration.bad-proof',static function()use($registration,$delivery):bool{return $registration->confirm($delivery->selector(),str_repeat('0',64),'Owned new registration password 49!','owned-source');}));
    Check::same('current',$x->inspect()['status']);
    Check::same(false,$x->boundary->run('owned.registration.weak-password',static function()use($registration,$delivery):bool{return $registration->confirm($delivery->selector(),$delivery->notice()->token(),'short','owned-source');}));
    Check::same('current',$x->inspect()['status']);
    Check::same(true,$x->boundary->run('owned.registration.confirm',static function()use($registration,$delivery):bool{return $registration->confirm($delivery->selector(),$delivery->notice()->token(),'Owned new registration password 49!','owned-source');}));
    Check::same('active',$e->observer->query("SELECT status FROM account_example WHERE address='new-owner@example.test'")->fetchColumn());
    Check::same('current',$x->inspect()['status']);Check::same(false,$x->boundary->active());
    $current=$x->inspect();$callsBefore=$calls;
    // Model a host SQL restore without rolling back the independent witness.
    $e->observer->exec("UPDATE account_example SET status='pending',verified=0,password=NULL WHERE address='new-owner@example.test'");
    lifecycleReason('account.witness_stale',static function()use($x,$registration,$delivery):void{$x->boundary->run('owned.registration.restored',static function()use($registration,$delivery):void{$registration->notification($delivery->notice()->id());});});
    Check::same($callsBefore,$calls);Check::same($current,$x->inspect());Check::same(false,$x->boundary->active());
});
managedCase(static function(ManagedEnvironment $e):void{
    $x=new EntryEnvironment($e,true);$fence=entryPromote($x);mkdir($e->directory.'/public-budget',0700);$calls=0;
    $authority=static function()use(&$calls):bool{++$calls;return true;};
    $config=['site'=>'managed-test','storage'=>['driver'=>'file','directory'=>$e->directory.'/public-budget'],
        'authentication'=>['identity_provider'=>'identity','request_guard'=>'request','managed_factors'=>true,'state_boundary'=>['authority'=>'boundary','store'=>'auth_store','scope'=>'tenant','epoch'=>str_repeat('e',64)]],
        'account_factors'=>['connection'=>'db','scope'=>'tenant','epoch'=>str_repeat('e',64),'repository'=>'accounts','integrity_keys'=>'keys','totp'=>'raw','fence'=>'fence','worker_guard'=>'authority','read_guard'=>'authority','management_guard'=>'authority'],
        'authorization'=>['policy'=>'role_policy'],'operations'=>['request_guard'=>'authority'],
        'accounts'=>['connection'=>'db','scope'=>'tenant','epoch'=>str_repeat('e',64),'repository'=>'accounts','integrity_keys'=>'keys','outbox_keys'=>'keys','notifications'=>'notifications','request_budget'=>'budgets','registration_authority'=>'authority','recovery_authority'=>'authority','mailbox_authority'=>'authority','mailbox_approval'=>'authority','request_guard'=>'authority','management_guard'=>'authority','delivery_guard'=>'authority']];
    $budgetPolicy=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60);
    $services=['boundary'=>$x->boundary,'auth_store'=>$x->store,'identity'=>$x->provider,'request'=>$x->guard,'db'=>$e->pdo,'accounts'=>$e->accounts,'keys'=>$e->keys,'raw'=>lifecycleRaw($e),'fence'=>$fence,'authority'=>$authority,'role_policy'=>new SoSecurity\Authorization\RolePolicy([]),
        'notifications'=>new SoSecurity\Account\Notifications('test',['test'=>str_repeat('n',32)],$e->clock),
        'budgets'=>new SoSecurity\Account\RequestBudgets(new SoSecurity\Storage\FileStore($e->directory.'/public-budget','lifecycle-budget',$e->clock),'managed-test',str_repeat('b',32),array_fill_keys(['site','source','target','subject'],$budgetPolicy),$e->clock)];
    $sdk=SoSecurity\Security::fromArray($config,$services,$e->clock);$columns=['scope','subject','credential_version','status','verified','mfa_required','roles','password'];
    $policy=$sdk->stateAccountPolicy($x->witness,$x->source,$x->sources['sql'],$x->sources['files'],'complete-sql','sessions-and-factors','account_example',array_combine($columns,$columns));
    lifecycleReason('configuration.state_entry_unsupported',static function()use($sdk):void{$sdk->registration();});
    $before=permissionState($x);$queries=$e->pdo->queries;
    $state=$sdk->stateAccountConnection($policy,'address','address_version');Check::same(true,$state->boundTo($x->boundary));
    $services4=[$sdk->registration(),$sdk->recovery(),$sdk->mailboxRecovery(),$sdk->addressChange()];
    Check::same(0,$calls);Check::same($queries,$e->pdo->queries);Check::same($before,permissionState($x));
    foreach($services4 as $service){lifecycleReason('account.state_required',static function()use($service):void{$service->initialize();});}
    $x->boundary->run('owned.factory.lifecycle.initialize',static function()use($services4):void{foreach($services4 as $service){$service->initialize();}});
    Check::same('current',$x->inspect()['status']);Check::same(true,$calls>0);
    $wrong=$config;$wrong['accounts']['recovery_factor']='wrong';$services['wrong']=new stdClass();$services['plan']=$state;$wrong['accounts']['state_connection']='plan';$other=SoSecurity\Security::fromArray($wrong,$services,$e->clock);
    lifecycleReason('configuration.state_connection',static function()use($other):void{$other->recovery();});
    lifecycleReason('configuration.state_connection',static function()use($other):void{$other->mailboxRecovery();});
});
echo 'PASS protected account lifecycle: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; exact SQL registration, old/new raw entry refusal before callbacks, observation isolation, four initializers, real registration with bad proof and weak password, one outer checkpoint across SQL units',PHP_EOL;
