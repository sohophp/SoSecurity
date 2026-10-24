<?php
declare(strict_types=1);
require __DIR__.'/permission-support.php';
function budgetCase(callable $body):void
{
    managedCase(static function(ManagedEnvironment $e)use($body):void{
    $x=new EntryEnvironment($e,true);$fence=entryPromote($x);mkdir($e->directory.'/public-budget',0700);
    $state=(object)['public'=>true,'current'=>true,'business'=>0,'events'=>[],'hook'=>null,'persist'=>0,'fault'=>false,'authorityHook'=>null];
    $request=new SoSecurity\Account\StateRequests(static function(string $action,string $scope)use($state,$x):bool{$state->events[]=['public',$action,$scope,$x->boundary->active()];return $state->public;},static function(string $action,string $scope)use($state,$x):bool{$state->events[]=['current',$action,$scope,$x->boundary->active()];if($state->hook!==null){($state->hook)();}return $state->current;});
    $authority=static function(...$arguments)use($state,$x):bool{++$state->business;Check::same(true,$x->boundary->active());if($state->fault){throw new RuntimeException('Owned synthetic authority fault.');}return $state->authorityHook===null||($state->authorityHook)(...$arguments)===true;};
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
    $x->boundary->run('owned.budget.initialize',static function()use($registration,$recovery,$mailbox):void{$registration->initialize();$recovery->initialize();$mailbox->initialize();});
    $body($e,$x,$sdk,$services,$connection,$state,$request,$authority);
    });
}
