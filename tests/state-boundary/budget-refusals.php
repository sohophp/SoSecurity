<?php
declare(strict_types=1);
require __DIR__.'/budget-support.php';
function budgetReason(string $reason,callable $body):Throwable
{
    ++Check::$assertions;try{$body();}catch(Throwable $error){if(!method_exists($error,'reason')){throw $error;}Check::same($reason,$error->reason());return $error;}throw new RuntimeException('Expected budget outcome: '.$reason);
}
function budgetRegistration(ManagedEnvironment $e,EntryEnvironment $x,array $services,SoSecurity\Account\StateAccountConnection $connection,SoSecurity\Account\StateRequestGuard $request,callable $authority,callable $budgets):SoSecurity\Account\Registration
{
    return new SoSecurity\Account\Registration($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->keys,$e->accounts,$services['notifications'],new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]),new SoSecurity\Password\PasswordPolicy(),$authority,$budgets,null,$e->clock,$authority,$authority,$connection,$request);
}
function budgetTables(EntryEnvironment $x):array
{
    $state=permissionState($x);unset($state['witness']);return $state;
}
// Formal shared subject quota is denied after its public reservation; all business data remains identical.
budgetCase(static function(ManagedEnvironment $e,EntryEnvironment $x,$sdk,array $services,$connection,$state,$request,$authority):void{
    $large=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60);$one=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1,60);
    $budgets=new SoSecurity\Account\RequestBudgets(new SoSecurity\Storage\FileStore($e->directory.'/public-budget','subject-only',$e->clock),'managed-test',str_repeat('b',32),['site'=>$large,'source'=>$large,'target'=>$large,'subject'=>$one],$e->clock);
    $s=budgetRegistration($e,$x,$services,$connection,$request,$authority,$budgets);$s->request('owned@example.test','owned-source');$before=budgetTables($x);$root=$x->inspect();$error=budgetReason('account.budget',static function()use($s):void{$s->request('owned@example.test','owned-source');});
    Check::same(true,$error instanceof SoSecurity\Account\StateBudgetRefusal);Check::same(true,$error->confirmed($e->pdo));Check::same(false,$error->confirmed($e->observer));
    Check::same($before,budgetTables($x));$after=$x->inspect();Check::same('current',$after['status']);Check::same($root['digest'],$after['digest']);Check::same($root['revision']+1,$after['revision']);
    $s->request('another-owner@example.test','owned-source');Check::same('current',$x->inspect()['status']);
    // The low-level work API cannot reuse a receipt without entering a new boundary context.
    budgetReason('account.completion_unknown',static function()use($x,$connection,$error):void{$x->witness->work(static function()use($error):void{throw $error;},'witnessBudget',$x->witness->internalOperation('account.registration.request'),null,$connection);});Check::same('pending',$x->inspect()['status']);
});
budgetCase(static function(ManagedEnvironment $e,EntryEnvironment $x,$sdk,array $services,$connection,$state,$request,$authority):void{
    $budgets=static function(string $action,string $phase):bool{return $phase!=='subject';};$s=budgetRegistration($e,$x,$services,$connection,$request,$authority,$budgets);$receipt=budgetReason('account.budget',static function()use($s):void{$s->request('owned@example.test','owned-source');});
    budgetReason('account.completion_unknown',static function()use($x,$connection,$receipt):void{$x->boundary->run('account.registration.request',static function()use($receipt):void{throw $receipt;},null,$connection);});Check::same('pending',$x->inspect()['status']);
});
// A final budget expiry rolls back the new account, encrypted notice, queue rows and ledger changes.
budgetCase(static function(ManagedEnvironment $e,EntryEnvironment $x,$sdk,array $services,$connection,$state,$request,$authority):void{
    $policy=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,1);$budgets=new SoSecurity\Account\RequestBudgets(new SoSecurity\Storage\FileStore($e->directory.'/public-budget','expiring-final',$e->clock),'managed-test',str_repeat('b',32),array_fill_keys(['site','source','target','subject'],$policy),$e->clock);
    $s=budgetRegistration($e,$x,$services,$connection,$request,$authority,$budgets);$before=budgetTables($x);$root=$x->inspect();$state->authorityHook=static function(string $action,string $phase)use($e):bool{if($action==='request'&&$phase==='commit'){$e->clock->time+=2;}return true;};
    budgetReason('account.budget',static function()use($s):void{$s->request('expired-owner@example.test','owned-source');});$state->authorityHook=null;
    Check::same($before,budgetTables($x));Check::same('current',$x->inspect()['status']);Check::same($root['digest'],$x->inspect()['digest']);$s->request('usable-owner@example.test','owned-source');Check::same('current',$x->inspect()['status']);
});
// Recovery and lost-mailbox requests also reject a formal exhausted subject quota without file/proof work.
foreach(['recovery','mailbox'] as $kind){budgetCase(static function(ManagedEnvironment $e,EntryEnvironment $x,$sdk,array $services,$connection,$state,$request,$authority)use($kind):void{
    $large=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1000,60);$one=new SoSecurity\RateLimit\BudgetPolicy('fixed_window',1,60);
    $budgets=new SoSecurity\Account\RequestBudgets(new SoSecurity\Storage\FileStore($e->directory.'/public-budget','other-subject',$e->clock),'managed-test',str_repeat('b',32),['site'=>$large,'source'=>$large,'target'=>$large,'subject'=>$one],$e->clock);
    if($kind==='recovery'){$service=new SoSecurity\Account\Recovery($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->keys,$e->accounts,$services['notifications'],new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]),new SoSecurity\Password\PasswordPolicy(),$authority,$budgets,null,$e->clock,$authority,$authority,$sdk->managedSecondFactor(),null,$connection,$request);}
    else{$service=new SoSecurity\Account\MailboxRecovery($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->keys,$e->accounts,$services['notifications'],$authority,$budgets,$authority,null,$e->clock,$authority,$authority,$sdk->managedSecondFactor(),$connection,$request);}
    $call=static function()use($service,$kind):void{if($kind==='recovery'){$service->request('owned@example.test','owned-source');}else{$service->request('owned@example.test','target@example.test','owned-source');}};
    $call();$before=budgetTables($x);$digest=$x->inspect()['digest'];budgetReason('account.budget',$call);Check::same($before,budgetTables($x));Check::same('current',$x->inspect()['status']);Check::same($digest,$x->inspect()['digest']);
    $sdk->registration()->request('still-usable@example.test','owned-source');Check::same('current',$x->inspect()['status']);
});}
// A committed proof attempt is real progress; a later rollback must not certify the entire flow as unchanged.
budgetCase(static function(ManagedEnvironment $e,EntryEnvironment $x,$sdk,array $services,$connection,$state,$request,$authority):void{
    $deny=false;$budgets=static function(string $action,string $phase)use(&$deny):bool{return !($deny&&$phase==='final');};$s=budgetRegistration($e,$x,$services,$connection,$request,$authority,$budgets);
    $s->request('attempt-owner@example.test','owned-source');$delivery=null;
    foreach($e->observer->query("SELECT record_id FROM sosecurity_account_records WHERE kind='notice'")->fetchAll(PDO::FETCH_COLUMN) as $id){$candidate=$x->boundary->run('owned.budget.notice',static function()use($s,$id){return $s->notification($id);});if($candidate!==null&&$candidate->notice()->type()==='verify_registration'){$delivery=$candidate;break;}}
    Check::same(true,$delivery instanceof SoSecurity\Account\Delivery);$deny=true;
    budgetReason('account.completion_unknown',static function()use($s,$delivery):void{$s->confirm($delivery->selector(),$delivery->notice()->token(),'Owned new attempt password 49!','owned-source');});
    $flow=json_decode($e->observer->query("SELECT payload FROM sosecurity_account_records WHERE kind='register'")->fetchColumn(),true);Check::same(1,$flow['attempts']);Check::same('pending',$flow['state']);
    Check::same('pending',$e->observer->query("SELECT status FROM account_example WHERE address='attempt-owner@example.test'")->fetchColumn());Check::same('pending',$x->inspect()['status']);
});
// A budget callback which writes a covered file cannot claim an unchanged rollback.
budgetCase(static function(ManagedEnvironment $e,EntryEnvironment $x,$sdk,array $services,$connection,$state,$request,$authority):void{
    $budgets=static function(string $action,string $phase)use($x,$e):bool{if($phase==='final'){$x->store->transact(SoSecurity\Support\Guard::key('budget-test','tenant','changed'),static function()use($e){return new SoSecurity\Storage\Change(['owned'=>true],$e->clock->time+3600,null);});return false;}return true;};
    $s=budgetRegistration($e,$x,$services,$connection,$request,$authority,$budgets);budgetReason('account.completion_unknown',static function()use($s):void{$s->request('changed-file-owner@example.test','owned-source');});Check::same('pending',$x->inspect()['status']);
});
// An ordinary callback error with the same public reason is not rollback evidence.
budgetCase(static function(ManagedEnvironment $e,EntryEnvironment $x,$sdk,array $services,$connection,$state,$request,$authority):void{
    $s=$sdk->registration();$state->authorityHook=static function(string $action,string $phase):bool{if($action==='request'&&$phase==='before'){throw new SoSecurity\Exception\SecurityException('Owned false refusal.','account.budget');}return true;};
    budgetReason('account.completion_unknown',static function()use($s):void{$s->request('fake-reason-owner@example.test','owned-source');});Check::same('pending',$x->inspect()['status']);
});
// A failed rollback never supplies a receipt, even if test cleanup later restores the SQL connection.
budgetCase(static function(ManagedEnvironment $e,EntryEnvironment $x,$sdk,array $services,$connection,$state,$request,$authority):void{
    $budgets=static function(string $action,string $phase)use($e):bool{if($phase==='final'){$e->pdo->failRollback=true;return false;}return true;};$s=budgetRegistration($e,$x,$services,$connection,$request,$authority,$budgets);
    budgetReason('account.completion_unknown',static function()use($s):void{$s->request('failed-rollback-owner@example.test','owned-source');});$e->pdo->failRollback=false;$e->pdo->exec('ROLLBACK');Check::same('pending',$x->inspect()['status']);
});
echo 'PASS confirmed no-effect lifecycle budget refusals: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; formal subject/final denial stays usable, exact rollback/context/source required, replay/file changes/callback errors/rollback failures retain unknown',PHP_EOL;
