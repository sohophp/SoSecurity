<?php
declare(strict_types=1);
require __DIR__.'/entry-support.php';
function permissionPolicy(EntryEnvironment $x,?SoSecurity\Auth\SessionRegistry $registry=null):SoSecurity\Account\StateAccountPolicy
{
    $fields=['scope','subject','credential_version','status','verified','mfa_required','roles','password'];$e=$x->e;
    return new SoSecurity\Account\StateAccountPolicy($x->witness,$x->source,$x->sources['sql'],$x->sources['files'],'complete-sql','sessions-and-factors','account_example',array_combine($fields,$fields),$x->store,$registry??$x->sessions,$x->factorAdapter,$e->factors,'managed-test','tenant',str_repeat('e',64),$e->keys);
}
function permissionRequest(string $token,array $roles=[],string $target='user',bool $self=true):SoSecurity\Account\StatePermission{return new SoSecurity\Account\StatePermission('account.review','tenant','user',$target,$token,$roles,2,300,true,$self);}
function permissionState(EntryEnvironment $x):array
{
    $state=['files'=>entryFiles($x),'witness'=>$x->inspect()];
    foreach(['account_example','sosecurity_account_roots','sosecurity_account_records','sosecurity_outbox_roots','sosecurity_outbox_records','factor_migration_audit','entry_worker_audit'] as $name){$state[$name]=$x->e->observer->query('SELECT * FROM '.$name)->fetchAll(PDO::FETCH_ASSOC);}return $state;
}
function permissionRun(EntryEnvironment $x,SoSecurity\Account\StateAccountPolicy $policy,SoSecurity\Account\StatePermission $r,callable $work){return $x->boundary->authorized('account.review','tenant',$r->definition()['target'],$policy,$r,$work);}
function permissionRefuse(EntryEnvironment $x,SoSecurity\Account\StateAccountPolicy $policy,SoSecurity\Account\StatePermission $r):void
{
    $before=permissionState($x);$lookups=$x->lookups;$reads=$x->e->reads;$calls=0;$persists=0;$x->persistHook=static function()use(&$persists):bool{++$persists;return true;};$error=null;
    try{permissionRun($x,$policy,$r,static function()use(&$calls):void{++$calls;});}catch(Throwable $caught){$error=$caught;}finally{$x->persistHook=null;}
    Check::same(true,$error instanceof SoSecurity\Exception\SecurityException);Check::same('account.state_denied',$error->reason());Check::same(0,$calls);Check::same(0,$persists);Check::same($before,permissionState($x));Check::same($lookups,$x->lookups);Check::same($reads,$x->e->reads);Check::same(false,$x->boundary->active());
}
