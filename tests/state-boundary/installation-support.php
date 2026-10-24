<?php
declare(strict_types=1);
require __DIR__.'/credentials-support.php';
function installationArgs(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\LocalStateWitness $next,SoSecurity\Account\StateAccountContainment $accounts,?callable $persist=null):array
{
    return [$next,$x->source,$x->sources['sql'],$x->sources['files'],'complete-sql','sessions-and-factors',$accounts,credentialService($x,$op),$x->e->registry,$x->e->factors,$x->e->keys,'managed-test','tenant',str_repeat('e',64),$x->e->clock,$persist??static function($h)use($x):bool{return witnessPersist($h,$x->e->directory.'/factors');}];
}
function installationSetup(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,?callable $persist=null,bool $withSessions=false):array
{
    permissionPolicy($x)->accountConnection($x->boundary,$x->e->accounts,new SoSecurity\Account\Policy(),'address','address_version');
    list($next,$accounts,$manifest)=credentialSetup($x,$op,$control);$service=credentialService($x,$op);$en=$service->prepare($next,$accounts,$manifest,'user','Owned installed user','witnessBudget');Check::same(true,$service->confirm($next,$accounts,$manifest,'user',$en->selector(),$en->password(),credentialCode($en,$x),'witnessBudget'));
    $args=installationArgs($x,$op,$next,$accounts,$persist);$plan=SoSecurity\Account\StateCredentialInstallation::prepare(...array_merge($args,array_merge([$manifest,'user',$en->selector(),'witnessBudget'],$withSessions?[$x->sessions,$x->store]:[])));return [$next,$accounts,$plan,$en];
}
/** Native reference from the authenticated prior coordinate; no duplicate caller-selected path. */
function installationRetirementReference(EntryEnvironment $x,array $manifest):array
{
    $profile=$x->e->factors->statePolicy('managed-test','tenant',str_repeat('e',64),$x->e->keys);return $x->e->factors->stateReference($manifest['prior']['scope'],$manifest['prior']['subject'],$profile['context']);
}
function installationApproval(EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,SoSecurity\Account\StateCredentialInstallReview $review,string $token):array
{
    $c=$control->beginInstallation($review,'user',$token);Check::same(null,$control->confirmInstallation($review,'user',$token,$c->token()));$token=retirementReauthenticate($op,$token);$g=$control->confirmInstallation($review,'user',$token,$c->token());Check::same(true,$g instanceof SoSecurity\Operation\Grant);return [$token,$g->token()];
}
function installedAssertions(EntryEnvironment $x,SoSecurity\Account\LocalStateWitness $next,SoSecurity\Account\StateCredentialInstallation $plan,SoSecurity\Account\StateCredentialEnrollment $en,array $original,array $receipt):void
{
    Check::same('quarantined',$receipt['status']);Check::same('complete',$receipt['remediation']['phase']);Check::same($original['digest'],$receipt['digest']);Check::same($plan->manifest(),$receipt['remediation']['manifest']);$row=$x->e->row();Check::same('disabled',$row['status']);Check::same(0,(int)$row['verified']);Check::same('[]',$row['roles']);Check::same(true,(new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]))->verify($en->password(),$row['password']));Check::same(false,(new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]))->verify($x->e->password,$row['password']));
    $m=$plan->manifest();$raw=file_get_contents($x->e->directory.'/factors/'.$m['factor']['file']);Check::same($m['factor']['after'],hash('sha256',$raw));$frame=json_decode($raw,true)['value'];Check::same($en->enrollment()->id(),$frame['payload']['enabled']['id']);Check::same(null,$frame['payload']['pending']);Check::same([],$frame['payload']['recovery']);
    if(isset($m['retirement'])){Check::same($m['retirement']['after'],file_get_contents($x->e->directory.'/factors/'.installationRetirementReference($x,$m)['file']));Check::same(null,json_decode($m['retirement']['after'],true)['value']['payload']);}
    $dump=json_encode($receipt);Check::same(false,strpos($dump,$en->password())!==false);Check::same(false,strpos($dump,$en->selector())!==false);Check::same(false,strpos($dump,$row['password'])!==false);$called=0;witnessReason('account.witness_pending',static function()use($next,&$called):void{$next->work(static function()use(&$called):void{++$called;},'witnessBudget',$next->internalOperation('owned.installed.not.enabled'));});Check::same(0,$called);
}
