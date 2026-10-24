<?php
declare(strict_types=1);
require __DIR__.'/containment-support.php';
require __DIR__.'/inventory-support.php';
function factorContainmentCase(callable $work,int $milliseconds=30000):void
{
    retirementCase($work,static function(ManagedEnvironment $e)use($milliseconds):EntryEnvironment{$services=inventoryServices($e);$services[3]->begin('user','owned-physical-pending');$x=new EntryEnvironment($e,false,2,$services,$milliseconds);entryPromote($x);return $x;});
}
function factorContainmentSetup(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):array
{
    list($next,$token)=containmentStage($x,$op,$control);$plan=containmentPlan($x,$next);$review=$next->containmentReview($plan,$control,'user',$token,'witnessBudget');list($token,$grant)=containmentApproval($op,$control,$review,$token);$next->containAccounts($review,$plan,$control,'user',$token,$grant,'witnessBudget');$e=$x->e;$s=$x->inventoryServices;
    $inventory=new SoSecurity\Account\StateFactorInventory($next,$x->source,$x->sources['sql'],$x->sources['files'],'complete-sql','sessions-and-factors',$e->registry,$e->factors,$s[1],$s[2],$s[3],$s[4],'managed-test','tenant',str_repeat('e',64),$e->keys,$e->clock);return [$next,$token,$inventory];
}
function factorContainmentPlan(EntryEnvironment $x,SoSecurity\Account\LocalStateWitness $w,SoSecurity\Account\StateFactorInventory $inventory,array $positions,?callable $persist=null,string $mode='managed'):SoSecurity\Account\StateFactorContainment
{
    $e=$x->e;return new SoSecurity\Account\StateFactorContainment($w,$inventory,$x->source,$x->sources['files'],'sessions-and-factors',$e->factors,'managed-test','tenant',str_repeat('e',64),$e->keys,'user',$positions,$persist??static function($h)use($e):bool{return witnessPersist($h,$e->directory.'/factors');},$mode);
}
function factorContainmentApproval(EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,SoSecurity\Account\StateFactorContainmentReview $review,string $token):array
{
    $c=$control->beginFactors($review,'user',$token);Check::same(null,$control->confirmFactors($review,'user',$token,$c->token()));$token=retirementReauthenticate($op,$token);$g=$control->confirmFactors($review,'user',$token,$c->token());Check::same(true,$g instanceof SoSecurity\Operation\Grant);return [$token,$g->token()];
}
function factorRaw(EntryEnvironment $x,string $file):?string{$path=$x->e->directory.'/factors/'.$file;return is_file($path)?file_get_contents($path):null;}
