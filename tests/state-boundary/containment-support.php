<?php
declare(strict_types=1);
require __DIR__.'/successor-support.php';
function containmentPlan(EntryEnvironment $x,SoSecurity\Account\LocalStateWitness $w,array $subjects=['user']):SoSecurity\Account\StateAccountContainment
{
    $fields=['scope','subject','credential_version','address_version','address','password','status','verified','mfa_required','roles'];return new SoSecurity\Account\StateAccountContainment($w,$x->source,$x->sources['sql'],'complete-sql','account_example',array_combine($fields,$fields),'tenant',$subjects);
}
function containmentStage(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):array
{
    $token=successorClosed($x,$op,$control);$review=$x->witness->successorReview($control,'user',$token,'witnessBudget');$next=$x->witness->successorReader($review);list($token,$grant)=successorApproval($op,$control,$review,$token);$x->witness->stageSuccessor($review,$next,$control,'user',$token,$grant,'witnessBudget');return [$next,$token];
}
function containmentApproval(EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,SoSecurity\Account\StateContainmentReview $review,string $token):array
{
    $c=$control->beginContainment($review,'user',$token);Check::same(null,$control->confirmContainment($review,'user',$token,$c->token()));$token=retirementReauthenticate($op,$token);$g=$control->confirmContainment($review,'user',$token,$c->token());Check::same(true,$g instanceof SoSecurity\Operation\Grant);return [$token,$g->token()];
}
