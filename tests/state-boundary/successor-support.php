<?php
declare(strict_types=1);
require __DIR__.'/retirement-support.php';
function successorClosed(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):string
{
    retirementPending($x);$token=$op->login()->credential()->token();$review=$x->witness->retirementReview($control,'user',$token,'witnessBudget');list($token,$grant)=retirementApproval($op,$control,$review,$token);$x->witness->retirePending($review,$control,'user',$token,$grant,'witnessBudget');return $token;
}
function successorApproval(EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,SoSecurity\Account\StateSuccessorReview $review,string $token):array
{
    $confirmation=$control->beginSuccessor($review,'user',$token);Check::same(null,$control->confirmSuccessor($review,'user',$token,$confirmation->token()));$token=retirementReauthenticate($op,$token);$grant=$control->confirmSuccessor($review,'user',$token,$confirmation->token());Check::same(true,$grant instanceof SoSecurity\Operation\Grant);return [$token,$grant->token()];
}
