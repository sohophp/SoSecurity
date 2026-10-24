<?php
declare(strict_types=1);
require __DIR__.'/containment-support.php';
function accountResolutionApproval(EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,SoSecurity\Account\StateAccountResolutionReview $review,string $token):array
{
    $c=$control->beginAccountResolution($review,'user',$token);Check::same(null,$control->confirmAccountResolution($review,'user',$token,$c->token()));$token=retirementReauthenticate($op,$token);$g=$control->confirmAccountResolution($review,'user',$token,$c->token());Check::same(true,$g instanceof SoSecurity\Operation\Grant);return [$token,$g->token()];
}
function accountResolutionReload(EntryEnvironment $x,SoSecurity\Account\LocalStateWitness $old):SoSecurity\Account\LocalStateWitness
{
    $e=$x->e;return new SoSecurity\Account\LocalStateWitness($e->pdo,$e->directory.'/independent-witness','managed-test','tenant',str_repeat('e',64),$e->keys,$x->source,static function($h)use($e):bool{return witnessPersist($h,$e->directory.'/independent-witness');},30000,3,$old->generation());
}
function accountResolutionPending(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,string $mode='after',array $subjects=['user']):array
{
    list($next,$token)=containmentStage($x,$op,$control);$accounts=containmentPlan($x,$next,$subjects);$review=$next->containmentReview($accounts,$control,'user',$token,'witnessBudget');list($token,$grant)=containmentApproval($op,$control,$review,$token);$old=$x->e->pdo->query("SELECT * FROM account_example WHERE scope='tenant' AND subject='user'")->fetch(PDO::FETCH_ASSOC);
    if($mode==='before'){$x->persistHook=static function():bool{return false;};}
    $finals=0;$budget=static function(string $phase)use(&$finals):bool{return $phase!=='final'||++$finals!==2;};
    witnessReason('account.completion_unknown',static function()use($next,$review,$accounts,$control,$token,$grant,$budget):void{$next->containAccounts($review,$accounts,$control,'user',$token,$grant,$budget);});$x->persistHook=null;$pending=$next->inspect('witnessBudget');Check::same('pending',$pending['remediation']['phase']);Check::same('contain_accounts',$pending['remediation']['review']['purpose']);Check::same(true,SoSecurity\Account\StateAccountManifest::valid($pending['remediation']['manifest']));
    $current=$x->e->pdo->query("SELECT * FROM account_example WHERE scope='tenant' AND subject='user'")->fetch(PDO::FETCH_ASSOC);Check::same($mode==='before',$old===$current);
    foreach(['password','address','roles'] as $key){if(is_string($old[$key])&&strlen($old[$key])>4){Check::same(false,strpos(json_encode($pending['remediation']['manifest']),$old[$key])!==false);}}
    return [$next,$token,$review,$grant,$pending,$old];
}
