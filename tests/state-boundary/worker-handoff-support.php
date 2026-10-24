<?php
declare(strict_types=1);
require __DIR__.'/recovery-audit-support.php';
function workerHandoffSetup(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,?callable $persist=null):array
{
    $old=entryPromote($x);list($w,$token)=containmentStage($x,$op,$control);$boundary=new SoSecurity\Account\StateBoundary($w,static function():bool{return true;});$dir=$x->e->directory.'/entry-next-fence';
    $next=new SoSecurity\Account\LocalEpochFence($dir,'managed-test','tenant',str_repeat('e',64),$x->e->keys,static function($h)use($dir,$persist):bool{witnessPersist($h,$dir);return $persist===null||$persist($h)===true;},5000,$boundary);$receipts=[];$recovery=workerService($x->e,$old,$receipts);
    $args=[$w,$x->source,$x->sources['sql'],'complete-sql',$old,$x->boundary,$next,$boundary,$recovery,$x->e->factors,'managed-test','tenant',str_repeat('e',64),$x->e->keys,new SoSecurity\Account\Policy(),$x->e->clock];
    $plan=SoSecurity\Account\StateWorkerHandoff::prepare(...array_merge($args,['witnessBudget']));return [$w,$token,$plan,$args,$old,$next,$boundary];
}
function workerHandoffApproval(EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,SoSecurity\Account\StateWorkerReview $review,string $token):array
{
    $c=$control->beginWorkers($review,'user',$token);Check::same(null,$control->confirmWorkers($review,'user',$token,$c->token()));$token=retirementReauthenticate($op,$token);$g=$control->confirmWorkers($review,'user',$token,$c->token());Check::same(true,$g instanceof SoSecurity\Operation\Grant);return [$token,$g->token()];
}
