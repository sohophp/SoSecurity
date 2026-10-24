<?php
declare(strict_types=1);
require __DIR__.'/factor-containment-support.php';
function factorResolutionPlan(EntryEnvironment $x,SoSecurity\Account\LocalStateWitness $w,array $manifest,?callable $persist=null):SoSecurity\Account\StateFactorResolution
{
    $e=$x->e;return new SoSecurity\Account\StateFactorResolution($w,$x->source,$x->sources['files'],'sessions-and-factors',$e->factors,'managed-test','tenant',str_repeat('e',64),$e->keys,$manifest,$persist??static function($h)use($e):bool{return witnessPersist($h,$e->directory.'/factors');});
}
function factorResolutionApproval(EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,SoSecurity\Account\StateFactorResolutionReview $review,string $token):array
{
    $c=$control->beginResolution($review,'user',$token);Check::same(null,$control->confirmResolution($review,'user',$token,$c->token()));$token=retirementReauthenticate($op,$token);$g=$control->confirmResolution($review,'user',$token,$c->token());Check::same(true,$g instanceof SoSecurity\Operation\Grant);return [$token,$g->token()];
}
function factorResolutionReload(EntryEnvironment $x,SoSecurity\Account\LocalStateWitness $old):SoSecurity\Account\LocalStateWitness
{
    $e=$x->e;return new SoSecurity\Account\LocalStateWitness($e->pdo,$e->directory.'/independent-witness','managed-test','tenant',str_repeat('e',64),$e->keys,$x->source,static function($h)use($e):bool{return witnessPersist($h,$e->directory.'/independent-witness');},30000,3,$old->generation());
}
