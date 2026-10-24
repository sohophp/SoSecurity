<?php
declare(strict_types=1);
require __DIR__.'/retirement-support.php';
$mode=$argv[2]??'role';
retirementCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control)use($mode):void{
    retirementPending($x);$reviewToken=$op->login()->credential()->token();$review=$x->witness->retirementReview($control,'user',$reviewToken,'witnessBudget');$approvalReview=$mode==='wrong-review'?$x->witness->retirementReview($control,'user',$reviewToken,'witnessBudget'):$review;list($token,$grant)=retirementApproval($op,$control,$approvalReview,$reviewToken);$before=$x->inspect();$snapshot=$x->source->digest();$budget='witnessBudget';$expected='account.retirement_changed';$closed=false;
    $revoke=static function()use($op):void{$op->boundary->run('owned.revoke.operator',static function()use($op):void{$op->e->pdo->exec("UPDATE account_example SET roles='[\"member\"]'");});};
    if($mode==='role'){$revoke();$expected='account.state_denied';}
    elseif($mode==='disabled'){$op->boundary->run('owned.disable.operator',static function()use($op):void{$op->e->pdo->exec("UPDATE account_example SET status='disabled'");});$expected='account.state_denied';}
    elseif($mode==='expired'){$op->e->clock->time=$review->metadata()['expires'];$expected='account.retirement_expired';}
    elseif($mode==='state-changed'){$x->e->pdo->exec("UPDATE entry_worker_audit SET context_digest='".str_repeat('f',64)."'");$snapshot=$x->source->digest();}
    elseif($mode==='selection'){$v=$review->metadata();$v['operation']=str_repeat('f',64);$review=new SoSecurity\Account\StateRetirementReview($v);}
    elseif($mode==='wrong-review'){$expected='account.retirement_denied';}
    elseif($mode==='budget'){$budget=static function(string $phase):bool{return $phase!=='final';};$expected='account.witness_budget';}
    elseif($mode==='final-revoke'){$budget=static function(string $phase)use($revoke):bool{if($phase==='final'){$revoke();}return true;};$expected='account.state_denied';}
    elseif($mode==='lost-close'){$x->persistHook=static function():bool{return false;};$expected='account.completion_unknown';$closed=true;}
    elseif($mode==='after-close-revoke'){$x->persistHook=static function()use($revoke):bool{$revoke();return true;};$expected='account.completion_unknown';$closed=true;}
    else{throw new RuntimeException('Unknown owned test mode');}
    try{witnessReason($expected,static function()use($x,$review,$control,$token,$grant,$budget):void{$x->witness->retirePending($review,$control,'user',$token,$grant,$budget);});}finally{$x->persistHook=null;}
    $after=$x->inspect();Check::same($closed?'closed':'pending',$after['status']);Check::same($before['operation'],$after['operation']);Check::same($before['digest'],$after['digest']);Check::same($before['revision'],$after['revision']);Check::same($snapshot,$x->source->digest());
    if(!$closed){Check::same($before,$after);}else{Check::same(true,isset($after['closure']));}
    $calls=0;witnessReason('account.witness_pending',static function()use($x,&$calls):void{$x->boundary->run('owned.no.replay',static function()use(&$calls):void{++$calls;});});Check::same(0,$calls);
});
echo 'PASS independent retirement refusal '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION."; exact preview/current operator/final budget, preserve blocked old authority and unknown SQL\n";
