<?php
declare(strict_types=1);
require __DIR__.'/successor-support.php';
$mode=$argv[2]??'expired';
retirementCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control)use($mode):void{
    $token=successorClosed($x,$op,$control);$closed=$x->inspect();$files=entryFiles($x);$snapshot=$x->source->digest();$path=glob($x->e->directory.'/independent-witness/*.witness')[0];$before=file_get_contents($path);
    if($mode==='role-preview'){
        $op->boundary->run('owned.revoke',static function()use($op):void{$op->e->pdo->exec("UPDATE account_example SET roles='[]'");});
        witnessReason('account.state_denied',static function()use($x,$control,$token):void{$x->witness->successorReview($control,'user',$token,'witnessBudget');});Check::same($before,file_get_contents($path));return;
    }
    $review=$x->witness->successorReview($control,'user',$token,'witnessBudget');$next=$x->witness->successorReader($review);list($token,$grant)=successorApproval($op,$control,$review,$token);$budget='witnessBudget';$expected='account.successor_changed';$written=false;
    if($mode==='expired'){$op->e->clock->time+=120;$expected='account.successor_expired';}
    elseif($mode==='state-changed'){$x->e->pdo->exec("UPDATE entry_worker_audit SET context_digest='".str_repeat('b',64)."'");}
    elseif($mode==='wrong-grant'){$review=$x->witness->successorReview($control,'user',$token,'witnessBudget');$next=$x->witness->successorReader($review);$expected='account.successor_denied';}
    elseif($mode==='final-revoke'){$expected='account.state_denied';$budget=static function(string $phase)use($op):bool{if($phase==='final'){$op->boundary->run('owned.revoke',static function()use($op):void{$op->e->pdo->exec("UPDATE account_example SET roles='[]'");});}return true;};}
    elseif($mode==='lost-stage'){$written=true;$expected='account.completion_unknown';$x->persistHook=static function():bool{return false;};}
    elseif($mode==='after-stage-revoke'){$written=true;$expected='account.completion_unknown';$x->persistHook=static function()use($op):bool{$op->boundary->run('owned.revoke',static function()use($op):void{$op->e->pdo->exec("UPDATE account_example SET roles='[]'");});return true;};}
    else{throw new RuntimeException('Unknown successor refusal mode');}
    witnessReason($expected,static function()use($x,$review,$next,$control,$token,$grant,$budget):void{$x->witness->stageSuccessor($review,$next,$control,'user',$token,$grant,$budget);});$x->persistHook=null;
    if($written){Check::same('quarantined',$next->inspect('witnessBudget')['status']);witnessReason('account.witness_corrupt',static function()use($x):void{$x->inspect();});$calls=0;witnessReason('account.witness_pending',static function()use($next,&$calls):void{$next->work(static function()use(&$calls):void{++$calls;},'witnessBudget',$next->internalOperation('owned.forbidden'));});Check::same(0,$calls);}
    else{Check::same($before,file_get_contents($path));Check::same($closed,$x->inspect());}
    Check::same($files,entryFiles($x));if($mode!=='state-changed'){Check::same($snapshot,$x->source->digest());}Check::same(1,(int)$x->e->observer->query('SELECT COUNT(*) FROM entry_worker_audit')->fetchColumn());
});
echo 'PASS successor refusal '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
