<?php
declare(strict_types=1);
require __DIR__.'/retirement-support.php';
require __DIR__.'/complete-backup-support.php';
foreach(['role','disabled','expired','selection','budget','repaired','lost-close','after-close-revoke','pending'] as $mode){
    retirementCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control)use($mode):void{
        $healthy=completeBackup($x);$token=$op->login()->credential()->token();
        if($mode==='pending'){
            retirementPending($x);$before=$x->inspect();witnessReason('account.stale_state',static function()use($x,$control,$token):void{$x->witness->staleReview($control,'user',$token,'witnessBudget');});Check::same($before,$x->inspect());return;
        }
        $x->e->pdo->exec("UPDATE account_example SET roles='[\"stale-refusal\"]' WHERE scope='tenant' AND subject='user'");$review=$x->witness->staleReview($control,'user',$token,'witnessBudget');list($token,$grant)=retirementApproval($op,$control,$review,$token);$before=$x->inspect();$snapshot=$x->source->digest();$budget='witnessBudget';$expected='account.retirement_changed';$closed=false;
        $revoke=static function()use($op):void{$op->boundary->run('owned.stale.revoke-operator',static function()use($op):void{$op->e->pdo->exec("UPDATE account_example SET roles='[\"member\"]'");});};
        if($mode==='role'){$revoke();$expected='account.state_denied';}
        elseif($mode==='disabled'){$op->boundary->run('owned.stale.disable-operator',static function()use($op):void{$op->e->pdo->exec("UPDATE account_example SET status='disabled'");});$expected='account.state_denied';}
        elseif($mode==='expired'){$op->e->clock->time=$review->metadata()['expires'];$expected='account.retirement_expired';}
        elseif($mode==='selection'){$v=$review->metadata();$v['seal']=str_repeat($v['seal'][0]==='a'?'b':'a',64);$review=new SoSecurity\Account\StateRetirementReview($v);}
        elseif($mode==='budget'){$budget=static function(string $phase):bool{return $phase!=='final';};$expected='account.witness_budget';}
        elseif($mode==='repaired'){completeRestore($x,$healthy);$snapshot=$healthy['digest'];}
        elseif($mode==='lost-close'){$x->persistHook=static function():bool{return false;};$expected='account.completion_unknown';$closed=true;}
        elseif($mode==='after-close-revoke'){$x->persistHook=static function()use($revoke):bool{$revoke();return true;};$expected='account.completion_unknown';$closed=true;}
        try{witnessReason($expected,static function()use($x,$review,$control,$token,$grant,$budget):void{$x->witness->retireStale($review,$control,'user',$token,$grant,$budget);});}finally{$x->persistHook=null;}
        $after=$x->inspect();Check::same($closed?'closed':'current',$after['status']);Check::same($before['revision'],$after['revision']);Check::same($before['digest'],$after['digest']);Check::same($before['operation'],$after['operation']);Check::same($snapshot,$x->source->digest());if(!$closed){Check::same($before,$after);}
        if($closed){$calls=0;witnessReason('account.witness_pending',static function()use($x,&$calls):void{$x->boundary->run('owned.closed-stale.refuse',static function()use(&$calls):void{++$calls;});});Check::same(0,$calls);}
        elseif($mode!=='repaired'){$calls=0;witnessReason('account.witness_stale',static function()use($x,&$calls):void{$x->boundary->run('owned.current-stale.refuse',static function()use(&$calls):void{++$calls;});});Check::same(0,$calls);}
    });
}
echo 'PASS stale retirement refusals: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; revoked/disabled/expired operator, invalid selection/budget, repaired data, unknown closure, separate pending route; no current-state adoption',PHP_EOL;
