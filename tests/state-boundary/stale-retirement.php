<?php
declare(strict_types=1);
require __DIR__.'/containment-support.php';
require __DIR__.'/complete-backup-support.php';

// Restore the entire old host SQL and authentication file domain after an actual session revocation.
retirementCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):void{
    $login=$x->login();$oldToken=$login->credential()->token();$backup=completeBackup($x);$x->sessions->revokeAll('tenant','user');$trusted=$x->inspect();
    completeRestore($x,$backup);Check::same('current',$x->inspect()['status']);$lookups=$x->lookups;witnessReason('account.witness_stale',static function()use($x,$oldToken):void{$x->sessions->verify('tenant','user',$oldToken,2);});Check::same($lookups,$x->lookups);
    $token=$op->login()->credential()->token();$review=$x->witness->staleReview($control,'user',$token,'witnessBudget');$v=$review->metadata();Check::same('retire_stale',$v['purpose']);Check::same('state.retire_stale',$review->intent('tenant')->action());Check::same($trusted['digest'],$v['before']);Check::same($backup['digest'],$v['observed']);Check::same(false,$v['before']===$v['observed']);Check::same($trusted,$x->inspect());
    // Both a different purpose and an otherwise valid wrong-action one-use grant are refused.
    $wrong=$v;$wrong['purpose']='retire_unknown';$wrongReview=new SoSecurity\Account\StateRetirementReview($wrong);Check::same('state.retire_unknown',$wrongReview->intent('tenant')->action());
    list($token,$wrongGrant)=retirementApproval($op,$control,$wrongReview,$token);
    witnessReason('account.retirement_changed',static function()use($x,$wrongReview,$control,$token,$wrongGrant):void{$x->witness->retireStale($wrongReview,$control,'user',$token,$wrongGrant,'witnessBudget');});
    witnessReason('account.retirement_changed',static function()use($x,$review,$control,$token,$wrongGrant):void{$x->witness->retirePending($review,$control,'user',$token,$wrongGrant,'witnessBudget');});
    witnessReason('account.retirement_denied',static function()use($x,$review,$control,$token,$wrongGrant):void{$x->witness->retireStale($review,$control,'user',$token,$wrongGrant,'witnessBudget');});Check::same($trusted,$x->inspect());
    // A changed observed source cannot be closed with the earlier approval.
    list($token,$grant)=retirementApproval($op,$control,$review,$token);$x->e->pdo->exec("UPDATE account_example SET roles='[\"changed-after-review\"]' WHERE scope='tenant' AND subject='user'");
    witnessReason('account.retirement_changed',static function()use($x,$review,$control,$token,$grant):void{$x->witness->retireStale($review,$control,'user',$token,$grant,'witnessBudget');});Check::same($trusted,$x->inspect());completeRestore($x,$backup);
    $receipt=$x->witness->retireStale($review,$control,'user',$token,$grant,'witnessBudget');Check::same('closed',$receipt['status']);Check::same($trusted['digest'],$receipt['digest']);Check::same($trusted['operation'],$receipt['operation']);Check::same($v,$receipt['closure']['review']);Check::same($backup['digest'],$x->source->digest());
    witnessReason('account.retirement_changed',static function()use($x,$review,$control,$token,$grant):void{$x->witness->retireStale($review,$control,'user',$token,$grant,'witnessBudget');});
    $calls=0;witnessReason('account.witness_pending',static function()use($x,&$calls):void{$x->boundary->run('owned.stale.never-reopen',static function()use(&$calls):void{++$calls;});});Check::same(0,$calls);
    // The already existing independently approved successor handoff accepts this separately closed cause.
    $successor=$x->witness->successorReview($control,'user',$token,'witnessBudget');$next=$x->witness->successorReader($successor);list($token,$grant)=successorApproval($op,$control,$successor,$token);$staged=$x->witness->stageSuccessor($successor,$next,$control,'user',$token,$grant,'witnessBudget');
    Check::same('quarantined',$staged['status']);Check::same($trusted['digest'],$staged['digest']);Check::same($trusted['operation'],$staged['successor']['predecessor_operation']);Check::same($backup['digest'],$x->source->digest());
});

// The very first checkpoint can also become stale without inventing an unknown operation or revision.
retirementCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):void{
    $before=$x->inspect();Check::same(1,$before['revision']);$token=$op->login()->credential()->token();
    witnessReason('account.stale_state',static function()use($x,$control,$token):void{$x->witness->staleReview($control,'user',$token,'witnessBudget');});Check::same($before,$x->inspect());
    $x->e->pdo->exec("UPDATE account_example SET roles='[\"stale-initial\"]' WHERE scope='tenant' AND subject='user'");$review=$x->witness->staleReview($control,'user',$token,'witnessBudget');list($token,$grant)=retirementApproval($op,$control,$review,$token);
    $closed=$x->witness->retireStale($review,$control,'user',$token,$grant,'witnessBudget');Check::same('closed',$closed['status']);Check::same(1,$closed['revision']);Check::same('initial',$closed['intent']['kind']);
    $review=$x->witness->successorReview($control,'user',$token,'witnessBudget');$next=$x->witness->successorReader($review);list($token,$grant)=successorApproval($op,$control,$review,$token);$staged=$x->witness->stageSuccessor($review,$next,$control,'user',$token,$grant,'witnessBudget');Check::same(2,$staged['revision']);
    $plan=containmentPlan($x,$next);$review=$next->containmentReview($plan,$control,'user',$token,'witnessBudget');Check::same(2,$review->metadata()['revision']);list($token,$grant)=containmentApproval($op,$control,$review,$token);$contained=$next->containAccounts($review,$plan,$control,'user',$token,$grant,'witnessBudget');
    Check::same('quarantined',$contained['status']);Check::same('complete',$contained['remediation']['phase']);Check::same('disabled',$x->e->observer->query("SELECT status FROM account_example WHERE subject='user' AND scope='tenant'")->fetchColumn());
    $calls=0;witnessReason('account.witness_pending',static function()use($next,&$calls):void{$next->work(static function()use(&$calls):void{++$calls;},'witnessBudget',$next->internalOperation('owned.still-quarantined'));});Check::same(0,$calls);
});
echo 'PASS independent stale-current retirement: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; actual seven-table/file restore, separate purpose/approval, exact observed state, first checkpoint, successor quarantine and fixed containment; no business reactivation',PHP_EOL;
