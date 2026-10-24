<?php
declare(strict_types=1);
require __DIR__.'/retirement-support.php';
retirementCase(static function(EntryEnvironment $x,EntryEnvironment $operator,SoSecurity\Account\StateRetirementControl $control):void{
    retirementPending($x);$pending=$x->inspect();$snapshot=$x->source->digest();$files=entryFiles($x);$reviewToken=$operator->login()->credential()->token();$review=$x->witness->retirementReview($control,'user',$reviewToken,'witnessBudget');$v=$review->metadata();
    Check::same('retire_unknown',$v['purpose']);Check::same($pending['operation'],$v['operation']);Check::same($pending['revision'],$v['revision']);Check::same($snapshot,$v['observed']);Check::same($pending['digest'],$v['before']);Check::same($pending['intent_digest'],$v['intent']);
    list($token,$grant)=retirementApproval($operator,$control,$review,$reviewToken);$receipt=$x->witness->retirePending($review,$control,'user',$token,$grant,'witnessBudget');
    Check::same('closed',$receipt['status']);Check::same($pending['digest'],$receipt['digest']);Check::same($pending['operation'],$receipt['operation']);Check::same($pending['intent'],$receipt['intent']);Check::same($pending['revision'],$receipt['revision']);Check::same($v,$receipt['closure']['review']);Check::same($control->binding(),$receipt['closure']['control']);
    Check::same($snapshot,$x->source->digest());Check::same($files,entryFiles($x));Check::same(1,(int)$x->e->observer->query('SELECT COUNT(*) FROM entry_worker_audit')->fetchColumn());
    $calls=0;witnessReason('account.witness_pending',static function()use($x,&$calls):void{$x->boundary->run('owned.replay',static function()use(&$calls):void{++$calls;});});Check::same(0,$calls);
    witnessReason('account.retirement_changed',static function()use($x,$review,$control,$token,$grant):void{$x->witness->retirePending($review,$control,'user',$token,$grant,'witnessBudget');});Check::same($receipt,$x->inspect());
    $queries=$x->e->pdo->queries;$operatorQueries=$operator->e->pdo->queries;
    foreach([[str_repeat('x',257),$token,$grant],['user','invalid',$grant],['user',$token,str_repeat('x',1025)]] as $bad){Check::throws(SoSecurity\Exception\ValidationException::class,static function()use($x,$review,$control,$bad):void{$x->witness->retirePending($review,$control,$bad[0],$bad[1],$bad[2],'witnessBudget');});}
    Check::same($queries,$x->e->pdo->queries);Check::same($operatorQueries,$operator->e->pdo->queries);
    foreach([print_r($control,true),var_export($control,true),json_encode($control),json_encode($receipt)] as $dump){Check::same(false,strpos($dump,$token)!==false);Check::same(false,strpos($dump,$grant)!==false);}
});
echo 'PASS independently approved unknown retirement: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; actual independent password/TOTP/reauth/one-use grant, permanent close, original unknown and actual SQL retained, no database adoption or replay\n";
