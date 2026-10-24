<?php
declare(strict_types=1);
require __DIR__.'/recovery-audit-support.php';
recoveryAuditCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,SoSecurity\Account\StateRecoveryAudit $audit):void{
    $token=successorClosed($x,$op,$control);$closed=$x->inspect();$review=$x->witness->successorReview($control,'user',$token,'witnessBudget');$next=$x->witness->successorReader($review);list($token,$grant)=successorApproval($op,$control,$review,$token);$dir=$x->e->directory.'/recovery-audit';
    // Unreferenced attacker data still consumes capacity. It cannot be silently pruned or adopted.
    for($i=0;$i<255;++$i){$path=$dir.'/'.hash('sha256','owned-unreferenced-capacity-'.$i).'.json';file_put_contents($path,'{}');chmod($path,0600);}
    $source=$x->source->digest();witnessReason('account.completion_unknown',static function()use($x,$review,$next,$control,$token,$grant):void{$x->witness->stageSuccessor($review,$next,$control,'user',$token,$grant,'witnessBudget');});Check::same($closed,$x->inspect());Check::same($source,$x->source->digest());Check::same(257,count(glob($dir.'/*.json')));Check::same(1,recoveryAuditCount($x->witness));
});
managedCase(static function(ManagedEnvironment $e):void{
    $x=new EntryEnvironment($e,false,2);$before=$x->inspect();$sql=$e->pdo->queries;$persist=static function():bool{return false;};
    $same=new SoSecurity\Account\StateRecoveryAudit($e->directory.'/independent-witness',$e->keys,$persist);Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($x,$e,$persist,$same):void{new SoSecurity\Account\LocalStateWitness($e->pdo,$e->directory.'/independent-witness','managed-test','tenant',str_repeat('e',64),$e->keys,$x->source,$persist,30000,2,null,$same);});Check::same($sql,$e->pdo->queries);
    $overlap=new SoSecurity\Account\StateRecoveryAudit($e->directory.'/factors',$e->keys,$persist);$bad=new SoSecurity\Account\LocalStateWitness($e->pdo,$e->directory.'/independent-witness','managed-test','tenant',str_repeat('e',64),$e->keys,$x->source,$persist,30000,2,null,$overlap);$called=0;Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($bad,&$called):void{$bad->work(static function()use(&$called):void{++$called;},'witnessBudget',$bad->internalOperation('owned.reject.overlap'));});Check::same(0,$called);Check::same($before,$x->inspect());
});
echo 'PASS bounded recovery audit capacity and domains: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; 256 records including orphans, no pruning/publication on exhaustion, distinct witness and business domains\n";
