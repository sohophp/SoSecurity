<?php
declare(strict_types=1);
require __DIR__.'/successor-support.php';
retirementCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):void{
    $token=successorClosed($x,$op,$control);$closed=$x->inspect();$observed=$x->source->digest();$files=entryFiles($x);$path=glob($x->e->directory.'/independent-witness/*.witness')[0];$before=file_get_contents($path);$stat=lstat($path);
    $review=$x->witness->successorReview($control,'user',$token,'witnessBudget');$v=$review->metadata();$next=$x->witness->successorReader($review);
    Check::same('closed',$x->inspect()['status']);Check::same($before,file_get_contents($path));Check::same('stage_successor',$v['purpose']);Check::same(hash('sha256',$before),$v['predecessor']);Check::same($observed,$v['observed']);Check::same($closed['intent_digest'],$v['intent']);Check::same(3,$next->format());Check::same($v['generation'],$next->generation());Check::same($x->witness->binding(),$next->binding());
    witnessReason('account.witness_corrupt',static function()use($next):void{$next->inspect('witnessBudget');});
    list($token,$grant)=successorApproval($op,$control,$review,$token);
    // The same valid grant must remain usable after every rejected selection and budget.
    foreach(['predecessor','observed','intent','control','nonce','seal','generation'] as $field){$bad=$v;$bad[$field]=str_repeat($v[$field][0]==='a'?'b':'a',64);$r=new SoSecurity\Account\StateSuccessorReview($bad);$reader=$x->witness->successorReader($r);witnessReason('account.successor_changed',static function()use($x,$r,$reader,$control,$token,$grant):void{$x->witness->stageSuccessor($r,$reader,$control,'user',$token,$grant,'witnessBudget');});Check::same($before,file_get_contents($path));}
    witnessReason('account.witness_budget',static function()use($x,$review,$next,$control,$token,$grant):void{$x->witness->stageSuccessor($review,$next,$control,'user',$token,$grant,static function(string $phase):bool{return $phase!=='final';});});Check::same($before,file_get_contents($path));
    $queries=$x->e->pdo->queries;$operatorQueries=$op->e->pdo->queries;
    foreach([[str_repeat('x',257),$token,$grant],['user','invalid',$grant],['user',$token,str_repeat('x',1025)]] as $bad){Check::throws(SoSecurity\Exception\ValidationException::class,static function()use($x,$review,$next,$control,$bad):void{$x->witness->stageSuccessor($review,$next,$control,$bad[0],$bad[1],$bad[2],'witnessBudget');});}
    Check::same($queries,$x->e->pdo->queries);Check::same($operatorQueries,$op->e->pdo->queries);
    $receipt=$x->witness->stageSuccessor($review,$next,$control,'user',$token,$grant,'witnessBudget');
    clearstatcache(true,$path);$after=lstat($path);Check::same($stat['ino'],$after['ino']);Check::same($stat['dev'],$after['dev']);Check::same(1,count(glob($x->e->directory.'/independent-witness/*.witness')));Check::same(true,$after['size']<=4096);
    Check::same('quarantined',$receipt['status']);Check::same($closed['revision']+1,$receipt['revision']);Check::same($closed['digest'],$receipt['digest']);Check::same(false,$receipt['digest']===$observed);Check::same($v['predecessor'],$receipt['lineage']);Check::same($v['generation'],$receipt['generation']);Check::same('recovery',$receipt['intent']['kind']);Check::same($v,$receipt['successor']['review']);Check::same($closed['operation'],$receipt['successor']['predecessor_operation']);Check::same($closed['intent'],$receipt['successor']['predecessor_intent']);Check::same($receipt,$next->inspect('witnessBudget'));
    Check::same($observed,$x->source->digest());Check::same($files,entryFiles($x));Check::same(1,(int)$x->e->observer->query('SELECT COUNT(*) FROM entry_worker_audit')->fetchColumn());
    witnessReason('account.witness_corrupt',static function()use($x):void{$x->inspect();});
    $wrong=$v;$wrong['generation']=str_repeat($v['generation'][0]==='a'?'b':'a',64);$wrongReader=$x->witness->successorReader(new SoSecurity\Account\StateSuccessorReview($wrong));witnessReason('account.witness_generation',static function()use($wrongReader):void{$wrongReader->inspect('witnessBudget');});
    $calls=0;$newBoundary=new SoSecurity\Account\StateBoundary($next,static function():bool{return true;});
    foreach([$x->boundary,$newBoundary] as $boundary){Check::throws(SoSecurity\Storage\StorageException::class,static function()use($boundary,&$calls):void{$boundary->run('owned.blocked',static function()use(&$calls):void{++$calls;});});}
    Check::same(0,$calls);witnessReason('account.witness_exists',static function()use($next,$observed):void{$next->initialize($observed);});
    foreach([print_r($review,true),var_export($review,true),json_encode($receipt)] as $dump){Check::same(false,strpos($dump,$token)!==false);Check::same(false,strpos($dump,$grant)!==false);}
});
echo 'PASS sealed successor quarantine: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; independent strong approval, same inode, exact predecessor, no baseline adoption, all business callbacks blocked\n";
