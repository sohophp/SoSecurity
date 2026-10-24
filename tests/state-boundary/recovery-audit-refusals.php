<?php
declare(strict_types=1);
require __DIR__.'/recovery-audit-support.php';
// Exact chain tampering is never hidden by a cached approval or earlier successful read.
recoveryAuditCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,SoSecurity\Account\StateRecoveryAudit $audit):void{
    $token=successorClosed($x,$op,$control);$root=$x->inspect();$page=$x->witness->recoveryHistory('witnessBudget');$dir=$x->e->directory.'/recovery-audit';$head=$dir.'/'.$root['recovery_audit']['head'].'.json';$original=file_get_contents($head);$marker=file_get_contents($dir.'/context.json');
    $withoutAudit=new SoSecurity\Account\LocalStateWitness($x->e->pdo,$x->e->directory.'/independent-witness','managed-test','tenant',str_repeat('e',64),$x->e->keys,$x->source,static function($h)use($x):bool{return witnessPersist($h,$x->e->directory.'/independent-witness');},30000,2);witnessReason('account.recovery_audit_required',static function()use($withoutAudit):void{$withoutAudit->inspect('witnessBudget');});
    foreach(['changed','missing','mode','hardlink','oversize','marker'] as $mode){
        try{
            if($mode==='changed'){file_put_contents($head,substr($original,0,-1).' ');}
            elseif($mode==='missing'){unlink($head);}
            elseif($mode==='mode'){chmod($head,0644);}
            elseif($mode==='hardlink'){link($head,$dir.'/'.str_repeat('f',64).'.json');}
            elseif($mode==='oversize'){file_put_contents($head,str_repeat('x',65537));}
            else{unlink($dir.'/context.json');}
            witnessReason('account.recovery_audit_corrupt',static function()use($x):void{$x->inspect();});
        }finally{if(is_file($dir.'/'.str_repeat('f',64).'.json')){unlink($dir.'/'.str_repeat('f',64).'.json');}file_put_contents($head,$original);chmod($head,0600);file_put_contents($dir.'/context.json',$marker);chmod($dir.'/context.json',0600);}
        Check::same($root,$x->inspect());Check::same($page,$x->witness->recoveryHistory('witnessBudget'));
    }
    foreach([['authority'=>'bad','offset'=>0],['authority'=>$page['authority'],'offset'=>256],['authority'=>$page['authority'],'offset'=>-1],['authority'=>$page['authority'],'offset'=>0,'extra'=>1]] as $cursor){Check::throws(SoSecurity\Exception\ValidationException::class,static function()use($x,$cursor):void{$x->witness->recoveryHistory('witnessBudget',$cursor);});}
    $offset=0;$cursor=['authority'=>$page['authority'],'offset'=>&$offset];$seen=$x->witness->recoveryHistory(static function()use(&$offset):bool{$offset=256;return true;},$cursor);Check::same($page,$seen);
    $review=$x->witness->successorReview($control,'user',$token,'witnessBudget');$next=$x->witness->successorReader($review);list($token,$grant)=successorApproval($op,$control,$review,$token);$x->witness->stageSuccessor($review,$next,$control,'user',$token,$grant,'witnessBudget');witnessReason('account.recovery_audit_cursor',static function()use($next,$page):void{$next->recoveryHistory('witnessBudget',['authority'=>$page['authority'],'offset'=>0]);});
    // An older audit snapshot must fail against the newer independent root.
    $newRoot=$next->inspect('witnessBudget');$newHead=$dir.'/'.$newRoot['recovery_audit']['head'].'.json';$saved=file_get_contents($newHead);unlink($newHead);witnessReason('account.recovery_audit_corrupt',static function()use($next):void{$next->inspect('witnessBudget');});file_put_contents($newHead,$saved);chmod($newHead,0600);Check::same($newRoot,$next->inspect('witnessBudget'));
    // A lost witness cannot be reset from the remaining audit and current database.
    $path=glob($x->e->directory.'/independent-witness/*.witness')[0];$authority=file_get_contents($path);unlink($path);try{witnessReason('account.recovery_audit_exists',static function()use($next,$x):void{$next->initialize($x->source->digest());});Check::same(false,is_file($path));}finally{file_put_contents($path,$authority);chmod($path,0600);}
});
// A journal fsync refusal must precede publication. A later approval can create a new branch, never adopt the orphan.
$calls=0;recoveryAuditCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,SoSecurity\Account\StateRecoveryAudit $audit):void{
    $token=successorClosed($x,$op,$control);$closed=$x->inspect();$review=$x->witness->successorReview($control,'user',$token,'witnessBudget');$next=$x->witness->successorReader($review);list($token,$grant)=successorApproval($op,$control,$review,$token);$source=$x->source->digest();
    witnessReason('account.completion_unknown',static function()use($x,$review,$next,$control,$token,$grant):void{$x->witness->stageSuccessor($review,$next,$control,'user',$token,$grant,'witnessBudget');});Check::same($closed,$x->inspect());Check::same($source,$x->source->digest());Check::same(1,recoveryAuditCount($x->witness));Check::same(3,count(glob($x->e->directory.'/recovery-audit/*.json')));
    $review=$x->witness->successorReview($control,'user',$token,'witnessBudget');$next=$x->witness->successorReader($review);list($token,$freshGrant)=successorApproval($op,$control,$review,$token);$result=$x->witness->stageSuccessor($review,$next,$control,'user',$token,$freshGrant,'witnessBudget');Check::same(2,$result['recovery_audit']['sequence']);Check::same(2,recoveryAuditCount($next));Check::same(4,count(glob($x->e->directory.'/recovery-audit/*.json')));Check::same($closed['digest'],$result['digest']);
},static function()use(&$calls):bool{return ++$calls!==3;});
// Starting from an old closed root cannot invent earlier history.
retirementCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):void{
    $token=successorClosed($x,$op,$control);$dir=$x->e->directory.'/recovery-audit';mkdir($dir,0700);$audit=new SoSecurity\Account\StateRecoveryAudit($dir,$x->e->keys,static function($h)use($dir):bool{return witnessPersist($h,$dir);});$x->witness=recoveryAuditReload($x,$x->witness,$audit);$review=$x->witness->successorReview($control,'user',$token,'witnessBudget');$next=$x->witness->successorReader($review);list($token,$grant)=successorApproval($op,$control,$review,$token);$result=$x->witness->stageSuccessor($review,$next,$control,'user',$token,$grant,'witnessBudget');Check::same(false,$result['recovery_audit']['complete']);Check::same(1,$result['recovery_audit']['sequence']);Check::same(1,recoveryAuditCount($next));
});
echo 'PASS recovery audit integrity and refusals: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; tamper/removal/mode/hardlink/size, audit rollback, missing config, detached/stale cursor, lost witness, unacknowledged orphan, legacy incomplete history\n";
