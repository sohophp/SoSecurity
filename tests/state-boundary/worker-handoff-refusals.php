<?php
declare(strict_types=1);
require __DIR__.'/worker-handoff-support.php';
recoveryAuditCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):void{
    list($w,$token,$plan,$args,$old,$next)=workerHandoffSetup($x,$op,$control);$before=$w->inspect('witnessBudget');$digest=$x->source->digest();$files=entryFiles($x);
    $called=0;Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($x,$old,$next,&$called):void{$r=[];$service=workerService($x->e,$old,$r);$service->rotateWorkers($next,str_repeat('a',64),'owned',static function()use(&$called):bool{++$called;return true;},static function():bool{return true;});});Check::same(0,$called);
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($plan,$w,$old,$next):void{$old->handoff($plan,$w,str_repeat('a',64),$next);});Check::same(null,$next->recoveryImage($w));
    $m=$plan->manifest();$m['next_root']['entries']++;Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($args,$m):void{SoSecurity\Account\StateWorkerHandoff::resume(...array_merge($args,[$m]));});
    $review=$w->workerHandoffReview($plan,$control,'user',$token,'witnessBudget');$v=$review->metadata();$v['seal']=str_repeat('a',64);$forged=new SoSecurity\Account\StateWorkerReview($v);witnessReason('account.worker_changed',static function()use($w,$forged,$plan,$control,$token):void{$w->handoffWorkers($forged,$plan,$control,'user',$token,'og1.'.str_repeat('a',32).'.'.str_repeat('b',64),'witnessBudget');});
    Check::same($before,$w->inspect('witnessBudget'));Check::same($digest,$x->source->digest());Check::same($files,entryFiles($x));Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($plan):void{serialize($plan);});
    $op->e->clock->time+=121;witnessReason('account.containment_expired',static function()use($w,$review,$plan,$control,$token):void{$w->handoffWorkers($review,$plan,$control,'user',$token,'og1.'.str_repeat('a',32).'.'.str_repeat('b',64),'witnessBudget');});Check::same($before,$w->inspect('witnessBudget'));Check::same($digest,$x->source->digest());
});
echo 'PASS worker handoff refusals: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; normal rotation cannot cross boundaries, direct effect capability denied, altered manifest/signature and expired approval refused before target mutation\n";
