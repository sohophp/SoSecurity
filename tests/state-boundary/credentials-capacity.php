<?php
declare(strict_types=1);
require __DIR__.'/credentials-support.php';
recoveryAuditCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):void{
    list($next,$accounts,$manifest)=credentialSetup($x,$op,$control);$service=credentialService($x,$op);$before=$next->inspect('witnessBudget');for($i=0;$i<4;++$i){$en=$service->prepare($next,$accounts,$manifest,'user','Owned capacity user','witnessBudget');Check::same(64,strlen($en->password()));}
    $operator=$op->inspect();witnessReason('account.credentials_capacity',static function()use($service,$next,$accounts,$manifest):void{$service->prepare($next,$accounts,$manifest,'user','Owned excess','witnessBudget');});Check::same('current',$op->inspect()['status']);Check::same($before,$next->inspect('witnessBudget'));
    $x->e->clock->time+=301;$en=$service->prepare($next,$accounts,$manifest,'user','Owned capacity reclaimed','witnessBudget');Check::same(64,strlen($en->password()));Check::same(true,$service->confirm($next,$accounts,$manifest,'user',$en->selector(),$en->password(),credentialCode($en,$x),'witnessBudget'));Check::same($before,$next->inspect('witnessBudget'));
});
echo 'PASS recovery credential fixed capacity: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; four candidates, overflow leaves independent current and target quarantine, expiry reclaims slots without target changes\n";
