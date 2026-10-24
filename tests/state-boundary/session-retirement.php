<?php
declare(strict_types=1);
require __DIR__.'/session-retirement-support.php';
recoveryAuditCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):void{
    $old=sessionRetirementOld($x);sessionRetirementProbe($x,$old,true);list($next,$accounts,$plan,$en)=sessionRetirementSetup($x,$op,$control);$original=$next->inspect('witnessBudget');$token=$op->login()->credential()->token();$review=$next->credentialInstallationReview($plan,$control,'user',$token,'witnessBudget');list($token,$grant)=installationApproval($op,$control,$review,$token);$done=$next->installCredentials($review,$plan,$control,'user',$token,$grant,'witnessBudget');installedAssertions($x,$next,$plan,$en,$original,$done);sessionRetirementAssert($x,$plan,$old);Check::same(6,recoveryAuditCount($next));
});
echo 'PASS installed session retirement: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; physical sessions/remember cleared, fixed new epoch, real old tokens accepted before and denied after even with frozen valid identity, pending proof never reaches factor; quarantine retained\n";
