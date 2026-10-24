<?php
declare(strict_types=1);
require __DIR__.'/managed-api-support.php';
recoveryAuditCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):void{
    list($api,$tokens,$session,$authority,$next,$plan,$token)=managedApiSetup($x,$op,$control);managedApiProbe($x,$tokens,$session,$authority,false);$before=$next->inspect('witnessBudget');$review=$next->apiKeyRetirementReview($plan,$control,'user',$token,'witnessBudget');list($token,$grant)=apiRetirementApproval($op,$control,$review,$token);$done=$next->retireApiKeys($review,$plan,$control,'user',$token,$grant,'witnessBudget');managedApiAssertions($x,$tokens,$session,$authority,$plan,$before,$done);Check::same(4,recoveryAuditCount($next));
});
echo 'PASS native account API retirement: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; actual issued claims and sessions, all entries cleared with fixed epoch, unchanged valid identity cannot revive old tokens, fresh issuance/rotation works in isolated control; quarantine retained\n";
