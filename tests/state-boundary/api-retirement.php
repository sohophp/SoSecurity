<?php
declare(strict_types=1);
require __DIR__.'/api-retirement-support.php';
recoveryAuditCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):void{
    list($api,$tokens,$next,$plan,$token)=apiRetirementSetup($x,$op,$control);apiRetirementProbe($x,$tokens,false);$before=$next->inspect('witnessBudget');$review=$next->apiKeyRetirementReview($plan,$control,'user',$token,'witnessBudget');list($token,$grant)=apiRetirementApproval($op,$control,$review,$token);$done=$next->retireApiKeys($review,$plan,$control,'user',$token,$grant,'witnessBudget');apiRetirementAssertions($x,$tokens,$next,$plan,$before,$done);Check::same(4,recoveryAuditCount($next));
});
echo 'PASS native legacy API epoch retirement: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; all live/expired legacy subject keys denied, foreign subjects/namespaces retained, new generation issued/rotated, missing marker counterexample, native audit; quarantine retained\n";
