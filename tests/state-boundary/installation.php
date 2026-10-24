<?php
declare(strict_types=1);
require __DIR__.'/installation-support.php';
recoveryAuditCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):void{
    list($next,$accounts,$plan,$en)=installationSetup($x,$op,$control);$original=$next->inspect('witnessBudget');$token=$op->login()->credential()->token();$review=$next->credentialInstallationReview($plan,$control,'user',$token,'witnessBudget');Check::same('install_credentials',$review->metadata()['purpose']);list($token,$grant)=installationApproval($op,$control,$review,$token);$receipt=$next->installCredentials($review,$plan,$control,'user',$token,$grant,'witnessBudget');installedAssertions($x,$next,$plan,$en,$original,$receipt);
    $copy=recoveryAuditReload($x,$next,new SoSecurity\Account\StateRecoveryAudit($x->e->directory.'/recovery-audit',$x->e->keys,static function($h)use($x):bool{return witnessPersist($h,$x->e->directory.'/recovery-audit');}));Check::same($receipt,$copy->inspect('witnessBudget'));Check::same(6,recoveryAuditCount($next));$largest=0;foreach(glob($x->e->directory.'/recovery-audit/*.json') as $file){$largest=max($largest,filesize($file));}Check::same(true,$largest>16384);Check::same(true,$largest<=65536);
});
echo 'PASS fixed credential installation: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; new factor durable before atomic account/pointer/root SQL, real one-use strong approval, encrypted resumable effects, candidate consumed; still disabled/quarantined\n";
