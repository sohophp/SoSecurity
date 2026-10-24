<?php
declare(strict_types=1);
require __DIR__.'/recovery-audit-support.php';
function credentialSetup(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):array
{
    list($next,$token)=containmentStage($x,$op,$control);$plan=containmentPlan($x,$next);$review=$next->containmentReview($plan,$control,'user',$token,'witnessBudget');list($token,$grant)=containmentApproval($op,$control,$review,$token);$done=$next->containAccounts($review,$plan,$control,'user',$token,$grant,'witnessBudget');return [$next,$plan,$done['remediation']['manifest']];
}
function credentialService(EntryEnvironment $x,EntryEnvironment $op):SoSecurity\Account\StateRecoveryCredentials
{
    return new SoSecurity\Account\StateRecoveryCredentials($op->boundary,new SoSecurity\Storage\FileStore($op->e->directory.'/factors','credential-drafts',$op->e->clock,5000),$x->e->factors,new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]),$x->e->keys,'managed-test','tenant',str_repeat('e',64));
}
function credentialCode(SoSecurity\Account\StateCredentialEnrollment $en,EntryEnvironment $x):string{parse_str(parse_url($en->enrollment()->provisioningUri(),PHP_URL_QUERY),$params);return (new SoSecurity\Mfa\Totp())->codeAt($params['secret'],$x->e->clock->time);}
