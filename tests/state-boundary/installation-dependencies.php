<?php
declare(strict_types=1);
require __DIR__.'/installation-support.php';
recoveryAuditCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control):void{
    $mysql=$x->e->pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql';$calls=0;$probe=0;$created=false;
    $persist=static function($h)use($x,$mysql,&$calls,&$probe,&$created):bool{
        witnessPersist($h,$x->e->directory.'/factors');if(++$calls===2){
            if($mysql){$x->e->pdo->exec('SET @owned_credential_install_probe=0');$x->e->pdo->exec('CREATE TRIGGER owned_credential_dependency BEFORE UPDATE ON sosecurity_account_records FOR EACH ROW SET @owned_credential_install_probe=1');}
            else{$x->e->pdo->exec('CREATE TABLE owned_credential_probe(flag INTEGER NOT NULL)');$x->e->pdo->exec('INSERT INTO owned_credential_probe VALUES(0)');$x->e->pdo->exec('CREATE TRIGGER owned_credential_dependency AFTER UPDATE ON sosecurity_account_records BEGIN UPDATE owned_credential_probe SET flag=1; END');$probe=(int)$x->e->pdo->query('SELECT total_changes()')->fetchColumn();}$created=true;
        }return true;
    };
    list($next,$accounts,$plan,$en)=installationSetup($x,$op,$control,$persist);$before=$next->inspect('witnessBudget');$token=$op->login()->credential()->token();$review=$next->credentialInstallationReview($plan,$control,'user',$token,'witnessBudget');list($token,$grant)=installationApproval($op,$control,$review,$token);
    try{witnessReason('account.completion_unknown',static function()use($next,$review,$plan,$control,$token,$grant):void{$next->installCredentials($review,$plan,$control,'user',$token,$grant,'witnessBudget');});Check::same(true,$created);Check::same(0,$mysql?(int)$x->e->pdo->query('SELECT @owned_credential_install_probe')->fetchColumn():(int)$x->e->pdo->query('SELECT total_changes()')->fetchColumn()-$probe);Check::same(null,$x->e->row()['password']);Check::same('pending',$next->inspect('witnessBudget')['remediation']['phase']);}
    finally{$x->e->pdo->exec('DROP TRIGGER IF EXISTS owned_credential_dependency');if(!$mysql){$x->e->pdo->exec('DROP TABLE IF EXISTS owned_credential_probe');}}
    $manifest=$plan->manifest();$next=recoveryAuditReload($x,$next,new SoSecurity\Account\StateRecoveryAudit($x->e->directory.'/recovery-audit',$x->e->keys,static function($h)use($x):bool{return witnessPersist($h,$x->e->directory.'/recovery-audit');}));$accounts=containmentPlan($x,$next);$plan=SoSecurity\Account\StateCredentialInstallation::resume(...array_merge(installationArgs($x,$op,$next,$accounts),[$manifest]));$review=$next->credentialResolutionReview($plan,$control,'user',$token,'witnessBudget');list($token,$grant)=installationApproval($op,$control,$review,$token);$done=$next->installCredentials($review,$plan,$control,'user',$token,$grant,'witnessBudget');installedAssertions($x,$next,$plan,$en,$before,$done);
});
echo 'PASS credential directory SQL dependency protection: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; actual trigger probe never executes, all account/directory SQL stays before, reviewed continuation after dependency removal; quarantine remains\n";
