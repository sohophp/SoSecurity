<?php
declare(strict_types=1);
require __DIR__.'/revocation-support.php';
managedCase(static function(ManagedEnvironment $e):void{
    $f=revocationSetup($e);$calls=0;$service=revocationService($e,$f,static function()use(&$calls):bool{++$calls;return true;});$v=$service->review('user','owned-input-review')['context'];$calls=0;$before=revocationState($e);
    foreach(['purpose','effect','subject','state','authority','seal','format'] as $field){$bad=$v;$bad[$field]=$field==='format'?2:($field==='subject'?"user\0other":'wrong');$queries=$e->pdo->queries;Check::throws(SoSecurity\Exception\ValidationException::class,static function()use($service,$bad):void{$service->execute($bad,'owned-invalid',normalProof());});Check::same($queries,$e->pdo->queries);}
    foreach([['type'=>'totp','code'=>'123456'],['type'=>'approved','code'=>"code\0suffix"],['type'=>'approved','code'=>str_repeat('x',513)]] as $proof){$queries=$e->pdo->queries;revocationReason('account.revocation_input',static function()use($service,$v,$proof):void{$service->execute($v,'owned-invalid-proof',$proof);});Check::same($queries,$e->pdo->queries);}
    Check::same(0,$calls);Check::same($before,revocationState($e));Check::same(true,$f->work(static function():bool{return true;}));
});
foreach(['budget','approval','expired'] as $fault){managedCase(static function(ManagedEnvironment $e)use($fault):void{
    $f=revocationSetup($e);$armed=false;$authorityCalls=0;$approvalCalls=0;$service=revocationService($e,$f,static function()use(&$authorityCalls):bool{++$authorityCalls;return true;},static function()use($fault,&$armed):bool{return !($armed&&$fault==='budget');},static function()use($fault,&$armed,&$approvalCalls):bool{++$approvalCalls;return !($armed&&$fault==='approval');});$v=$service->review('user','owned-refusal-review')['context'];$before=revocationState($e);$physical=modeSnapshot($e);$authorityCalls=0;$approvalCalls=0;$armed=true;if($fault==='expired'){$e->clock->time=$v['expires'];}
    migrationReason($fault==='budget'?'account.revocation_budget':($fault==='approval'?'account.revocation_denied':'account.revocation_expired'),static function()use($service,$v):void{$service->execute($v,'owned-refused',normalProof());});if($fault==='budget'){Check::same(0,$authorityCalls);Check::same(0,$approvalCalls);}Check::same($before,revocationState($e));Check::same($physical,modeSnapshot($e));Check::same(true,$f->work(static function():bool{return true;}));
});}
foreach(['password','roles','mfa','history'] as $fault){managedCase(static function(ManagedEnvironment $e)use($fault):void{
    $f=revocationSetup($e);$service=revocationService($e,$f);$v=$service->review('user','owned-cas-review')['context'];$before=revocationState($e);$physical=modeSnapshot($e);$changed=false;$replacement=(new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]))->hash('Owned prohibited replacement password 49!');
    $e->pdo->afterStatement=static function(string $sql)use($e,$f,$fault,$replacement,&$changed):void{
        if(!$changed&&strpos($sql,'UPDATE account_example SET credential_version=:next_version,mfa_required=:required')===0){$changed=true;
            if($fault==='password'){$q=$e->pdo->prepare("UPDATE account_example SET password=? WHERE scope='tenant' AND subject='user'");$q->execute([$replacement]);$q->closeCursor();}
            elseif($fault==='roles'){$e->pdo->exec("UPDATE account_example SET roles='[\"unexpected\"]' WHERE scope='tenant' AND subject='user'");}
            elseif($fault==='mfa'){$e->pdo->exec("UPDATE account_example SET mfa_required=0 WHERE scope='tenant' AND subject='user'");}
            else{$u=new SoSecurity\Support\SqlTransaction($e->pdo,$e->clock,10000);$l=new SoSecurity\Account\Ledger($u,'account-factor-recovery:'.hash('sha256','managed-test'),'tenant',str_repeat('e',64),$e->keys,new SoSecurity\Account\Policy(),2,$f->binding());$u->enlist(static function()use($l,$e):void{$l->put(hash('sha256','owned-illegal-revocation-history'),hash('sha256','foreign-owner'),'budget','owned forbidden history',$e->clock->time+100);});}
        }
    };
    migrationReason('account.completion_unknown',static function()use($service,$v):void{$service->execute($v,'owned-reject-broken-cas',normalProof());});$e->pdo->afterStatement=null;Check::same(true,$changed);Check::same($before,revocationState($e));Check::same($physical,modeSnapshot($e));
});}
foreach(['authorize','delete_current'] as $phase){managedCase(static function(ManagedEnvironment $e)use($phase):void{
    $f=revocationSetup($e);$armed=false;$service=revocationService($e,$f,static function(string $purpose,string $at)use($e,$phase,&$armed):bool{if($armed&&$at===$phase){$armed=false;$e->pdo->exec("UPDATE account_example SET credential_version='owned-forbidden-authority-version' WHERE scope='tenant' AND subject='user'");}return true;});$v=$service->review('user','owned-actor-review')['context'];$before=$e->row();$physical=modeSnapshot($e);$armed=true;
    migrationReason($phase==='authorize'?'account.revocation_changed':'account.completion_unknown',static function()use($service,$v):void{$service->execute($v,'owned-current-actor',normalProof());});Check::same(false,$armed);Check::same($physical,modeSnapshot($e));Check::same($phase==='authorize'?0:1,(int)$e->observer->query('SELECT COUNT(*) FROM factor_privileged_audit')->fetchColumn());if($phase==='authorize'){Check::same($before,$e->row());Check::same(true,$f->work(static function():bool{return true;}));}else{Check::same(false,$e->row()['credential_version']==='owned-forbidden-authority-version');}
});}
echo 'PASS privileged revocation safety: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; bounded inputs, current budgets/approval, expiry, actual broken CAS writes and actor-side mutation rollback before exact deletion\n";
