<?php
declare(strict_types=1);
require __DIR__.'/resolution-support.php';
foreach(['password','roles','mfa','history'] as $fault){managedCase(static function(ManagedEnvironment $e)use($fault):void{
    list($f,$legacy,$ops,$op)=unresolvedOperation($e,'regenerate','physical');$h=resolutionService($e,$f);$view=$h->review($op['operation'],'owned-cas-review');$before=$e->row();$physical=modeSnapshot($e);$row=purgeFlow($e,$f,$op['operation']);$changed=false;$replacement=(new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]))->hash('Owned forbidden credential change 49!');
    $e->pdo->afterStatement=static function(string $sql)use($e,$f,$fault,$replacement,&$changed):void{
        if(!$changed&&strpos($sql,'UPDATE account_example SET credential_version=:next_version,mfa_required=:required')===0){
            $changed=true;
            if($fault==='password'){$q=$e->pdo->prepare("UPDATE account_example SET password=? WHERE scope='tenant' AND subject='user'");$q->execute([$replacement]);$q->closeCursor();}
            elseif($fault==='roles'){$e->pdo->exec("UPDATE account_example SET roles='[\"unexpected\"]' WHERE scope='tenant' AND subject='user'");}
            elseif($fault==='mfa'){$e->pdo->exec("UPDATE account_example SET mfa_required=0 WHERE scope='tenant' AND subject='user'");}
            else{$u=new SoSecurity\Support\SqlTransaction($e->pdo,$e->clock,10000);$l=new SoSecurity\Account\Ledger($u,'account-factor-recovery:'.hash('sha256','managed-test'),'tenant',str_repeat('e',64),$e->keys,new SoSecurity\Account\Policy(),2,$f->binding());$u->enlist(static function()use($l,$e):void{$l->put(hash('sha256','owned-forbidden-cas-history'),hash('sha256','foreign-owner'),'budget','owned forbidden unrelated history',$e->clock->time+100);});}
        }
    };
    migrationReason('account.completion_unknown',static function()use($h,$view):void{$h->abandon($view['context'],'owned-reject-broken-cas',normalProof());});$e->pdo->afterStatement=null;Check::same(true,$changed);Check::same($before,$e->row());Check::same($physical,modeSnapshot($e));Check::same($row,purgeFlow($e,$f,$op['operation']));Check::same(2,migrationHistoryCount($e,$f));Check::same(0,(int)$e->observer->query('SELECT COUNT(*) FROM factor_resolution_audit')->fetchColumn());
});}
// Current-actor SQL side effects cannot silently change either the reviewed root or target account.
foreach(['history','credential'] as $fault){managedCase(static function(ManagedEnvironment $e)use($fault):void{
    list($f,$legacy,$ops,$op)=unresolvedOperation($e,'reencrypt');$armed=false;$h=resolutionService($e,$f,static function(string $action,string $phase)use($e,$f,$fault,&$armed):bool{
        if($armed&&$phase==='authorize'){$armed=false;if($fault==='credential'){$e->pdo->exec("UPDATE account_example SET credential_version='owned-forbidden-actor-version' WHERE scope='tenant' AND subject='user'");}else{$u=new SoSecurity\Support\SqlTransaction($e->pdo,$e->clock,10000);$l=new SoSecurity\Account\Ledger($u,'account-factor-recovery:'.hash('sha256','managed-test'),'tenant',str_repeat('e',64),$e->keys,new SoSecurity\Account\Policy(),2,$f->binding());$u->enlist(static function()use($l,$e):void{$l->put(hash('sha256','owned-forbidden-actor-history'),hash('sha256','actor-owner'),'budget','owned forbidden actor history',$e->clock->time+100);});}}return true;
    });$view=$h->review($op['operation'],'owned-actor-review');$before=$e->row();$armed=true;migrationReason('account.resolution_changed',static function()use($h,$view):void{$h->abandon($view['context'],'owned-reject-changing-actor',normalProof());});Check::same(false,$armed);Check::same($before,$e->row());Check::same(2,migrationHistoryCount($e,$f));Check::same(true,$f->work(static function():bool{return true;}));Check::same(0,(int)$e->observer->query('SELECT COUNT(*) FROM factor_resolution_audit')->fetchColumn());
});}
// Even direct advanced wiring cannot claim success when its account CAS does nothing.
managedCase(static function(ManagedEnvironment $e):void{
    list($f,$legacy,$ops,$op)=unresolvedOperation($e,'reencrypt');$calls=0;$before=$e->row();$h=$ops->resolution(static function($unit,array $facts):array{return $facts;},static function():bool{return true;},static function():bool{return true;},static function():bool{return true;},static function()use(&$calls):bool{++$calls;return true;},static function()use(&$calls):bool{++$calls;return true;});$view=$h->review($op['operation'],'owned-noop-cas-review');migrationReason('account.completion_unknown',static function()use($h,$view):void{$h->abandon($view['context'],'owned-no-noop-cas',normalProof());});Check::same(0,$calls);Check::same($before,$e->row());Check::same('prepared',json_decode(purgeFlow($e,$f,$op['operation'])['payload'],true)['state']);
});
echo 'PASS operation resolution CAS invariants: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; actual same-PDO broken password/roles/MFA/history writes and actor mutations rejected and rolled back\n";
