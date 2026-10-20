<?php
declare(strict_types=1);
require __DIR__.'/operations-support.php';
foreach(['disable','regenerate','reencrypt'] as $action){managedCase(static function(ManagedEnvironment $e)use($action):void{
    $e->registry->initialize('user');$old=$e->registry->current('user');$before=$e->row();$f=purgeFence($e);$s=normalOperations($e,$f);$s->initialize();$review=$s->review($action,'user','owned-review');$proof=$action==='reencrypt'?[]:normalFactor($e);$r=$s->execute($review,'owned-execute',normalProof(),$proof);Check::same(true,$r['completed']);Check::same($action,$r['action']);$inspect=$s->inspect($review['operation'],'owned-inspect');Check::same('completed',$inspect['state']);Check::same($old->factorId(),$inspect['slot']['factor']);
    foreach(['address','address_version','password','roles','status','verified'] as $k){Check::same($before[$k],$e->row()[$k]);}
    if($action==='reencrypt'){Check::same($before,$e->row());Check::same($old->binding(),$e->registry->binding('tenant','user'));Check::same(null,$r['codes']);}
    else{Check::same(false,$before['credential_version']===$e->row()['credential_version']);Check::same(false,$old->binding()===$e->registry->current('user')->binding());}
    if($action==='disable'){
        Check::same('0',(string)$e->row()['mfa_required']);Check::same(false,$e->registry->current('user')->enabled());Check::same(false,$e->factors->status($old->slotScope(),$old->slotSubject())['enabled']);Check::same(true,$r['factor_removed']);Check::same(['absent'=>1,'conflicts'=>0],$s->clean($review['operation'],'owned-clean'));Check::same('cleaned',$s->inspect($review['operation'],'owned-inspect')['state']);
    }elseif($action==='regenerate'){
        Check::same(10,count($r['codes']));Check::same(false,$e->factors->verifyRecovery($old->slotScope(),$old->slotSubject(),$e->codes[0]));Check::same(true,$e->factors->verifyRecovery($old->slotScope(),$old->slotSubject(),$r['codes'][0]));Check::same(false,$e->factors->verifyRecovery($old->slotScope(),$old->slotSubject(),$r['codes'][0]));
    }
    Check::same($action==='disable'?3:2,(int)$e->observer->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn());Check::same(false,strpos(json_encode($inspect),'owned-step-up-approval')!==false);
    Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($s,$review,$proof):void{$s->execute($review,'owned-no-replay',normalProof(),$proof);});
});}
managedCase(static function(ManagedEnvironment $e):void{$e->registry->initialize('user');$f=purgeFence($e);$s=normalOperations($e,$f);$s->initialize();$r=$s->review('disable','user','owned-review');Check::same(true,$s->execute($r,'owned-recovery-disable',normalProof(),normalFactor($e,true))['factor_removed']);Check::same(false,$e->registry->current('user')->enabled());});
echo 'PASS managed normal factor operations: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; signed exact review, logical disable/version first, recovery rotation once-only output, re-encryption identity preservation and durable cleanup\n";
