<?php
declare(strict_types=1);
require __DIR__.'/restoration-support.php';
managedCase(static function(ManagedEnvironment $e):void{
    $f=restorationSetup($e);$r=restorationService($e,$f);list($v,$en,$secret)=restorationPrepared($e,$r);$actual=(new SoSecurity\Mfa\Totp())->codeAt($secret,$e->clock->time);$wrong=str_pad((string)(((int)$actual+1)%1000000),6,'0',STR_PAD_LEFT);
    migrationReason('account.restoration_unproven',static function()use($r,$v):void{$r->operationReview($v['operation'],'owned-no-unproven-activation');});
    for($i=0;$i<4;++$i){Check::same(null,$r->prove($v['operation'],$wrong,'owned-wrong-new-factor'));}Check::same(4,$r->inspect($v['operation'],'owned-four-attempts')['attempts']);Check::same(true,count($r->prove($v['operation'],$actual,'owned-last-permitted-proof'))>0);Check::same(5,$r->inspect($v['operation'],'owned-last-attempt')['attempts']);$physical=['old'=>modeSnapshot($e),'new'=>restorationPhysical($e,$v)];
    migrationReason('account.restoration_unproven',static function()use($r,$v,$actual):void{$r->prove($v['operation'],$actual,'owned-sixth-not-permitted');});Check::same($physical,['old'=>modeSnapshot($e),'new'=>restorationPhysical($e,$v)]);Check::same('proven',$r->inspect($v['operation'],'owned-still-proven')['state']);
});
managedCase(static function(ManagedEnvironment $e):void{
    $f=restorationSetup($e);$r=restorationService($e,$f);list($v,$secret,$codes)=restorationProven($e,$r);$old=$r->operationReview($v['operation'],'owned-activation-before-reproof');$e->clock->time=(intdiv($e->clock->time,30)+1)*30;Check::same([],$r->prove($v['operation'],(new SoSecurity\Mfa\Totp())->codeAt($secret,$e->clock->time),'owned-reprove-not-replay-codes'));
    migrationReason('account.restoration_changed',static function()use($r,$old):void{$r->activate($old,'owned-stale-before-reproof',normalProof());});Check::same(true,$f->work(static function():bool{return true;}));$fresh=$r->operationReview($v['operation'],'owned-fresh-after-reproof');Check::same(true,$r->activate($fresh,'owned-activate-reproved-new-factor',normalProof())['restored']);
});
managedCase(static function(ManagedEnvironment $e):void{
    $f=restorationSetup($e);$r=restorationService($e,$f);list($v,$secret,$codes)=restorationProven($e,$r);$e->clock->time=$v['expires']+30;Check::same([],$r->prove($v['operation'],(new SoSecurity\Mfa\Totp())->codeAt($secret,$e->clock->time),'owned-proof-within-flow-lifetime'));$approve=$r->operationReview($v['operation'],'owned-fresh-activation-lifetime');Check::same(true,$approve['expires']>$v['expires']);Check::same(true,$r->activate($approve,'owned-explicit-later-activation',normalProof())['restored']);
});
echo 'PASS restoration proof boundaries: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; fifth permitted attempt works, sixth refused without physical mutation, reproof never replays codes and stale activation refused, workflow deadline separate from preparation review\n";
