<?php
declare(strict_types=1);
require __DIR__.'/api-business-support.php';
foreach(['rollback','lost-transaction','expiry-before-commit','expiry-after-commit','committed-unknown'] as $mode){
    businessCase(static function(EntryEnvironment $x,SoSecurity\Api\CredentialRegistry $api,string $header)use($mode):void{
        $rows=businessRows($x);$calls=0;$persists=[];apiIntentObserve($x,$persists);if($mode==='committed-unknown'){$x->finalAllowed=false;}
        witnessReason('account.completion_unknown',static function()use($x,$api,$header,$mode,&$calls){businessRun($x,$api,$header,static function(PDO $pdo,SoSecurity\Api\VerifiedCredential $proof,SoSecurity\Operation\Intent $intent)use($x,$mode,&$calls):int{
            ++$calls;$result=businessWrite($pdo,$proof,$intent);if($mode==='rollback'){throw new RuntimeException('Owned business failure');}if($mode==='lost-transaction'){$pdo->exec('COMMIT');}if($mode==='expiry-before-commit'){$x->e->clock->time=$proof->expiresAt();}if($mode==='expiry-after-commit'){$x->e->pdo->afterCommit=static function()use($x,$proof):void{$x->e->clock->time=$proof->expiresAt();};}return $result;
        });});$x->finalAllowed=true;$x->e->pdo->afterCommit=null;$x->persistHook=null;Check::same(1,$calls);Check::same(1,count($persists));Check::same('pending',$x->inspect()['status']);Check::same('api.credentials.execute',$x->inspect()['intent']['action']);
        Check::same(in_array($mode,['rollback','expiry-before-commit'],true),$rows===businessRows($x));$after=businessRows($x);$root=$x->inspect();
        nativeApiNoEffect($x,static function()use($x,$api,$header,&$calls){businessRun($x,$api,$header,static function()use(&$calls):void{++$calls;});},'account.witness_pending');Check::same(1,$calls);Check::same($after,businessRows($x));Check::same($root,$x->inspect());
    });
}
echo 'PASS native business uncertain outcomes: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; real rollback, lost transaction, expiry rollback and committed final-unknown remain pending without replay\n";
