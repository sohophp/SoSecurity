<?php
declare(strict_types=1);
require __DIR__.'/intent-history-support.php';
managedCase(static function(ManagedEnvironment $e):void{
    list($f,$legacy)=migrationSetup($e);$core=migrationService($e,$legacy,$f);$v=$core->review('user','owned-migration-review',migrationStop());$core->execute($v,'owned-migrate',migrationProof());$ops=lifecycleOperations($e,$f);$op=$ops->review('reencrypt','user','owned-operation-review');$ops->execute($op,'owned-operation',normalProof());
    $actorCalls=0;$approvalCalls=0;$authority=static function()use(&$actorCalls):bool{++$actorCalls;return true;};$approval=static function()use(&$approvalCalls):bool{++$approvalCalls;return true;};
    $migration=migrationHistory($e,$core,$authority,null,$approval);$operation=operationHistory($e,$ops,$authority,null,$approval);
    foreach(['purge','rekey'] as $mode){
        $m=$migration->review($mode,'owned-migration-page');$o=$operation->review($mode,'owned-operation-page');
        $queries=$e->pdo->queries;$actors=$actorCalls;$proofs=$approvalCalls;
        foreach([[$migration,$o],[$operation,$m]] as $case){
            Check::throws(SoSecurity\Exception\ValidationException::class,static function()use($case,$mode):void{$method=$mode==='purge'?'drainAndMaintain':'maintain';$case[0]->$method($case[1]['context'],'owned-wrong-purpose',migrationProof());});
            Check::same($queries,$e->pdo->queries);Check::same($actors,$actorCalls);Check::same($proofs,$approvalCalls);
        }
        Check::same(true,$f->work(static function():bool{return true;}));
    }
    Check::same(2,migrationHistoryCount($e,$f));Check::same('activated',$core->inspect($v['operation'],'owned-preserved')['state']);Check::same('completed',$ops->inspect($op['operation'],'owned-preserved')['state']);
});
echo 'PASS intent history purpose separation: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
