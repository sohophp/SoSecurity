<?php
declare(strict_types=1);
require __DIR__.'/grants-native-support.php';
foreach(['rollback','expiry','committed-unknown'] as $mode){
    grantCase(static function(EntryEnvironment $x,string $token)use($mode):void{
        $g=nativeGrants($x);$i=grantIntent($x->e->pdo);$pending=$g->begin('tenant','user',$token,$i);$token=grantReauth($x,$token);$grant=$g->confirm('tenant','user',$token,$i,$pending->token());$rows=businessRows($x);$calls=0;$root=$x->inspect();if($mode==='committed-unknown'){$x->finalAllowed=false;}
        witnessReason('account.completion_unknown',static function()use($x,$g,$token,$grant,$mode,&$calls):void{grantExecute($x,$g,$token,$grant->token(),static function(PDO $pdo,SoSecurity\Operation\Permit $permit)use($x,$mode,&$calls):int{++$calls;$v=grantWrite($pdo,$permit);if($mode==='rollback'){throw new RuntimeException('Owned business rollback');}if($mode==='expiry'){$x->e->clock->time=$permit->expiresAt();}return $v;});});$x->finalAllowed=true;Check::same(1,$calls);Check::same('pending',$x->inspect()['status']);Check::same('operations.execute',$x->inspect()['intent']['action']);Check::same($root['digest'],$x->inspect()['digest']);Check::same($mode!=='committed-unknown',$rows===businessRows($x));$files=entryFiles($x);Check::same(false,strpos(json_encode($x->inspect()),$grant->token())!==false);grantNoEffect($x,static function()use($x,$g,$token,$grant,&$calls){return grantExecute($x,$g,$token,$grant->token(),static function()use(&$calls):void{++$calls;});},'account.witness_pending');Check::same(1,$calls);Check::same($files,entryFiles($x));
    });
}
echo 'PASS native grant unknown business outcomes: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; real SQL rollback/expiry and committed unknown keep consumed proof pending, no callback replay\n";
