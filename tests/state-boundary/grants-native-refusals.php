<?php
declare(strict_types=1);
require __DIR__.'/grants-native-support.php';
use SoSecurity\Account\Example\StateDocuments;
grantCase(static function(EntryEnvironment $x,string $token):void{
    $allowed=true;$g=nativeGrants($x,static function()use(&$allowed):bool{return $allowed;},new SoSecurity\Operation\Policy(120,1));$i=grantIntent($x->e->pdo);$allowed=false;grantNoEffect($x,static function()use($g,$token,$i):void{$g->begin('tenant','user',$token,$i);},'operation.request_denied');$allowed=true;
    grantNoEffect($x,static function()use($g,$i):void{$g->begin('tenant','user','invalid',$i);},'operation.authentication');grantNoEffect($x,static function()use($g,$token,$x):void{$g->begin('tenant','user',$token,grantIntent($x->e->pdo,'Denied','foreign'));},'authorization.denied');
    $wrong=new SoSecurity\Operation\Intent($i->action(),$i->resource(),['owner'=>'other'],['owner']);grantNoEffect($x,static function()use($g,$token,$wrong):void{$g->begin('tenant','user',$token,$wrong);},'authorization.denied');
    $p=$g->begin('tenant','user',$token,$i);grantNoEffect($x,static function()use($g,$token,$i):void{$g->begin('tenant','user',$token,$i);},'operation.capacity');grantNoEffect($x,static function()use($g,$token,$i){return $g->consume('tenant','user',$token,$i,'invalid');});
    foreach(['wrong-pdo','wrong-definition','nested','transaction'] as $mode){
        $before=permissionState($x);$rows=businessRows($x);$pdo=$mode==='wrong-pdo'?$x->e->observer:$x->e->pdo;$defs=StateDocuments::definition();if($mode==='wrong-definition'){unset($defs['state_example_documents']['columns']['owner']);}$work=static function():void{throw new RuntimeException('Must never run');};$attempt=static function()use($g,$token,$pdo,$defs,$work){return $g->execute('tenant','user',$token,'invalid',$pdo,$defs,static function(PDO $p):SoSecurity\Operation\Intent{return grantIntent($p);},$work);};
        if($mode==='transaction'){$pdo->beginTransaction();}try{if($mode==='nested'){$x->boundary->run('owned.nested.grants',static function()use($attempt):void{Check::throws(SoSecurity\Exception\ConfigurationException::class,$attempt);});}else{Check::throws(SoSecurity\Exception\ConfigurationException::class,$attempt);}}finally{if($mode==='transaction'){$pdo->rollBack();}}
        if($mode!=='nested'){Check::same($before,permissionState($x));}Check::same($rows,businessRows($x));
    }
    $token=grantReauth($x,$token);$grant=$g->confirm('tenant','user',$token,$i,$p->token());$old=entryFiles($x);Check::same(true,$g->consume('tenant','user',$token,$i,$grant->token()) instanceof SoSecurity\Operation\Permit);
    $x->boundary->run('owned.grants.withdraw',static function()use($x):void{$x->e->pdo->exec('UPDATE account_example SET roles=\'[]\'');});grantNoEffect($x,static function()use($g,$token,$i):void{$g->begin('tenant','user',$token,$i);},'operation.authentication');$x->e->pdo->exec('UPDATE account_example SET roles=\'["editor"]\'');entryRestore($x,$old);grantNoEffect($x,static function()use($g,$token,$i,$grant){return $g->consume('tenant','user',$token,$i,$grant->token());},'account.witness_stale');
});
echo 'PASS native grant pre-effect refusals: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; guards/session/object/fields/capacity, exact SQL and context, role withdrawal and old role/file/proof replay\n";
