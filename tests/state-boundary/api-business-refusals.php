<?php
declare(strict_types=1);
require __DIR__.'/api-business-support.php';
use SoSecurity\Account\Example\StateDocuments;
businessCase(static function(EntryEnvironment $x,SoSecurity\Api\CredentialRegistry $api,string $header):void{
    $rows=businessRows($x);$calls=0;$work=static function()use(&$calls):void{++$calls;};
    nativeApiNoEffect($x,static function()use($x,$api,$header,$work){businessRun($x,$api,$header,$work,static function(PDO $pdo,SoSecurity\Api\VerifiedCredential $proof):SoSecurity\Operation\Intent{return new SoSecurity\Operation\Intent('documents.write',businessIntent($pdo,$proof)->resource(),['owner'=>'other'],['owner']);});},'authorization.denied');
    foreach(['wrong-pdo','wrong-table','missing-column','empty-tables','foreign-resource','nested','pdo-transaction','sql-transaction'] as $mode){
        $before=permissionState($x);$persists=0;$x->persistHook=static function()use(&$persists):bool{++$persists;return true;};$pdo=$mode==='wrong-pdo'?$x->e->observer:$x->e->pdo;$tables=StateDocuments::definition();$prepare='businessIntent';
        if($mode==='wrong-table'){$tables['undeclared']=$tables['state_example_documents'];}if($mode==='missing-column'){unset($tables['state_example_documents']['columns']['title']);}if($mode==='empty-tables'){$tables=[];}
        if($mode==='foreign-resource'){$prepare=static function():SoSecurity\Operation\Intent{return new SoSecurity\Operation\Intent('documents.write',new SoSecurity\Authorization\Resource('foreign','document','owned','1',['owner'=>'user']),[],['title']);};}
        $invoke=static function()use($api,$header,$pdo,$tables,$prepare,$work){return $api->withAuthorization('tenant',$header,'records:write',$pdo,$tables,StateDocuments::policy(),$prepare,$work);};
        if($mode==='pdo-transaction'){$pdo->beginTransaction();}elseif($mode==='sql-transaction'){$pdo->exec('BEGIN');}
        try{if($mode==='nested'){$x->boundary->run('owned.nested.business',static function()use($invoke):void{Check::throws(SoSecurity\Exception\ConfigurationException::class,$invoke);});}else{Check::throws(SoSecurity\Exception\ConfigurationException::class,$invoke);}}
        finally{if($mode==='pdo-transaction'){$pdo->rollBack();}elseif($mode==='sql-transaction'){$pdo->exec('ROLLBACK');}$x->persistHook=null;}
        if($mode==='nested'){Check::same(2,$persists);}else{Check::same(0,$persists);Check::same($before,permissionState($x));}Check::same($rows,businessRows($x));Check::same(0,$calls);
    }
    nativeApiNoEffect($x,static function()use($x,$api,$header,$work){return $api->withAuthorization('tenant',$header,'records:write',$x->e->pdo,StateDocuments::definition(),new SoSecurity\Authorization\RolePolicy(['documents.write'=>['type'=>'document','roles'=>['admin'],'fields'=>['title']]]),'businessIntent',$work);},'authorization.denied');
    nativeApiNoEffect($x,static function()use($x,$api,$header,$work){businessRun($x,$api,$header,$work,static function():void{throw new RuntimeException('PRIVATE-SQL-DETAIL');});},'api_credentials.business_unavailable');
    $at=$x->e->clock->time;
    nativeApiNoEffect($x,static function()use($x,$api,$header,$work){return businessRun($x,$api,$header,$work,static function(PDO $pdo,SoSecurity\Api\VerifiedCredential $proof)use($x):SoSecurity\Operation\Intent{$intent=businessIntent($pdo,$proof);$x->e->clock->time=$proof->expiresAt();return $intent;});});$x->e->clock->time=$at;
    $before=permissionState($x);$prepare=static function(PDO &$pdo,SoSecurity\Api\VerifiedCredential &$proof):SoSecurity\Operation\Intent{$intent=businessIntent($pdo,$proof);$pdo=null;$proof=null;return $intent;};Check::same(2,businessRun($x,$api,$header,'businessWrite',$prepare));Check::same(true,$before!==permissionState($x));
});
echo 'PASS native business admission refusal: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; field/graph/table/resource/nested/host-transaction checks, detached callback arguments\n";
