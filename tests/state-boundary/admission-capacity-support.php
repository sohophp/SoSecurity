<?php
declare(strict_types=1);
require_once __DIR__.'/hmac-native-support.php';
require_once dirname(__DIR__,2).'/examples/StateDocumentLinks.php';
require_once __DIR__.'/reset-native-support.php';
function capacityCase(callable $body):void
{
    hmacCase(static function(EntryEnvironment $x)use($body):void{$x->boundary->run('owned.capacity.roles',static function()use($x):void{$x->e->pdo->exec('UPDATE account_example SET roles=\'["editor"]\' WHERE scope=\'tenant\' AND subject=\'user\'');});$body($x,$x->login()->credential()->token());},8);
}
function capacityIssuer(EntryEnvironment $x,string $session,string $kind,?callable $guard=null):Closure
{
    if($kind==='links'){$service=new SoSecurity\Link\Links($x->store,$x->e->keys,'managed-test',new SoSecurity\Link\Policy('https://capacity.example.test'),$guard??static function():bool{return true;},$x->e->clock,$x->boundary,permissionPolicy($x),$x->sessions,new SoSecurity\Authorization\Authorizer($x->provider,SoSecurity\Account\Example\StateDocumentLinks::policy()));return static function()use($x,$service,$session){return $service->issueFor('tenant','user',$session,$x->e->pdo,SoSecurity\Account\Example\StateDocuments::definition(),static function(PDO $pdo):SoSecurity\Link\Target{return SoSecurity\Account\Example\StateDocumentLinks::target($pdo,'tenant','owned');},true);};}if($kind==='reset'){$service=resetNative($x,$guard);return static function()use($service){return $service->issueFor('tenant','user');};}if($kind==='grants'){$service=nativeGrants($x,$guard);return static function()use($x,$service,$session){return $service->begin('tenant','user',$session,grantIntent($x->e->pdo));};}$service=nativeApi($x,$guard);return static function()use($service,$session){return $service->issue('tenant','user',$session,'Physical capacity',['records:read'],300);};
}
function capacityFill(EntryEnvironment $x,int $limit=8):array
{
    $fill=[];$i=0;while(count(glob($x->e->directory.'/factors/*.json'))<$limit){$key='owned-capacity-filler:'.(++$i);$x->boundary->run('owned.capacity.fill',static function()use($x,$key,$i):void{$x->store->transact($key,static function()use($i):SoSecurity\Storage\Change{return new SoSecurity\Storage\Change(['owned_filler'=>$i],$i===1?1:0,null);});});$fill[]=$key;}Check::same($limit,count(glob($x->e->directory.'/factors/*.json')));Check::same('current',$x->inspect()['status']);return $fill;
}
function capacityRelease(EntryEnvironment $x,string $key):void{$x->boundary->run('owned.capacity.release',static function()use($x,$key):void{$x->store->transact($key,static function():SoSecurity\Storage\Change{return new SoSecurity\Storage\Change(null,0,null);});});}
