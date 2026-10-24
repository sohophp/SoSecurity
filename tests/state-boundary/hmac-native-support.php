<?php
declare(strict_types=1);
require_once __DIR__.'/grants-native-support.php';
function hmacKey(string $secret='n'):SoSecurity\Api\SigningKey{return new SoSecurity\Api\SigningKey('service-key',str_repeat($secret,32),'user',['documents:write']);}
function hmacPolicy():SoSecurity\Api\SignaturePolicy{return new SoSecurity\Api\SignaturePolicy(['origin'=>'https://api.example.test','clock_skew'=>0]);}
function hmacCase(callable $body,int $cap=100000):void
{
    managedCase(static function(ManagedEnvironment $e)use($body,$cap):void{
        $mysql=$e->pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql';$e->pdo->exec('DROP TABLE IF EXISTS state_example_documents');$e->pdo->exec($mysql?'CREATE TABLE state_example_documents(scope VARBINARY(256) NOT NULL,id VARBINARY(256) NOT NULL,owner VARBINARY(256) NOT NULL,version BIGINT NOT NULL,title VARBINARY(1024) NOT NULL,PRIMARY KEY(scope,id)) ENGINE=InnoDB':'CREATE TABLE state_example_documents(scope TEXT NOT NULL,id TEXT NOT NULL,owner TEXT NOT NULL,version INTEGER NOT NULL,title TEXT NOT NULL,PRIMARY KEY(scope,id))');$q=$e->pdo->prepare('INSERT INTO state_example_documents VALUES(?,?,?,?,?)');foreach([['tenant','owned','user',1,'Original'],['tenant','foreign','other',1,'Foreign']] as $r){$q->execute($r);}$q->closeCursor();
        $ring=new SoSecurity\Api\KeyRing([hmacKey()]);$x=new EntryEnvironment($e,false,3,null,30000,null,str_repeat('f',64),SoSecurity\Account\Example\StateDocuments::definition(),$ring,$cap);$body($x);
    });
}
function nativeHmac(EntryEnvironment $x,?callable $guard=null):SoSecurity\Api\HmacVerifier
{
    $guard=$guard??static function(string $entry,SoSecurity\Api\Identity $identity,?SoSecurity\Operation\Intent $intent):bool{return $intent===null||($identity->allows('documents:write')&&$identity->subject()===($intent->resource()->attributes()['owner']??null));};return new SoSecurity\Api\HmacVerifier(hmacPolicy(),$x->signingKeys,new SoSecurity\Api\NonceStore($x->store,$x->e->clock),$x->e->clock,$x->boundary,permissionPolicy($x),$x->sessions,$x->store,$x->sources['keys'],'hmac-keys',$guard,'managed-test');
}
function hmacRequest(EntryEnvironment $x,?SoSecurity\Api\SigningKey $key=null,int $ttl=60):array
{
    $url='https://api.example.test/documents/owned';$body='{"title":"HMAC title"}';$headers=(new SoSecurity\Api\HmacSigner(hmacPolicy(),$key??hmacKey(),$x->e->clock))->sign('POST',$url,$body,'application/json',$ttl);return ['method'=>'POST','url'=>$url,'body'=>$body,'headers'=>$headers];
}
function hmacVerify(SoSecurity\Api\HmacVerifier $v,array $r):?SoSecurity\Api\Identity{return $v->verifyFor('tenant',$r['method'],$r['url'],$r['body'],$r['headers'],'documents:write');}
function hmacExecute(EntryEnvironment $x,SoSecurity\Api\HmacVerifier $v,array $r,callable $work,?callable $prepare=null)
{
    return $v->withVerification('tenant',$x->e->pdo,SoSecurity\Account\Example\StateDocuments::definition(),$prepare??static function(PDO $pdo):SoSecurity\Operation\Intent{return grantIntent($pdo,'HMAC title');},$r['method'],$r['url'],$r['body'],$r['headers'],$work,'documents:write');
}
function hmacWrite(PDO $pdo,SoSecurity\Api\Identity $identity,SoSecurity\Operation\Intent $intent):int
{
    $r=$intent->resource();$version=(int)$r->version();$q=$pdo->prepare('UPDATE state_example_documents SET title=?,version=? WHERE scope=? AND id=? AND owner=? AND version=?');$q->execute([$intent->parameters()['title'],$version+1,$r->scope(),$r->id(),$identity->subject(),$version]);Check::same(1,$q->rowCount());$q->closeCursor();return $version+1;
}
function hmacExpected(EntryEnvironment $x,string $entry,array $r,string $observed,?SoSecurity\Operation\Intent $intent=null):array
{
    $j=JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE;$policy=hash('sha256','SoSecurity.Api.Hmac.Native.Policy.1.'.json_encode([permissionPolicy($x)->binding(),hmacPolicy()->options(),$x->sources['keys']->fingerprint(),$x->signingKeys->stateDigest(),3600,'managed-test'],$j));$id=hmacKey()->identity();$identity=hash('sha256',json_encode([$id->id(),$id->subject(),$id->scopes()],$j));$signed=SoSecurity\Api\SignatureProfile::parse($r['headers']);$names=$intent===null?[]:array_keys(SoSecurity\Account\Example\StateDocuments::definition());sort($names);$request=hash('sha256','SoSecurity.Api.Hmac.Native.Request.1.'.json_encode(['entry'=>$entry,'method'=>$r['method'],'url'=>hash('sha256',$r['url']),'body'=>hash('sha256',$r['body']),'signature'=>hash('sha256',SoSecurity\Api\SignatureProfile::base($r['method'],$r['url'],$signed['digest'],$signed['type'],$signed['parameters']).$signed['mac']),'required_scope'=>'documents:write','identity'=>$identity,'intent'=>$intent===null?null:$intent->fingerprint(),'tables'=>$names,'observed'=>$observed,'policy'=>$policy],$j));return ['kind'=>'authorized','action'=>'hmac.'.$entry,'scope'=>hash('sha256',json_encode(['SoSecurity.Account.StateOperation.Scope.1','tenant'],$j)),'actor'=>hash('sha256',json_encode(['SoSecurity.Account.StateOperation.SigningIdentity.1','tenant',$identity],$j)),'target'=>$intent===null?$identity:$intent->fingerprint(),'permission'=>$request,'policy'=>$policy,'authorized_at'=>$x->e->clock->time];
}
