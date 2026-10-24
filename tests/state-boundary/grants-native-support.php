<?php
declare(strict_types=1);
require __DIR__.'/api-business-support.php';
require dirname(__DIR__,2).'/examples/StateDocumentGrants.php';
use SoSecurity\Operation\Grants;
use SoSecurity\Operation\Intent;
use SoSecurity\Operation\Permit;
use SoSecurity\Account\Example\StateDocuments;
function grantCase(callable $body):void
{
    managedCase(static function(ManagedEnvironment $e)use($body):void{
        $mysql=$e->pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql';$e->pdo->exec('DROP TABLE IF EXISTS state_example_documents');$e->pdo->exec($mysql?'CREATE TABLE state_example_documents(scope VARBINARY(256) NOT NULL,id VARBINARY(256) NOT NULL,owner VARBINARY(256) NOT NULL,version BIGINT NOT NULL,title VARBINARY(1024) NOT NULL,PRIMARY KEY(scope,id)) ENGINE=InnoDB':'CREATE TABLE state_example_documents(scope TEXT NOT NULL,id TEXT NOT NULL,owner TEXT NOT NULL,version INTEGER NOT NULL,title TEXT NOT NULL,PRIMARY KEY(scope,id))');$q=$e->pdo->prepare('INSERT INTO state_example_documents VALUES(?,?,?,?,?)');foreach([['tenant','owned','user',1,'Original'],['tenant','foreign','other',1,'Foreign']] as $r){$q->execute($r);}$q->closeCursor();$e->pdo->exec('UPDATE account_example SET roles=\'["editor"]\'');
        $x=new EntryEnvironment($e,false,3,null,30000,null,str_repeat('c',64),StateDocuments::definition());$body($x,$x->login()->credential()->token());
    });
}
function nativeGrants(EntryEnvironment $x,?callable $guard=null,?SoSecurity\Operation\Policy $policy=null):Grants
{
    return new Grants($x->store,$x->sessions,new SoSecurity\Authorization\Authorizer($x->provider,StateDocuments::policy()),$guard??static function():bool{return true;},$policy,$x->e->clock,$x->boundary,permissionPolicy($x));
}
function grantIntent(PDO $pdo,string $title='Grant title',string $id='owned'):Intent
{
    $q=$pdo->prepare('SELECT owner,version FROM state_example_documents WHERE scope=? AND id=?');$q->execute(['tenant',$id]);$r=$q->fetch(PDO::FETCH_ASSOC);$q->closeCursor();if(!$r){throw new RuntimeException('Owned test resource missing.');}return new Intent('documents.write',new SoSecurity\Authorization\Resource('tenant','document',$id,(string)$r['version'],['owner'=>$r['owner']]),['title'=>$title],['title']);
}
function grantReauth(EntryEnvironment $x,string $token):string
{
    $first=$x->auth->password('tenant','owned-grant-reauth','owned@example.test',$x->e->password,'',$token);Check::same('mfa_required',$first->status());$next=$x->auth->secondFactor('tenant','owned-grant-reauth',$first->challenge(),normalFactor($x->e));Check::same('authenticated',$next->status());Check::same(SoSecurity\Auth\SessionRegistry::reference($token)['id'],$next->credential()->id());Check::same(false,$token===$next->credential()->token());return $next->credential()->token();
}
function grantNoEffect(EntryEnvironment $x,callable $attempt,?string $reason=null,$expected=null):void
{
    $rows=businessRows($x);nativeApiNoEffect($x,$attempt,$reason,$expected);Check::same($rows,businessRows($x));
}
function grantWrite(PDO $pdo,Permit $permit):int
{
    $i=$permit->intent();$r=$i->resource();$v=(int)$r->version();$q=$pdo->prepare('UPDATE state_example_documents SET title=?,version=? WHERE scope=? AND id=? AND version=? AND owner=?');$q->execute([$i->parameters()['title'],$v+1,$r->scope(),$r->id(),$v,$permit->account()->subject()]);$n=$q->rowCount();$q->closeCursor();Check::same(1,$n);return $v+1;
}
function grantExecute(EntryEnvironment $x,Grants $g,string $token,string $grant,callable $work,?callable $prepare=null)
{
    return $g->execute('tenant','user',$token,$grant,$x->e->pdo,StateDocuments::definition(),$prepare??static function(PDO $pdo):Intent{return grantIntent($pdo);},$work);
}
function grantExpected(EntryEnvironment $x,Grants $g,string $method,string $token,?Intent $intent,?array $reference,array $tables=[]):array
{
    $view=apiIntentIdentity($x,'user',$token);$j=JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE;$policy=hash('sha256','SoSecurity.Operation.Admission.Policy.1.'.json_encode([permissionPolicy($x)->binding(),$g->policy()->fingerprint(),StateDocuments::policy()->fingerprint()],$j));$request=hash('sha256','SoSecurity.Operation.Admission.Request.1.'.json_encode(['entry'=>$method,'actor'=>'user','identity'=>$view['fingerprint'],'session'=>SoSecurity\Auth\SessionRegistry::reference($token),'intent'=>$intent===null?null:$intent->fingerprint(),'reference'=>$reference,'tables'=>$tables,'observed'=>$x->source->digest(),'policy'=>$policy],$j));$actor=hash('sha256',json_encode(['SoSecurity.Account.StateOperation.Subject.1','tenant','user'],$j));return ['kind'=>'authorized','action'=>'operations.'.($method==='revokeAll'?'revoke_all':$method),'scope'=>hash('sha256',json_encode(['SoSecurity.Account.StateOperation.Scope.1','tenant'],$j)),'actor'=>$actor,'target'=>$actor,'permission'=>$request,'policy'=>$policy,'authorized_at'=>$x->e->clock->time];
}
