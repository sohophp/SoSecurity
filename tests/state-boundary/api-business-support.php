<?php
declare(strict_types=1);
require __DIR__.'/api-intent-support.php';
require_once dirname(__DIR__,2).'/examples/StateDocuments.php';
use SoSecurity\Account\Example\StateDocuments;
function businessCase(callable $body,int $format=2):void
{
    managedCase(static function(ManagedEnvironment $e)use($body,$format):void{
        $e->pdo->exec('DROP TABLE IF EXISTS state_example_documents');$mysql=$e->pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql';
        $e->pdo->exec($mysql?'CREATE TABLE state_example_documents(scope VARBINARY(256) NOT NULL,id VARBINARY(256) NOT NULL,owner VARBINARY(256) NOT NULL,version BIGINT NOT NULL,title VARBINARY(1024) NOT NULL,PRIMARY KEY(scope,id)) ENGINE=InnoDB':'CREATE TABLE state_example_documents(scope TEXT NOT NULL,id TEXT NOT NULL,owner TEXT NOT NULL,version INTEGER NOT NULL,title TEXT NOT NULL,PRIMARY KEY(scope,id))');
        $q=$e->pdo->prepare('INSERT INTO state_example_documents VALUES(?,?,?,?,?)');foreach([['tenant','owned','user',1,'Original'],['tenant','foreign','other',1,'Foreign'],['foreign','owned','user',1,'Other scope']] as $row){$q->execute($row);}$q->closeCursor();$e->pdo->exec('UPDATE account_example SET roles=\'["editor"]\'');
        $x=new EntryEnvironment($e,false,$format,null,30000,null,$format===3?str_repeat('b',64):null,StateDocuments::definition());$session=$x->login()->credential()->token();$api=nativeApi($x);$bearer=$api->issue('tenant','user',$session,'Owned business',['records:read','records:write'],600)->token();$body($x,$api,'Bearer '.$bearer);
    });
}
function businessRows(EntryEnvironment $x):array{return $x->e->observer->query('SELECT * FROM state_example_documents ORDER BY scope,id')->fetchAll(PDO::FETCH_ASSOC);}
function businessIntent(PDO $pdo,SoSecurity\Api\VerifiedCredential $proof):SoSecurity\Operation\Intent
{
    $q=$pdo->query("SELECT owner,version FROM state_example_documents WHERE scope='tenant' AND id='owned'");$row=$q->fetch(PDO::FETCH_ASSOC);$q->closeCursor();return new SoSecurity\Operation\Intent('documents.write',new SoSecurity\Authorization\Resource('tenant','document','owned',(string)$row['version'],['owner'=>$row['owner']]),['title'=>'Changed'],['title']);
}
function businessWrite(PDO $pdo,SoSecurity\Api\VerifiedCredential $proof,SoSecurity\Operation\Intent $intent):int
{
    $q=$pdo->prepare('UPDATE state_example_documents SET title=?,version=version+1 WHERE scope=? AND id=? AND version=? AND owner=?');$r=$intent->resource();$q->execute([$intent->parameters()['title'],$r->scope(),$r->id(),(int)$r->version(),$proof->account()->subject()]);$count=$q->rowCount();$q->closeCursor();Check::same(1,$count);return (int)$r->version()+1;
}
function businessRun(EntryEnvironment $x,SoSecurity\Api\CredentialRegistry $api,string $header,callable $work,?callable $prepare=null)
{
    return $api->withAuthorization('tenant',$header,'records:write',$x->e->pdo,StateDocuments::definition(),StateDocuments::policy(),$prepare??'businessIntent',$work);
}
