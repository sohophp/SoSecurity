<?php
declare(strict_types=1);
namespace SoSecurity\Account\Example;

use PDO;
use SoSecurity\Api\CredentialRegistry;
use SoSecurity\Api\VerifiedCredential;
use SoSecurity\Authorization\Resource;
use SoSecurity\Authorization\RolePolicy;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Operation\Intent;

/** Host example: provision and declare the table before witness initialization; every writer shares that witness. */
final class StateDocuments
{
    public static function definition():array
    {
        return ['state_example_documents'=>['columns'=>['scope'=>'bytes:256','id'=>'bytes:256','owner'=>'bytes:256','version'=>'int','title'=>'bytes:1024'],'primary'=>['scope','id']]];
    }
    public static function policy():RolePolicy
    {
        return new RolePolicy(['documents.write'=>['type'=>'document','roles'=>['editor'],'fields'=>['title'],'owner_attribute'=>'owner']]);
    }
    /** Null means bearer admission failed; conflicts and authorization errors throw before any business write. */
    public static function rename(CredentialRegistry $api,PDO $pdo,string $scope,$authorization,string $id,int $version,string $title):?int
    {
        if($id===''||strlen($id)>256||!preg_match('//u',$id)||$version<1||$version===PHP_INT_MAX||$title===''||strlen($title)>1024||!preg_match('//u',$title)){
            throw new ValidationException('Use a bounded document id, version and UTF-8 title.','documents.input');
        }
        return $api->withAuthorization($scope,$authorization,'records:write',$pdo,self::definition(),self::policy(),static function(PDO $connection,VerifiedCredential $proof)use($scope,$id,$version,$title):Intent{
            $q=$connection->prepare('SELECT owner,version FROM state_example_documents WHERE scope=:scope AND id=:id');$q->execute(['scope'=>$scope,'id'=>$id]);$row=$q->fetch(PDO::FETCH_ASSOC);$q->closeCursor();
            if(!$row||(string)$row['version']!==(string)$version){throw new SecurityException('Document is missing or its version changed.','documents.conflict');}
            return new Intent('documents.write',new Resource($scope,'document',$id,(string)$version,['owner'=>$row['owner']]),['title'=>$title],['title']);
        },static function(PDO $connection,VerifiedCredential $proof,Intent $intent):int{
            $r=$intent->resource();$version=(int)$r->version();$q=$connection->prepare('UPDATE state_example_documents SET title=:title,version=:next WHERE scope=:scope AND id=:id AND owner=:owner AND version=:version');
            $q->execute(['title'=>$intent->parameters()['title'],'next'=>$version+1,'scope'=>$r->scope(),'id'=>$r->id(),'owner'=>$proof->account()->subject(),'version'=>$version]);$count=$q->rowCount();$q->closeCursor();
            if($count!==1){throw new SecurityException('Document changed during the owned business unit.','documents.conflict');}return $version+1;
        });
    }
}
