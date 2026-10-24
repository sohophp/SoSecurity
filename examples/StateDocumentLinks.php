<?php
declare(strict_types=1);
namespace SoSecurity\Account\Example;
use PDO;
use SoSecurity\Authorization\Resource;
use SoSecurity\Authorization\RolePolicy;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Link\Links;
use SoSecurity\Link\Target;
use SoSecurity\Link\VerifiedLink;
/** Complete business table declaration is StateDocuments::definition(); load both example classes explicitly. */
final class StateDocumentLinks
{
    public static function policy():RolePolicy
    {
        $rules=[];foreach(['issue'=>['target','one_time','ttl','binding'],'all'=>[],'revoke'=>['id'],'revoke_all'=>[]] as $action=>$fields){$rules['links.'.$action]=['type'=>'document','roles'=>['editor'],'fields'=>$fields,'owner_attribute'=>'owner'];}return new RolePolicy($rules);
    }
    public static function target(PDO $pdo,string $scope,string $id,?int $expectedVersion=null):Target
    {
        if($id===''||strlen($id)>256||preg_match('//u',$id)!==1){throw new ValidationException('Use a bounded document id.','documents.input');}$q=$pdo->prepare('SELECT owner,version FROM state_example_documents WHERE scope=? AND id=?');$q->execute([$scope,$id]);$row=$q->fetch(PDO::FETCH_ASSOC);$q->closeCursor();if(!$row||($expectedVersion!==null&&(string)$row['version']!==(string)$expectedVersion)){throw new SecurityException('Document missing or version changed.','documents.conflict');}
        $version=(int)$row['version'];if((string)$version!==(string)$row['version']||$version<1||$version===PHP_INT_MAX){throw new SecurityException('Document version is invalid or exhausted.','documents.conflict');}
        return new Target('documents.rename',new Resource($scope,'document',$id,(string)$row['version'],['owner'=>$row['owner']]),'/documents/rename',['id'=>$id],'POST');
    }
    /** Return null for a rejected link; SQL, proof and final witness success must precede any response output. */
    public static function rename(Links $links,PDO $pdo,string $scope,string $id,string $url,string $title):?int
    {
        if($title===''||strlen($title)>1024||preg_match('//u',$title)!==1){throw new ValidationException('Use a bounded UTF-8 title.','documents.input');}
        return $links->withVerification($scope,$pdo,StateDocuments::definition(),static function(PDO $connection)use($scope,$id):Target{return self::target($connection,$scope,$id);},$url,static function(PDO $connection,VerifiedLink $proof)use($title):int{
            $r=$proof->target()->resource();$version=(int)$r->version();if($version<1||$version===PHP_INT_MAX){throw new SecurityException('Document version exhausted.','documents.conflict');}$q=$connection->prepare('UPDATE state_example_documents SET title=?,version=? WHERE scope=? AND id=? AND owner=? AND version=?');$q->execute([$title,$version+1,$r->scope(),$r->id(),$r->attributes()['owner'],$version]);$changed=$q->rowCount();$q->closeCursor();if($changed!==1){throw new SecurityException('Document changed during update.','documents.conflict');}return $version+1;
        },'POST');
    }
}
