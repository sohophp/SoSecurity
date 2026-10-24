<?php
declare(strict_types=1);
namespace SoSecurity\Account\Example;
use PDO;
use SoSecurity\Auth\VerifiedSession;
use SoSecurity\Authorization\Resource;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Operation\Grants;
use SoSecurity\Operation\Intent;
use SoSecurity\Operation\Permit;
/** Host consumer: configure the native grants with StateDocuments::policy() and declare its table first. */
final class StateDocumentGrants
{
    public static function intent(PDO $pdo,string $scope,string $id,int $version,string $title):Intent
    {
        if($id===''||strlen($id)>256||!preg_match('//u',$id)||$version<1||$version===PHP_INT_MAX||$title===''||strlen($title)>1024||!preg_match('//u',$title)){throw new ValidationException('Use bounded document input and version.','documents.input');}
        $q=$pdo->prepare('SELECT owner,version FROM state_example_documents WHERE scope=? AND id=?');$q->execute([$scope,$id]);$row=$q->fetch(PDO::FETCH_ASSOC);$q->closeCursor();if(!$row||(string)$row['version']!==(string)$version){throw new SecurityException('Document missing or version changed.','documents.conflict');}
        return new Intent('documents.write',new Resource($scope,'document',$id,(string)$version,['owner'=>$row['owner']]),['title'=>$title],['title']);
    }
    /** Confirmation and grant are prepared after actual login/reauthentication. Only this call may commit the update. */
    public static function rename(Grants $grants,PDO $pdo,string $scope,string $subject,string $session,string $grant,string $id,int $version,string $title):?int
    {
        return $grants->execute($scope,$subject,$session,$grant,$pdo,StateDocuments::definition(),static function(PDO $connection,VerifiedSession $current)use($scope,$id,$version,$title):Intent{return self::intent($connection,$scope,$id,$version,$title);},static function(PDO $connection,Permit $permit):int{
            $i=$permit->intent();$r=$i->resource();$v=(int)$r->version();$q=$connection->prepare('UPDATE state_example_documents SET title=?,version=? WHERE scope=? AND id=? AND version=? AND owner=?');$q->execute([$i->parameters()['title'],$v+1,$r->scope(),$r->id(),$v,$permit->account()->subject()]);$count=$q->rowCount();$q->closeCursor();if($count!==1){throw new SecurityException('Document changed during the owned unit.','documents.conflict');}return $v+1;
        });
    }
}
