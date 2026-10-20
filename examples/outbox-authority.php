<?php
declare(strict_types=1);
namespace SoSecurity\Examples\Outbox;

use PDO;
use SoSecurity\Exception\SecurityException;

// Optional host-owned current authority. It is never copied from a restored business database.
/** @return never */
function authorityDenied():void {throw new SecurityException('Current independent authority is unavailable.','outbox_example.authority');}
function authorityIdentity(string $path):string
{
    clearstatcache(true,$path);$stat=@stat($path);if(!is_array($stat)){authorityDenied();}return $stat['dev'].':'.$stat['ino'];
}
function authoritySetup(array $settings):array
{
    if(!array_key_exists('authority_database',$settings)){$settings['authority_database']=null;return $settings;}
    if(!class_exists('SQLite3',false)){authorityDenied();}
    $path=privateFile($settings['authority_database'],$settings['document_root']);$identity=authorityIdentity($path);
    foreach(['database','checkpoint_database','checkpoint_lock','configuration_file','seals','wire_keys','idempotency_keys','resolution_keys'] as $field){if(is_string($settings[$field] ?? null)&&authorityIdentity($settings[$field])===$identity){authorityDenied();}}
    $settings['authority_database']=$path;$settings['authority_identity']=$identity;return $settings;
}
/** @phpstan-impure Rechecks the private deployment snapshot and the current authority file. */
function authorityDeployment(array $settings):?string
{
    try{
    $current=jsonFile(privateFile($settings['configuration_file'],$settings['document_root']));$known=$settings['authority_database'] ?? null;
    if(!array_key_exists('authority_database',$current)){if($known!==null){authorityDenied();}return null;}
    if(!is_string($current['authority_database'])||$current['authority_database']!==$known||!class_exists('SQLite3',false)){authorityDenied();}
    $path=privateFile($known,$settings['document_root']);if(authorityIdentity($path)!==($settings['authority_identity'] ?? null)){authorityDenied();}
    return $path;
    }catch(\Throwable $failure){authorityDenied();}
}
/** A fresh read-only connection per decision avoids retained authority transaction snapshots.
 * @phpstan-impure
 */
function authorityRow(array $settings,string $sql,array $parameters):?array
{
    $path=authorityDeployment($settings);
    if($path===null){$q=$settings['pdo']->prepare($sql.' LIMIT 2');$q->execute($parameters);$rows=$q->fetchAll(PDO::FETCH_ASSOC);$q->closeCursor();if(count($rows)>1){authorityDenied();}return $rows[0] ?? null;}
    $db=null;$statement=null;$result=null;
    try{
        // SQLite3 exposes OPEN_READONLY on PHP 7.2 too; PDO's equivalent flags are newer.
        $db=new \SQLite3($path,SQLITE3_OPEN_READONLY);$db->enableExceptions(true);$db->busyTimeout(1000);
        $statement=$db->prepare($sql.' LIMIT 2');if($statement===false){authorityDenied();}
        foreach($parameters as $name=>$value){if(!is_string($name)||!is_string($value)||!$statement->bindValue(':'.$name,$value,SQLITE3_TEXT)){authorityDenied();}}
        $result=$statement->execute();if($result===false){authorityDenied();}
        // Do not step an empty result again: SQLite can reset and execute it in a later state.
        $row=$result->fetchArray(SQLITE3_ASSOC);if($row!==false&&$result->fetchArray(SQLITE3_ASSOC)!==false){authorityDenied();}
        if(authorityDeployment($settings)!==$path){authorityDenied();}return $row===false?null:$row;
    }catch(\Throwable $failure){authorityDenied();}
    finally{if($result instanceof \SQLite3Result){$result->finalize();}if($statement instanceof \SQLite3Stmt){$statement->close();}if($db instanceof \SQLite3){$db->close();}}
}

/** One statement binds all required roles and the current object association to one authority snapshot.
 * @phpstan-impure
 */
function authorityAllows(array $settings,array $roles,?string $owner=null,bool $historical=false,?string $actor=null):bool
{
    if(count($roles)<1||count($roles)>8||array_values($roles)!==$roles){authorityDenied();}
    foreach($roles as $role){if(!is_string($role)||!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$role)){authorityDenied();}}
    $actor=$actor ?? $settings['actor'];identifier($actor);$parameters=['actor'=>$actor];
    $sql="SELECT a.version,a.roles FROM main.outbox_example_actors a";
    if($owner!==null){identifier($owner);$sql.=" INNER JOIN main.outbox_example_routes r ON r.publisher=:publisher AND r.tenant=:tenant INNER JOIN main.outbox_example_owners o ON o.subject=:owner";$parameters+=['publisher'=>PUBLISHER,'tenant'=>SCOPE,'owner'=>$owner];}
    $sql.=" WHERE a.subject=:actor AND typeof(a.enabled)='integer' AND a.enabled=1 AND typeof(a.version)='text' AND length(CAST(a.version AS BLOB)) BETWEEN 1 AND 64 AND typeof(a.roles)='text' AND length(CAST(a.roles AS BLOB))<=1024";
    if($owner!==null){$enabled=$historical?' IN (0,1)':'=1';$sql.=" AND typeof(r.enabled)='integer' AND r.enabled".$enabled." AND typeof(o.enabled)='integer' AND o.enabled".$enabled;}
    $row=authorityRow($settings,$sql,$parameters);
    if(!is_array($row)||($actor===$settings['actor']&&!hash_equals($settings['version'],$row['version']))){return false;}
    identifier($row['version']);$current=json_decode($row['roles'],true,4);
    if(!is_array($current)||array_values($current)!==$current||count($current)>8){return false;}
    foreach($current as $role){if(!is_string($role)||!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$role)){return false;}}
    foreach($roles as $role){if(!in_array($role,$current,true)){return false;}}return true;
}
