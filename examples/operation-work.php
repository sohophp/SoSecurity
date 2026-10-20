<?php
declare(strict_types=1);
namespace SoSecurity\Examples\Operations;
use PDO;
use SoSecurity\Operation\Grants;
use SoSecurity\Operation\Intent;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;

/** Host-owned tables and transaction, authoritative account version, authenticated route/CSRF/schema.
 * operation_accounts(tenant,subject,version,enabled), operation_documents(tenant,id,owner,version,title),
 * operation_receipts(tenant,id,subject,intent_hash,resource_id,created_at), UNIQUE(tenant,id).
 * Account/role/credential changes must advance the same authoritative version checked here.
 * No schema creation, request parsing, commit or rollback on import/call; caller rolls back every failure.
 */
function databaseNow(PDO $pdo): string
{
    if (!$pdo->inTransaction()) { throw new ConfigurationException('Host business transaction required.','operation.transaction'); }
    $driver=$pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
    if ($driver==='sqlite') { return "CAST(strftime('%s','now') AS INTEGER)"; }
    if ($driver==='mysql') { return 'UNIX_TIMESTAMP()'; }
    throw new ConfigurationException('Example supports SQLite/MySQL database clocks.','operation.database');
}
/** Metadata only; caller authenticates the route, then Grants checks the action/owner/fields before disclosure. */
function intent(PDO $pdo,string $scope,string $id,string $title): Intent
{
    if (!preg_match('/\A[A-Za-z0-9_-]{1,64}\z/D',$id) || $title==='' || strlen($title)>200 || !preg_match('//u',$title) || preg_match('/[\x00-\x1f\x7f]/',$title)) {
        throw new ValidationException('Invalid bounded document proposal.','operation.payload');
    }
    $query=$pdo->prepare('SELECT owner,version FROM operation_documents WHERE tenant=:tenant AND id=:id');$query->execute(['tenant'=>$scope,'id'=>$id]);$row=$query->fetch(PDO::FETCH_ASSOC);
    if (!is_array($row)) {throw new SecurityException('Operation resource not accepted.','operation.denied');}
    return new Intent('document.update',new \SoSecurity\Authorization\Resource($scope,'document',$id,(string)$row['version'],['owner'=>$row['owner']]),['title'=>$title],['title']);
}
/** Consume before applying exactly the reviewed title update. Failure burns a consumed grant; never auto-refund. */
function apply(PDO $pdo,Grants $grants,string $scope,string $subject,string $sessionToken,Intent $intent,string $grant,?\SoSecurity\Auth\PasswordRecord $passwordRecord=null): void
{
    $started=time();$clock=databaseNow($pdo);$parameters=$intent->parameters();$resource=$intent->resource();
    if ($intent->action()!=='document.update' || $resource->scope()!==$scope || $resource->type()!=='document' || $intent->fields()!==['title']
        || array_keys($parameters)!==['title'] || !is_string($parameters['title']) || $parameters['title']==='' || strlen($parameters['title'])>200
        || preg_match('/[\x00-\x1f\x7f]/',$parameters['title']) || !preg_match('/\A[1-9][0-9]{0,17}\z/D',$resource->version()) || (int)$resource->version()>=PHP_INT_MAX) {
        throw new ValidationException('Invalid reviewed document-title update.','operation.payload');
    }
    $permit=$grants->consume($scope,$subject,$sessionToken,$intent,$grant);
    if ($permit===null) { throw new SecurityException('Operation authorization not accepted.','operation.denied'); }
    $accountVersion=$permit->account()->version();$credentialPredicate='';$credentialParameters=[];
    if ($passwordRecord!==null) {
        // Compare the actual password-provider identity before using the raw business version in SQL.
        if (!hash_equals($permit->account()->fingerprint(),$passwordRecord->identity()->fingerprint())) { throw new SecurityException('Password account changed.','operation.conflict'); }
        $accountVersion=$passwordRecord->account()->version();$credentialPredicate=' AND password_hash=:password_hash';$credentialParameters=['password_hash'=>$passwordRecord->hash()];
    }
    $receipt=$pdo->prepare('INSERT INTO operation_receipts(tenant,id,subject,intent_hash,resource_id,created_at) VALUES(:tenant,:id,:subject,:intent,:resource,'.$clock.')');
    try {$receipt->execute(['tenant'=>$scope,'id'=>$permit->id(),'subject'=>$permit->account()->subject(),'intent'=>$intent->fingerprint(),'resource'=>$resource->id()]);}
    catch (\PDOException $error) {
        if ($error->getCode()==='23000' || $error->getCode()==='23505') { throw new SecurityException('Operation receipt conflicts with prior execution.','operation.conflict'); }
        throw $error;
    }
    $sql='UPDATE operation_documents SET title=:title,version=version+1 WHERE tenant=:tenant AND id=:id AND owner=:owner AND version=:version'
        .' AND EXISTS(SELECT 1 FROM operation_accounts WHERE tenant=:account_tenant AND subject=:subject AND version=:account_version AND enabled=1'.$credentialPredicate.')'
        .' AND CAST(:deadline AS DECIMAL(20,0))>'.$clock;
    $update=$pdo->prepare($sql);$update->execute(['title'=>$parameters['title'],'tenant'=>$scope,'id'=>$resource->id(),'owner'=>$permit->account()->subject(),'version'=>(int)$resource->version(),
        'account_tenant'=>$scope,'subject'=>$permit->account()->subject(),'account_version'=>$accountVersion,'deadline'=>$permit->expiresAt()]+$credentialParameters);
    if ($update->rowCount()!==1) { throw new SecurityException('Operation resource, account version or database deadline changed.','operation.conflict'); }
    // A fresh query covers statement-start clocks, slow triggers and lock/transport waits before returning.
    $raw=$pdo->query('SELECT '.$clock)->fetchColumn();$now=time();
    if ((!is_int($raw) && !is_string($raw)) || !preg_match('/\A[0-9]{1,19}\z/D',(string)$raw) || (string)(int)$raw!==(string)$raw || (int)$raw<0 || $now<$started) { throw new SecurityException('Operation business clock unavailable.','operation.clock'); }
    if ($now>=$permit->expiresAt() || (int)$raw>=$permit->expiresAt()) { throw new SecurityException('Operation expired during business SQL; roll back.','operation.expired'); }
}
