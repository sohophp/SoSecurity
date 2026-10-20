<?php
declare(strict_types=1);
// Synthetic authentication only for shared-ledger contention. Native password/TOTP is tested over HTTP.
function concurrentOperations(SoSecurity\Storage\AtomicStore $store,TestClock $clock): array
{
    $provider=new SoSecurity\Auth\CallbackIdentityProvider(static function () {return null;},static function (string $scope,string $subject) {
        return $scope==='operation-concurrency'&&$subject==='worker' ? new SoSecurity\Auth\Account($scope,$subject,'1',true,['editor']) : null;
    });
    $sessions=new SoSecurity\Auth\SessionRegistry($store,$provider,null,$clock,600,1200,4);
    $authorizer=new SoSecurity\Authorization\Authorizer($provider,new SoSecurity\Authorization\RolePolicy(['document.update'=>['type'=>'document','roles'=>['editor'],'fields'=>['title'],'owner_attribute'=>'owner']]));
    $grants=new SoSecurity\Operation\Grants($store,$sessions,$authorizer,static function ():bool {return true;},new SoSecurity\Operation\Policy(300,8,900),$clock);
    $intent=new SoSecurity\Operation\Intent('document.update',new SoSecurity\Authorization\Resource('operation-concurrency','document','a','1',['owner'=>'worker']),['title'=>'Shared test proposal'],['title']);
    return ['provider'=>$provider,'sessions'=>$sessions,'grants'=>$grants,'intent'=>$intent];
}
function concurrentOperationProof(array $services,?string $token=null): SoSecurity\Auth\SessionCredential
{
    $sessions=$services['sessions'];$identity=(new SoSecurity\Auth\IdentityState($services['provider'],null))->load('operation-concurrency','worker');$epoch=$sessions->epoch('operation-concurrency','worker');
    if ($token===null) {$credential=$sessions->register('operation-concurrency','worker',$identity['fingerprint'],$epoch,'password');}
    else {$ref=SoSecurity\Auth\SessionRegistry::reference($token);$credential=$sessions->replace('operation-concurrency','worker',$identity['fingerprint'],$epoch,'totp',$ref['id'],$ref['digest']);}
    if ($credential===null) {throw new RuntimeException('Operation test proof failed.');}return $credential;
}
