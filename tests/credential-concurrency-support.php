<?php
declare(strict_types=1);
// Synthetic trusted login for real shared-ledger races; this does not test password or MFA protocols.
function concurrentCredentials(SoSecurity\Storage\AtomicStore $store,TestClock $clock):array
{
    $provider=new SoSecurity\Auth\CallbackIdentityProvider(static function(){return null;},static function(string $scope,string $subject){return $scope==='credential-concurrency'&&$subject==='worker'?new SoSecurity\Auth\Account($scope,$subject,'1',true,['editor']):null;});
    $sessions=new SoSecurity\Auth\SessionRegistry($store,$provider,null,$clock,600,1200,4);
    $policy=new SoSecurity\Api\CredentialPolicy(['allowed_scopes'=>['documents:read','documents:write'],'ttl'=>300,'maximum_ttl'=>3600,'capacity'=>8,'fresh_age'=>900,'io_milliseconds'=>30000]);
    $registry=new SoSecurity\Api\CredentialRegistry($store,$sessions,$provider,new SoSecurity\Support\HmacKeys('test',['test'=>str_repeat('c',32)]),'credential-concurrency',static function(){return true;},static function(){return ['documents:read','documents:write'];},$policy,$clock);
    return ['provider'=>$provider,'sessions'=>$sessions,'registry'=>$registry];
}
function credentialConcurrencySuite(string $kind,string $target,SoSecurity\Storage\AtomicStore $store,string $directory):void
{
    $clock=new TestClock();$clock->time=time();$services=concurrentCredentials($store,$clock);$identity=(new SoSecurity\Auth\IdentityState($services['provider'],null))->load('credential-concurrency','worker');$session=$services['sessions']->register('credential-concurrency','worker',$identity['fingerprint'],$services['sessions']->epoch('credential-concurrency','worker'));
    $registry=$services['registry'];$root=SoSecurity\Api\CredentialState::root('credential-concurrency','credential-concurrency','worker');$key=SoSecurity\Api\CredentialState::key('credential-concurrency',$root);
    $store->transact($key,static function(){return new SoSecurity\Storage\Change(null,0,null);});
    Check::same(8,parallelSuccesses($kind,$target,'credential-issue',[(string)$clock->time,$session->token()]));Check::same(8,count($registry->all('credential-concurrency','worker',$session->token())));Check::same(8,$registry->revokeAll('credential-concurrency','worker',$session->token()));
    $issued=$registry->issue('credential-concurrency','worker',$session->token(),'Original',['documents:read','documents:write']);$channel=$directory.'/credential-winner-'.bin2hex(random_bytes(8));
    Check::same(1,parallelSuccesses($kind,$target,'credential-rotate',[(string)$clock->time,$session->token(),$issued->metadata()->id(),'1',$channel]));$next=file_get_contents($channel);Check::same(0600,fileperms($channel)&0777);unlink($channel);Check::same(2,$registry->all('credential-concurrency','worker',$session->token())[0]->generation());
    Check::same(0,parallelSuccesses($kind,$target,'credential-auth',[(string)$clock->time,$issued->token(),'documents:read']));Check::same(24,parallelSuccesses($kind,$target,'credential-auth',[(string)$clock->time,$next,'documents:read']));
    Check::same(1,parallelSuccesses($kind,$target,'credential-replace',[(string)$clock->time,$session->token(),$issued->metadata()->id(),'2',$channel]));$narrow=file_get_contents($channel);unlink($channel);Check::same(3,$registry->all('credential-concurrency','worker',$session->token())[0]->generation());Check::same(null,$registry->authenticate('credential-concurrency',$next,'documents:read'));Check::same(null,$registry->authenticate('credential-concurrency',$narrow,'documents:write'));
    Check::same(1,parallelSuccesses($kind,$target,'credential-revoke',[(string)$clock->time,$session->token(),$issued->metadata()->id()]));Check::same(0,parallelSuccesses($kind,$target,'credential-auth',[(string)$clock->time,$narrow,'documents:read']));
    $last=$registry->issue('credential-concurrency','worker',$session->token(),'Revoke all',['documents:read']);Check::same(1,parallelSuccesses($kind,$target,'credential-revoke-all',[(string)$clock->time,$session->token()]));Check::same(0,parallelSuccesses($kind,$target,'credential-auth',[(string)$clock->time,$last->token(),'documents:read']));
    $expired=$registry->issue('credential-concurrency','worker',$session->token(),'Expires',['documents:read']);$clock->time+=300;Check::same(0,parallelSuccesses($kind,$target,'credential-auth',[(string)$clock->time,$expired->token(),'documents:read']));
    $store->transact($key,static function(){return new SoSecurity\Storage\Change(null,0,null);});$store->transact(SoSecurity\Support\Guard::key('auth-sessions','credential-concurrency','worker'),static function(){return new SoSecurity\Storage\Change(null,0,null);});
    echo "PASS $kind managed credentials: 24 processes; fresh-account capacity 8, one generation rotation/replacement/revocation, all live authentications, scope reduction, revoke-all and expiry\n";
}
