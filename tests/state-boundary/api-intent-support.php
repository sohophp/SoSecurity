<?php
declare(strict_types=1);
require_once __DIR__.'/api-native-support.php';
/** Independent expected payload from the documented admission receipt contract; no SDK intent builder. */
function apiIntentExpected(EntryEnvironment $x,SoSecurity\Api\CredentialRegistry $api,string $entry,string $actor,string $target,string $actorIdentity,string $targetIdentity,array $credential,array $parameters,array $scopes,string $observed,?SoSecurity\Authorization\RolePolicy $roles=null):array
{
    $json=JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE;$policy=hash('sha256','SoSecurity.Api.Credentials.AdmissionPolicy.1.'.json_encode(['managed-test','tenant',permissionPolicy($x)->binding(),$api->policy()->fingerprint(),$roles===null?null:$roles->fingerprint(),$x->e->keys->currentId()],$json));$data=['entry'=>$entry,'actor'=>$actor,'target'=>$target,'actor_identity'=>$actorIdentity,'target_identity'=>$targetIdentity,'credential'=>$credential,'parameters'=>$parameters,'allowed_scopes'=>$scopes,'observed'=>$observed,'policy'=>$policy];$action=in_array($entry,['authenticate','fromAuthorization'],true)?'authenticate':($entry==='revokeAll'?'revoke_all':$entry);
    return ['kind'=>'authorized','action'=>'api.credentials.'.$action,'scope'=>hash('sha256',json_encode(['SoSecurity.Account.StateOperation.Scope.1','tenant'],$json)),'actor'=>hash('sha256',json_encode(['SoSecurity.Account.StateOperation.Subject.1','tenant',$actor],$json)),'target'=>hash('sha256',json_encode(['SoSecurity.Account.StateOperation.Subject.1','tenant',$target],$json)),'permission'=>hash('sha256','SoSecurity.Api.Credentials.AdmissionRequest.1.'.json_encode($data,$json)),'policy'=>$policy,'authorized_at'=>$x->e->clock->time];
}
function apiIntentObserve(EntryEnvironment $x,array &$writes):void
{
    $x->persistHook=static function($h)use(&$writes):bool{$at=ftell($h);rewind($h);$raw=stream_get_contents($h);fseek($h,$at);$writes[]=json_decode($raw,true);return true;};
}
function apiIntentCheck(array $expected,array $state):void
{
    Check::same($expected,$state['intent']);Check::same(hash('sha256',json_encode(['SoSecurity.Account.StateOperation.1',$expected],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)),$state['intent_digest']);
}
function apiIntentIdentity(EntryEnvironment $x,string $subject,?string $token):array
{
    $digest=$x->source->digest();return permissionPolicy($x)->credentialView('tenant',$subject,$token,$digest);
}
