<?php
declare(strict_types=1);
require_once __DIR__.'/permission-support.php';
function nativeApi(EntryEnvironment $x,?callable $guard=null,?callable $scopes=null,array $options=[],?SoSecurity\Authorization\Authorizer $authorization=null,?callable $manager=null):SoSecurity\Api\CredentialRegistry
{
    return new SoSecurity\Api\CredentialRegistry($x->store,$x->sessions,$x->provider,$x->e->keys,'managed-test',$guard??static function():bool{return true;},$scopes??static function():array{return ['records:read','records:write'];},new SoSecurity\Api\CredentialPolicy($options+['allowed_scopes'=>['records:read','records:write'],'minimum_strength'=>2,'methods'=>['totp'],'io_milliseconds'=>30000]),$x->e->clock,$x->factorAdapter,$authorization,$manager,$x->boundary,permissionPolicy($x));
}
function nativeApiNoEffect(EntryEnvironment $x,callable $attempt,?string $reason=null,$expected=null):void
{
    $before=permissionState($x);$lookups=$x->lookups;$persists=0;$x->persistHook=static function()use(&$persists):bool{++$persists;return true;};
    try{if($reason!==null){witnessReason($reason,$attempt);}else{Check::same($expected,$attempt());}}finally{$x->persistHook=null;}
    Check::same(0,$persists);Check::same($before,permissionState($x));Check::same($lookups,$x->lookups);Check::same(false,$x->boundary->active());
}
