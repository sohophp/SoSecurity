<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Exception\SecurityException;

final class HmacVerifier
{
    private $policy;
    private $keys;
    private $nonces;
    private $clock;
    public function __construct(SignaturePolicy $policy,KeyProvider $keys,NonceStore $nonces,?Clock $clock=null)
    { $this->policy=$policy; $this->keys=$keys; $this->nonces=$nonces; $this->clock=$clock ?? new SystemClock(); }
    public function verify(string $method,string $url,string $body,array $headers,?string $requiredScope=null): ?Identity
    {
        if ($requiredScope!==null) { Identity::validateScopes([$requiredScope]); }
        try { $target=$this->policy->target($method,$url,$body); $signed=SignatureProfile::parse($headers); }
        catch (ValidationException $e) { return null; }
        $now=$this->clock->now(); $skew=$this->policy->clockSkew();
        if ($now<0 || $now>PHP_INT_MAX-$skew || $signed['expires']>PHP_INT_MAX-$skew-1
            || $signed['created']>$now+$skew || $signed['expires']<$now-$skew || $signed['expires']<=$signed['created']
            || $signed['expires']-$signed['created']>$this->policy->maximumLifetime()
            || !hash_equals(SignatureProfile::digest($body),$signed['digest'])) { return null; }
        try { $key=$this->keys->find($signed['keyid']); }
        catch (\Throwable $e) { throw new SecurityException('Signing key lookup failed.','api.key_provider',$e); }
        if ($key===null) { return null; }
        if ($key->identity()->id()!==$signed['keyid']) { throw new SecurityException('Signing key provider returned another identity.','api.key_provider'); }
        if ($requiredScope!==null && !$key->identity()->allows($requiredScope)) { return null; }
        $base=SignatureProfile::base($method,$target,$signed['digest'],$signed['type'],$signed['parameters']);
        if (!hash_equals(Hmac::sign($base,$key->secret()),$signed['mac'])) { return null; }
        $expires=$signed['expires']+$skew+1;
        if (!$this->nonces->consume($signed['keyid'],$signed['nonce'],$expires)) { return null; }
        $finalNow=$this->clock->now();
        if ($finalNow<0 || $finalNow>PHP_INT_MAX-$skew || $finalNow>$signed['expires']+$skew || $signed['created']>$finalNow+$skew) { return null; }
        return $key->identity();
    }
}
