<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;
use SoSecurity\Exception\ValidationException;

final class HmacSigner
{
    private $policy;
    private $key;
    private $clock;
    public function __construct(SignaturePolicy $policy,SigningKey $key,?Clock $clock=null) { $this->policy=$policy; $this->key=$key; $this->clock=$clock ?? new SystemClock(); }
    public function sign(string $method,string $url,string $body='',string $type='application/octet-stream',int $lifetime=60,?string $nonce=null): array
    {
        $target=$this->policy->target($method,$url,$body); $type=SignatureProfile::contentType($type);
        if ($lifetime<1 || $lifetime>$this->policy->maximumLifetime()) { throw new ValidationException('Signature lifetime is outside policy.','api.lifetime'); }
        $created=$this->clock->now();
        if ($created<0 || $created>PHP_INT_MAX-$lifetime) { throw new \SoSecurity\Exception\ConfigurationException('Clock cannot represent signature expiry.','configuration.clock'); }
        $expires=$created+$lifetime; $nonce=$nonce ?? rtrim(strtr(base64_encode(random_bytes(24)),'+/','-_'),'=');
        $params=SignatureProfile::parameters($created,$expires,$nonce,$this->key->identity()->id()); $digest=SignatureProfile::digest($body);
        return ['Content-Type'=>$type,'Content-Digest'=>$digest,'Signature-Input'=>'sig1='.$params,
            'Signature'=>'sig1=:'.base64_encode(Hmac::sign(SignatureProfile::base($method,$target,$digest,$type,$params),$this->key->secret())).':'];
    }
}
