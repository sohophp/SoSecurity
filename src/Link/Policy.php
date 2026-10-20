<?php
declare(strict_types=1);
namespace SoSecurity\Link;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Http\Uri;

/** Fixed trusted origin and bounded retained-link policy. No request Host/proxy inference. */
final class Policy
{
    private $origin;
    private $ttl;
    private $maximum;
    private $capacity;
    private $http;
    public function __construct(string $origin,int $ttl=300,int $maximumTtl=86400,int $capacity=32,bool $allowHttp=false)
    {
        try {$canonical=Uri::originValue($origin);}catch (\Throwable $error) {throw new ConfigurationException('Configure a canonical signing origin.','configuration.link_origin');}
        if ($canonical!==$origin || (!$allowHttp && substr($origin,0,8)!=='https://') || $ttl<1 || $ttl>$maximumTtl || $maximumTtl>86400 || $capacity<1 || $capacity>64) {
            throw new ConfigurationException('Invalid fixed-origin bounded signed-link policy.','configuration.link');
        }
        $this->origin=$origin;$this->ttl=$ttl;$this->maximum=$maximumTtl;$this->capacity=$capacity;$this->http=$allowHttp;
    }
    public function origin():string {return $this->origin;}
    public function ttl():int {return $this->ttl;}
    public function maximumTtl():int {return $this->maximum;}
    public function capacity():int {return $this->capacity;}
    public function allowsHttp():bool {return $this->http;}
    public function fingerprint():string {return hash('sha256',json_encode([$this->origin,$this->ttl,$this->maximum,$this->capacity,$this->http]));}
    public function __set(string $name,$value):void {throw new ConfigurationException('Signed-link policies are immutable.','configuration.immutable');}
}
