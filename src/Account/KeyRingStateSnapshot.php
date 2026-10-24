<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use PDO;
use SoSecurity\Api\KeyRing;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;
/** Immutable key configuration is actual state: changing contents changes digest, not source identity. */
final class KeyRingStateSnapshot implements StateSnapshot
{
    private $dependencies;private $fingerprint;
    public function __construct(PDO $connection,string $profile,KeyRing $keys,\SoSecurity\Api\SignaturePolicy $policy)
    {
        Guard::label($profile);if(preg_match('//u',$profile)!==1){throw new ConfigurationException('Use an explicit UTF-8 key configuration profile.','configuration.state_snapshot');}$this->dependencies=static function()use($connection,$keys,$policy):array{return [$connection,$keys,$policy];};$this->fingerprint=hash('sha256','SoSecurity.State.KeyRing.Profile.1.'.$profile);
    }
    public function connection():PDO{return ($this->dependencies)()[0];}
    public function fingerprint():string{return $this->fingerprint;}
    public function uses(KeyRing $keys,\SoSecurity\Api\SignaturePolicy $policy):bool{return ($this->dependencies)()[1]===$keys&&self::policy(($this->dependencies)()[2])===self::policy($policy);}
    private static function policy(\SoSecurity\Api\SignaturePolicy $policy):string{$options=$policy->options();ksort($options,SORT_STRING);return json_encode($options,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);}
    public function digest():string{return hash('sha256','SoSecurity.State.KeyRing.Snapshot.1.'.$this->fingerprint.($this->dependencies)()[1]->stateDigest().self::policy(($this->dependencies)()[2]));}
    /** Configuration is an immutable in-process value; this source does not own a database or filesystem. */
    public function storageDomains():array{return [];}
    public function __debugInfo():array{return ['keyring_state_snapshot'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Rebuild key snapshots from private current configuration.','configuration.state_snapshot');}
    public function __wakeup():void{throw new ConfigurationException('Do not deserialize key snapshots.','configuration.state_snapshot');}
    public function __set(string $name,$value):void{throw new ConfigurationException('State sources are immutable.','configuration.immutable');}
}
