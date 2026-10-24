<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Webhook\Endpoint;
use SoSecurity\Webhook\KeySet;
use SoSecurity\Webhook\ProcessingPolicy;

/** Immutable local Webhook configuration source. Does not authorize requests or bind SQL coverage. */
final class WebhookStateSnapshot implements StateSnapshot
{
    private $dependencies;
    private $fingerprint;
    public function __construct(PDO $connection,string $profile,Endpoint $endpoint,KeySet $keys,HmacKeys $integrityKeys,?ProcessingPolicy $processing=null)
    {
        Guard::label($profile);
        if(preg_match('//u',$profile)!==1||!$keys->matches($endpoint)){throw new ConfigurationException('Use a named local Webhook profile with its exact endpoint keys.','configuration.state_snapshot');}
        $this->fingerprint=hash('sha256','SoSecurity.State.Webhook.Profile.1.'.$profile);
        $this->dependencies=static function()use($connection,$endpoint,$keys,$integrityKeys,$processing):array{return [$connection,$endpoint,$keys,$integrityKeys,$processing];};
    }
    public function connection():PDO{return ($this->dependencies)()[0];}
    public function fingerprint():string{return $this->fingerprint;}
    public function uses(Endpoint $endpoint,KeySet $keys,HmacKeys $integrityKeys,?ProcessingPolicy $processing=null):bool
    {
        $d=($this->dependencies)();return $d[1]->fingerprint()===$endpoint->fingerprint()&&$d[2]===$keys&&$d[3]===$integrityKeys&&($d[4]===null?null:$d[4]->fingerprint())===($processing===null?null:$processing->fingerprint());
    }
    public function digest():string
    {
        $d=($this->dependencies)();return hash('sha256','SoSecurity.State.Webhook.Snapshot.1.'.json_encode([$this->fingerprint,$d[1]->fingerprint(),$d[2]->stateDigest(),$d[3]->stateDigest(),$d[4]===null?null:$d[4]->fingerprint()],JSON_UNESCAPED_SLASHES));
    }
    /** Fixed in-process configuration has no mutable database or filesystem domain. */
    public function storageDomains():array{return [];}
    public function __debugInfo():array{return ['webhook_state_snapshot'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Rebuild Webhook snapshots from trusted local configuration.','configuration.state_snapshot');}
    public function __wakeup():void{throw new ConfigurationException('Do not deserialize Webhook snapshots.','configuration.state_snapshot');}
    public function __set(string $name,$value):void{throw new ConfigurationException('State sources are immutable.','configuration.immutable');}
}
