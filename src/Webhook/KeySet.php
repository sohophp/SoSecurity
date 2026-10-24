<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;

/** Private endpoint-bound key snapshot; request headers cannot select the protocol or trust root. */
final class KeySet
{
    private $endpoint;
    private $protocol;
    private $keys=[];
    public function __construct(Endpoint $endpoint,array $keys)
    {
        if(!$keys||count($keys)>8){throw new ConfigurationException('Provide 1-8 webhook verification keys.','configuration.webhook_keys');}$protocol=$endpoint->protocol();$seen=[];
        if($protocol==='standard-ed25519'&&(!extension_loaded('sodium')||!function_exists('sodium_crypto_sign_verify_detached'))){throw new DependencyException('Ed25519 webhook verification requires ext-sodium.','dependency.sodium');}
        foreach($keys as $id=>$key){
            if(!is_string($id)||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$id)||!is_string($key)){throw new ConfigurationException('Invalid named webhook key.','configuration.webhook_keys');}
            $length=strlen($key);if(($protocol==='standard-ed25519'&&$length!==32)||($protocol==='standard-hmac'&&($length<24||$length>64))||(!in_array($protocol,['standard-hmac','standard-ed25519'],true)&&($length<16||$length>256))){throw new ConfigurationException('Webhook key does not match the configured protocol.','configuration.webhook_keys');}
            $digest=hash('sha256',$key);if(isset($seen[$digest])){throw new ConfigurationException('Duplicate webhook verification material.','configuration.webhook_keys');}$seen[$digest]=true;
            // var_export() reads private properties without consulting __debugInfo().
            $this->keys[$id]=static function()use($key):string{return $key;};
        }
        $this->endpoint=$endpoint->fingerprint();$this->protocol=$protocol;
    }
    public static function fromEncoded(Endpoint $endpoint,array $keys):self
    {
        if(!$keys||count($keys)>8){throw new ConfigurationException('Provide 1-8 webhook verification keys.','configuration.webhook_keys');}
        $protocol=$endpoint->protocol();if(!in_array($protocol,['standard-hmac','standard-ed25519'],true)){throw new ConfigurationException('Encoded Standard keys cannot be used for another provider.','configuration.webhook_keys');}$prefix=$protocol==='standard-hmac'?'whsec_':'whpk_';$decoded=[];
        foreach($keys as $id=>$value){if(!is_string($value)||strlen($value)>128||substr($value,0,strlen($prefix))!==$prefix){throw new ConfigurationException('Invalid Standard webhook key prefix.','configuration.webhook_keys');}$encoded=substr($value,strlen($prefix));$raw=base64_decode($encoded,true);if(!is_string($raw)||base64_encode($raw)!==$encoded){throw new ConfigurationException('Invalid Standard webhook key encoding.','configuration.webhook_keys');}$decoded[$id]=$raw;}
        return new self($endpoint,$decoded);
    }
    /** Preserve verification preference order as well as endpoint, IDs and actual key material. */
    public function stateDigest():string
    {
        $rows=[];foreach($this->keys as $id=>$read){if(!$read instanceof \Closure){throw new ConfigurationException('Reload webhook verification keys.','configuration.webhook_keys');}$rows[]=[$id,hash_hmac('sha256','SoSecurity.Webhook.KeySet.Material.1.',$read())];}
        return hash('sha256','SoSecurity.Webhook.KeySet.State.1.'.json_encode([$this->endpoint,$this->protocol,$rows],JSON_UNESCAPED_SLASHES));
    }
    public function matches(Endpoint $endpoint):bool {return hash_equals($this->endpoint,$endpoint->fingerprint());}
    public function verify(string $message,array $signatures):?string
    {
        if(strlen($message)>1050624||!$signatures||count($signatures)>8||array_values($signatures)!==$signatures){throw new ConfigurationException('Invalid bounded webhook signature work.','configuration.webhook_signatures');}
        $expected=$this->protocol==='standard-ed25519'?64:32;foreach($signatures as $signature){if(!is_string($signature)||strlen($signature)!==$expected){throw new ConfigurationException('Invalid decoded webhook signature.','configuration.webhook_signatures');}}
        $accepted=null;foreach($this->keys as $id=>$read){
            if(!($read instanceof \Closure)){throw new ConfigurationException('Reload webhook verification keys from trusted configuration.','configuration.webhook_keys');}
            $key=$read();$mac=$this->protocol==='standard-ed25519'?null:hash_hmac('sha256',$message,$key,true);
            foreach($signatures as $signature){$valid=$mac===null?sodium_crypto_sign_verify_detached($signature,$message,$key):hash_equals($mac,$signature);if($valid&&$accepted===null){$accepted=$id;}}
        }return $accepted;
    }
    public function __debugInfo():array {return ['protocol'=>$this->protocol,'key_ids'=>array_keys($this->keys),'keys'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize webhook verification keys.','configuration.webhook_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload webhook verification keys from trusted configuration.','configuration.webhook_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Webhook key snapshots are immutable.','configuration.immutable');}
}
