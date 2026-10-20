<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;

/** Explicit deployment limits. An empty capability allowlist denies issuance and protected API routes. */
final class CredentialPolicy
{
    private $options;
    public function __construct(array $options=[])
    {
        // A copied PHP array can retain references in its slots. Detach them before normalization/retention.
        $detached=[];foreach($options as $name=>$value){$detached[$name]=$value;}$options=$detached;
        $defaults=['allowed_scopes'=>[],'ttl'=>86400,'maximum_ttl'=>31536000,'capacity'=>16,'fresh_age'=>300,'minimum_strength'=>1,'delegated_minimum_strength'=>2,'methods'=>['password','totp','webauthn'],'io_milliseconds'=>3000];
        if(array_diff(array_keys($options),array_keys($defaults))){throw new ConfigurationException('Unknown managed-credential policy.','configuration.api_credentials');}$options+=$defaults;
        if(!is_array($options['allowed_scopes'])||!is_array($options['methods'])){throw new ConfigurationException('Credential scopes/methods must be lists.','configuration.api_credentials');}
        try{$options['allowed_scopes']=CredentialEncoding::scopes($options['allowed_scopes'],true);}catch(\InvalidArgumentException $error){throw new ConfigurationException('Invalid credential scope allowlist.','configuration.api_credentials');}
        foreach(['ttl','maximum_ttl'] as $field){if(!is_int($options[$field])){throw new ConfigurationException('Credential durations must be integers.','configuration.api_credentials');}Guard::duration($options[$field]);}
        foreach(['capacity'=>[1,16],'fresh_age'=>[1,3600],'minimum_strength'=>[1,2],'delegated_minimum_strength'=>[1,2],'io_milliseconds'=>[1,30000]] as $field=>$range){if(!is_int($options[$field])||$options[$field]<$range[0]||$options[$field]>$range[1]){throw new ConfigurationException('Invalid bounded credential policy.','configuration.api_credentials');}}
        if($options['ttl']>$options['maximum_ttl']||array_values($options['methods'])!==$options['methods']||!$options['methods']||count($options['methods'])>4){throw new ConfigurationException('Invalid credential lifetime or authentication methods.','configuration.api_credentials');}
        $methods=[];$strength=0;foreach($options['methods'] as $method){if(!is_string($method)||!in_array($method,['password','totp','webauthn','recovery'],true)||in_array($method,$methods,true)){throw new ConfigurationException('Invalid credential authentication method.','configuration.api_credentials');}$methods[]=$method;$strength=max($strength,\SoSecurity\Auth\SessionRegistry::strength($method));}
        if($strength<$options['minimum_strength']){throw new ConfigurationException('No permitted credential authentication method meets minimum strength.','configuration.api_credentials');}sort($methods);$options['methods']=$methods;ksort($options);$this->options=$options;
    }
    public function options():array {return $this->options;}
    public function allowedScopes():array {return $this->options['allowed_scopes'];}
    public function ttl():int {return $this->options['ttl'];}
    public function maximumTtl():int {return $this->options['maximum_ttl'];}
    public function capacity():int {return $this->options['capacity'];}
    public function freshAge():int {return $this->options['fresh_age'];}
    public function minimumStrength():int {return $this->options['minimum_strength'];}
    public function delegatedMinimumStrength():int {return $this->options['delegated_minimum_strength'];}
    public function methods():array {return $this->options['methods'];}
    public function ioMilliseconds():int {return $this->options['io_milliseconds'];}
    public function fingerprint():string {return hash('sha256',json_encode($this->options));}
    public function __set(string $name,$value):void {throw new ConfigurationException('Credential policies are immutable.','configuration.immutable');}
}
