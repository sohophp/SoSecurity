<?php
declare(strict_types=1);
namespace SoSecurity\Idempotency;
use SoSecurity\Exception\ConfigurationException;

final class Policy
{
    private $options=[];
    public function __construct(array $options=[])
    {
        $defaults=['ttl'=>86400,'maximum_entries'=>1000,'maximum_response_bytes'=>65536,'io_milliseconds'=>10000];
        if(count($options) > count($defaults) || array_diff(array_keys($options),array_keys($defaults))){throw new ConfigurationException('Unknown idempotency policy.','configuration.idempotency');}
        foreach($defaults as $name=>$default){$this->options[$name]=array_key_exists($name,$options)?$options[$name]:$default;}
        foreach(['ttl'=>[1,31536000],'maximum_entries'=>[1,100000],'maximum_response_bytes'=>[1,1048576],'io_milliseconds'=>[1,30000]] as $name=>$bounds){$value=$this->options[$name];if(!is_int($value)||$value<$bounds[0]||$value>$bounds[1]){throw new ConfigurationException('Invalid bounded idempotency policy.','configuration.idempotency');}}
    }
    public function ttl():int {return $this->options['ttl'];}
    public function maximumEntries():int {return $this->options['maximum_entries'];}
    public function maximumResponseBytes():int {return $this->options['maximum_response_bytes'];}
    public function ioMilliseconds():int {return $this->options['io_milliseconds'];}
    public function options():array {return $this->options;}
    public function fingerprint():string {return hash('sha256',json_encode($this->options));}
    public function __set(string $name,$value):void {throw new ConfigurationException('Idempotency policy is immutable.','configuration.immutable');}
}
