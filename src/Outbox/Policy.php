<?php
declare(strict_types=1);
namespace SoSecurity\Outbox;
use SoSecurity\Exception\ConfigurationException;

final class Policy
{
    private $options=[];
    public function __construct(array $options=[])
    {
        $defaults=['message_age'=>86400,'recovery_age'=>2592000,'retention_seconds'=>3600,'lease_seconds'=>60,'maximum_attempts'=>8,'maximum_manual_retries'=>3,'backoff_seconds'=>5,'maximum_backoff_seconds'=>3600,'maximum_entries'=>1000,'maximum_payload_bytes'=>65536,'scan_limit'=>50,'io_milliseconds'=>10000];
        if(array_diff(array_keys($options),array_keys($defaults))){throw new ConfigurationException('Unknown outbox policy.','configuration.outbox');}
        foreach($defaults as $name=>$default){$this->options[$name]=array_key_exists($name,$options)?$options[$name]:$default;}
        $bounds=['message_age'=>[1,31536000],'recovery_age'=>[1,31536000],'retention_seconds'=>[0,31536000],'lease_seconds'=>[1,3600],'maximum_attempts'=>[1,30],'maximum_manual_retries'=>[0,10],'backoff_seconds'=>[1,86400],'maximum_backoff_seconds'=>[1,86400],'maximum_entries'=>[1,100000],'maximum_payload_bytes'=>[1,1048576],'scan_limit'=>[1,50],'io_milliseconds'=>[1,30000]];
        foreach($bounds as $name=>$range){$value=$this->options[$name];if(!is_int($value)||$value<$range[0]||$value>$range[1]){throw new ConfigurationException('Invalid bounded outbox policy.','configuration.outbox');}}
        if($this->options['recovery_age']<$this->options['message_age']||$this->options['maximum_backoff_seconds']<$this->options['backoff_seconds']){throw new ConfigurationException('Outbox policy lifetimes/backoff are inconsistent.','configuration.outbox');}
    }
    public function messageAge():int {return $this->options['message_age'];}
    public function recoveryAge():int {return $this->options['recovery_age'];}
    public function retentionSeconds():int {return $this->options['retention_seconds'];}
    public function leaseSeconds():int {return $this->options['lease_seconds'];}
    public function maximumAttempts():int {return $this->options['maximum_attempts'];}
    public function maximumManualRetries():int {return $this->options['maximum_manual_retries'];}
    public function maximumEntries():int {return $this->options['maximum_entries'];}
    public function maximumPayloadBytes():int {return $this->options['maximum_payload_bytes'];}
    public function scanLimit():int {return $this->options['scan_limit'];}
    public function ioMilliseconds():int {return $this->options['io_milliseconds'];}
    public function backoff(int $attempt):int
    {
        if($attempt<1||$attempt>100){throw new ConfigurationException('Use an outbox attempt count of 1-100.','configuration.outbox');}
        $delay=$this->options['backoff_seconds'];for($i=1;$i<$attempt&&$delay<$this->options['maximum_backoff_seconds'];++$i){$delay=min($delay*2,$this->options['maximum_backoff_seconds']);}return $delay;
    }
    public function options():array {return $this->options;}
    public function fingerprint():string {return hash('sha256',json_encode($this->options));}
    public function __set(string $name,$value):void {throw new ConfigurationException('Outbox policy is immutable.','configuration.immutable');}
}
