<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use SoSecurity\Exception\ConfigurationException;

/** Fixed bounded worker policy. Changes require an explicit migration of existing processing records. */
final class ProcessingPolicy
{
    private $options;
    public function __construct(array $options=[])
    {
        $copy=[];foreach($options as $name=>$value){if($name==='backoff'&&is_array($value)){$steps=[];foreach($value as $index=>$step){$steps[$index]=$step;}$copy[$name]=$steps;}else{$copy[$name]=$value;}}$options=$copy;
        $defaults=['maximum_attempts'=>5,'maximum_manual_retries'=>3,'lease_seconds'=>60,'backoff'=>[1,5,30,120],'io_milliseconds'=>10000];
        if(array_diff(array_keys($options),array_keys($defaults))){throw new ConfigurationException('Unknown webhook processing policy.','configuration.webhook_processing');}$options+=$defaults;
        foreach(['maximum_attempts'=>[1,20],'maximum_manual_retries'=>[0,8],'lease_seconds'=>[1,900],'io_milliseconds'=>[1,30000]] as $key=>$bounds){if(!is_int($options[$key])||$options[$key]<$bounds[0]||$options[$key]>$bounds[1]){throw new ConfigurationException('Invalid bounded webhook processing policy.','configuration.webhook_processing');}}
        if(!is_array($options['backoff'])||!$options['backoff']||count($options['backoff'])>20||array_values($options['backoff'])!==$options['backoff']){throw new ConfigurationException('Provide bounded retry delays.','configuration.webhook_processing');}
        $last=0;foreach($options['backoff'] as $step){if(!is_int($step)||$step<1||$step>86400||$step<$last){throw new ConfigurationException('Retry delays must be increasing positive seconds.','configuration.webhook_processing');}$last=$step;}
        ksort($options);$this->options=$options;
    }
    public function maximumAttempts():int {return $this->options['maximum_attempts'];}
    public function maximumManualRetries():int {return $this->options['maximum_manual_retries'];}
    public function leaseSeconds():int {return $this->options['lease_seconds'];}
    public function ioMilliseconds():int {return $this->options['io_milliseconds'];}
    public function retryDelay(int $attempt):int {if($attempt<1||$attempt>20){throw new ConfigurationException('Invalid processing attempt.','configuration.webhook_processing');}$steps=$this->options['backoff'];return $steps[min($attempt-1,count($steps)-1)];}
    public function options():array {return $this->options;}
    public function fingerprint():string {return hash('sha256',json_encode($this->options));}
    public function __set(string $name,$value):void {throw new ConfigurationException('Processing policies are immutable.','configuration.immutable');}
}
