<?php
declare(strict_types=1);
namespace SoSecurity\Download;
use SoSecurity\Exception\ConfigurationException;

final class Policy
{
    private $options;
    public function __construct(array $options=[])
    {
        $detached=[];foreach($options as $name=>$value){$detached[$name]=$value;}$options=$detached;
        $defaults=['maximum_bytes'=>20971520,'maximum_response_bytes'=>null,'io_milliseconds'=>3000,'send_milliseconds'=>30000,'chunk_bytes'=>65536,'ranges'=>true];
        if(array_diff(array_keys($options),array_keys($defaults))){throw new ConfigurationException('Unknown download policy option.','configuration.download');}$options+=$defaults;
        if($options['maximum_response_bytes']===null){$options['maximum_response_bytes']=$options['maximum_bytes'];}
        foreach(['maximum_bytes'=>[1,268435456],'maximum_response_bytes'=>[1,268435456],'io_milliseconds'=>[1,30000],'send_milliseconds'=>[1,30000],'chunk_bytes'=>[1024,262144]] as $key=>$bounds){
            if(!is_int($options[$key])||$options[$key]<$bounds[0]||$options[$key]>$bounds[1]){throw new ConfigurationException('Invalid bounded download policy.','configuration.download');}
        }
        if(!is_bool($options['ranges'])||$options['maximum_response_bytes']>$options['maximum_bytes']){throw new ConfigurationException('Invalid download response/range budget.','configuration.download');}$this->options=$options;
    }
    public function options():array {return $this->options;}
    public function maximumBytes():int {return $this->options['maximum_bytes'];}
    public function maximumResponseBytes():int {return $this->options['maximum_response_bytes'];}
    public function ioMilliseconds():int {return $this->options['io_milliseconds'];}
    public function sendMilliseconds():int {return $this->options['send_milliseconds'];}
    public function chunkBytes():int {return $this->options['chunk_bytes'];}
    public function ranges():bool {return $this->options['ranges'];}
    public function __set(string $name,$value):void {throw new ConfigurationException('Download policy is immutable.','configuration.immutable');}
}
