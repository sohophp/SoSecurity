<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Http\Uri;
use SoSecurity\Support\Guard;

/** Server-owned endpoint contract; protocols never negotiate from request input. */
final class Endpoint
{
    private $id;
    private $scope;
    private $account;
    private $url;
    private $protocol;
    private $options;
    public function __construct(string $id,string $scope,string $account,string $url,string $protocol,array $options=[])
    {
        if(!preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$id)||!in_array($protocol,['standard-hmac','standard-ed25519','stripe-v1','github-sha256'],true)){throw new ConfigurationException('Configure an exact webhook endpoint/protocol.','configuration.webhook');}
        foreach([$scope,$account] as $value){Guard::label($value);if(!preg_match('//u',$value)){throw new ConfigurationException('Webhook identities must be UTF-8.','configuration.webhook');}}
        $defaults=['allow_http'=>false,'allow_untimed'=>false,'maximum_body'=>65536,'tolerance'=>300,'future_skew'=>30,'io_milliseconds'=>3000];
        if(count($options) > count($defaults) || array_diff(array_keys($options),array_keys($defaults))){throw new ConfigurationException('Unknown webhook policy.','configuration.webhook');}
        $copy=[];foreach($options as $name=>$value){$copy[$name]=$value;}$options=$copy;
        $options+=$defaults;
        foreach(['allow_http','allow_untimed'] as $name){if(!is_bool($options[$name])){throw new ConfigurationException('Webhook exceptions must be explicit booleans.','configuration.webhook');}}
        foreach(['maximum_body'=>[0,1048576],'tolerance'=>[1,900],'future_skew'=>[0,120],'io_milliseconds'=>[1,30000]] as $name=>$limits){if(!is_int($options[$name])||$options[$name]<$limits[0]||$options[$name]>$limits[1]){throw new ConfigurationException('Invalid bounded webhook policy.','configuration.webhook');}}
        try{$uri=Uri::parse($url);}catch(\Throwable $error){throw new ConfigurationException('Configure an exact webhook URL.','configuration.webhook');}
        if(strlen($url)>2048||$uri->url()!==$url||(!$options['allow_http']&&substr($url,0,8)!=='https://')){throw new ConfigurationException('Webhook URL requires canonical bytes and HTTPS.','configuration.webhook');}
        if(($protocol==='github-sha256')!==$options['allow_untimed']){throw new ConfigurationException('Only GitHub requires explicit acceptance of its unsigned freshness metadata.','configuration.webhook_freshness');}
        ksort($options);$this->id=$id;$this->scope=$scope;$this->account=$account;$this->url=$url;$this->protocol=$protocol;$this->options=$options;
    }
    public function id():string {return $this->id;}
    public function scope():string {return $this->scope;}
    public function account():string {return $this->account;}
    public function url():string {return $this->url;}
    public function protocol():string {return $this->protocol;}
    public function options():array {return $this->options;}
    public function maximumBody():int {return $this->options['maximum_body'];}
    public function tolerance():int {return $this->options['tolerance'];}
    public function futureSkew():int {return $this->options['future_skew'];}
    public function ioMilliseconds():int {return $this->options['io_milliseconds'];}
    public function fingerprint():string {return hash('sha256',json_encode([$this->id,$this->scope,$this->account,$this->url,$this->protocol,$this->options]));}
    public function __set(string $name,$value):void {throw new ConfigurationException('Webhook endpoints are immutable.','configuration.immutable');}
}
