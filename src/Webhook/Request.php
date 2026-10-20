<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

/** Exact host-extracted request bytes. No superglobals, HTTP transport, stream reads or JSON normalization. */
final class Request
{
    private $read;
    public function __construct(string $method,string $url,string $body,array $headers)
    {
        if(!preg_match('/\A[A-Z]{1,16}\z/D',$method)||strlen($url)>2048||strlen($body)>1048576||count($headers)>32){throw new ValidationException('Webhook request exceeds its input budget.','webhook.input');}
        $checked=[];$size=0;foreach($headers as $name=>$value){
            if(!is_string($name)||!preg_match('/\A[A-Za-z][A-Za-z0-9-]{0,63}\z/D',$name)||!is_string($value)||strlen($value)>4096||preg_match('/[\x00-\x1f\x7f]/',$value)){throw new ValidationException('Invalid webhook request header.','webhook.input');}
            $name=strtolower($name);if(array_key_exists($name,$checked)){throw new ValidationException('Duplicate webhook request header.','webhook.input');}$size+=strlen($name)+strlen($value);if($size>16384){throw new ValidationException('Webhook headers exceed their total budget.','webhook.input');}$checked[$name]=$value;
        }
        ksort($checked);$this->read=static function()use($method,$url,$body,$checked):array{return [$method,$url,$body,$checked];};
    }
    private function data():array {if(!($this->read instanceof \Closure)){throw new ConfigurationException('Reload webhook requests from trusted input.','configuration.webhook_serialization');}return ($this->read)();}
    public function method():string {return $this->data()[0];}
    public function url():string {return $this->data()[1];}
    public function body():string {return $this->data()[2];}
    public function header(string $name):?string {$headers=$this->data()[3];return $headers[strtolower($name)] ?? null;}
    public function __debugInfo():array {return ['method'=>$this->method(),'request'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize webhook request secrets.','configuration.webhook_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload webhook requests from trusted input.','configuration.webhook_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Webhook requests are immutable.','configuration.immutable');}
}
