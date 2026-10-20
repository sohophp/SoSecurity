<?php
declare(strict_types=1);
namespace SoSecurity\Idempotency;
use SoSecurity\Exception\ConfigurationException;

/** Host-owned result bytes. No automatic headers, cookies, output or network calls. */
final class Response
{
    private $read;
    public function __construct(int $status,string $body)
    {
        if($status<200||$status>599||strlen($body)>1048576){throw new ConfigurationException('Provide a bounded application response.','configuration.idempotency_response');}$this->read=static function()use($status,$body):array{return [$status,$body];};
    }
    private function data():array {if(!($this->read instanceof \Closure)){throw new ConfigurationException('Reload idempotent responses from trusted storage.','configuration.idempotency_serialization');}return ($this->read)();}
    public function status():int {return $this->data()[0];}
    public function body():string {return $this->data()[1];}
    public function __debugInfo():array {return ['status'=>$this->status(),'body'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize response objects into authority.','configuration.idempotency_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload idempotent responses from trusted storage.','configuration.idempotency_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Idempotent responses are immutable.','configuration.immutable');}
}
