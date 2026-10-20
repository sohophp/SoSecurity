<?php
declare(strict_types=1);
namespace SoSecurity\Idempotency;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Support\Guard;

/** Description only, never authentication. Host supplies actual scope/subject/operation and raw request bytes. */
final class Request
{
    private $read;
    public function __construct(string $scope,string $subject,string $operation,string $key,string $method,string $target,string $body,array $bindings=[])
    {
        State::group($scope,$subject,$operation);
        if(!preg_match('/\A[A-Za-z0-9][A-Za-z0-9_.:-]{15,127}\z/D',$key)||!in_array($method,['POST','PUT','PATCH','DELETE'],true)||strlen($target)>2048||!preg_match('/\A\/[!-~]*\z/D',$target)||strpos($target,'#')!==false||strlen($body)>1048576||count($bindings)>16){throw new ValidationException('Invalid bounded idempotent request.','idempotency.request');}
        $checked=[];foreach($bindings as $name=>$value){if(!is_string($name)||!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$name)||!is_string($value)||strlen($value)>1024||!preg_match('//u',$value)||preg_match('/[\x00-\x1f\x7f]/',$value)){throw new ValidationException('Invalid server request binding.','idempotency.request');}$checked[$name]=$value;}
        ksort($checked);
        $fingerprint=hash('sha256','SoSecurity.Idempotency.Request.1.'.json_encode([$method,$target,$checked,hash('sha256',$body)]));
        $this->read=static function()use($scope,$subject,$operation,$key,$method,$target,$body,$checked,$fingerprint):array{return [$scope,$subject,$operation,$key,$method,$target,$body,$checked,$fingerprint];};
    }
    private function data():array {if(!($this->read instanceof \Closure)){throw new ConfigurationException('Reload idempotent requests from authenticated input.','configuration.idempotency_serialization');}return ($this->read)();}
    public function scope():string {return $this->data()[0];}
    public function subject():string {return $this->data()[1];}
    public function operation():string {return $this->data()[2];}
    public function key():string {return $this->data()[3];}
    public function method():string {return $this->data()[4];}
    public function target():string {return $this->data()[5];}
    public function body():string {return $this->data()[6];}
    public function bindings():array {return $this->data()[7];}
    public function fingerprint():string {return $this->data()[8];}
    public function __debugInfo():array {return ['idempotent_request'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild requests from authenticated server context.','configuration.idempotency_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload idempotent requests from authenticated input.','configuration.idempotency_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Idempotent requests are immutable.','configuration.immutable');}
}
