<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

/** Host-mapped metadata from authenticated bytes; the association guard must still check business authority. */
final class Message
{
    private $id;
    private $type;
    private $resource;
    private $context=[];
    public function __construct(string $id,string $type,string $resource,array $context=[])
    {
        if(!preg_match('/\A[!-~]{1,256}\z/D',$id)||!preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$type)||$resource===''||strlen($resource)>256||!preg_match('//u',$resource)||preg_match('/[\x00-\x1f\x7f]/',$resource)||count($context)>16){throw new ValidationException('Invalid bounded webhook association metadata.','webhook.message');}
        foreach($context as $name=>$value){
            if(!is_string($name)||!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$name)||(!is_null($value)&&!is_bool($value)&&!is_int($value)&&!is_string($value))||(is_string($value)&&(strlen($value)>256||!preg_match('//u',$value)||preg_match('/[\x00-\x1f\x7f]/',$value)))){throw new ValidationException('Invalid bounded webhook context.','webhook.message');}$this->context[$name]=$value;
        }
        ksort($this->context);$this->id=$id;$this->type=$type;$this->resource=$resource;
    }
    public function id():string {return $this->id;}
    public function type():string {return $this->type;}
    public function resource():string {return $this->resource;}
    public function context():array {return $this->context;}
    public function fingerprint():string {return hash('sha256',json_encode([$this->id,$this->type,$this->resource,$this->context]));}
    public function __debugInfo():array {return ['message'=>'[redacted]'];}
    public function __set(string $name,$value):void {throw new ConfigurationException('Webhook metadata is immutable.','configuration.immutable');}
}
