<?php
declare(strict_types=1);
namespace SoSecurity\Download;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

/** Explicit actual method and bounded headers. No global/header/identity inference. */
final class Request
{
    private $method;
    private $readHeaders;
    public function __construct(string $method='GET',array $headers=[])
    {
        if(!in_array($method,['GET','HEAD','POST'],true)){throw new ValidationException('Download request method not accepted.','download.method');}
        if(count($headers)>64){throw new ValidationException('Too many download request headers.','download.headers');}$seen=[];$bytes=0;$accepted=[];
        foreach($headers as $name=>$value){
            if(!is_string($name)||strlen($name)>64||!preg_match('/\A[A-Za-z0-9_-]+\z/D',$name)||!is_string($value)||strlen($value)>2048){throw new ValidationException('Invalid bounded download header.','download.headers');}
            $key=strtolower($name);if(isset($seen[$key])){throw new ValidationException('Duplicate download header name.','download.headers');}$seen[$key]=true;$value=trim($value," \t");$bytes+=strlen($name)+strlen($value);
            if($bytes>8192||preg_match('/[\x00-\x1f\x7f-\xff]/',$value)){throw new ValidationException('Download header exceeds byte/format budget.','download.headers');}
            if(in_array($key,['range','if-range','if-none-match','if-modified-since'],true)){$accepted[$key]=$value;}
        }
        $range=$accepted['range'] ?? null;
        if($range!==null&&(!preg_match('/\Abytes=([0-9]{0,20})-([0-9]{0,20})\z/iD',$range,$parts)||($parts[1]===''&&$parts[2]===''))){throw new RangeException();}
        $this->method=$method;$this->readHeaders=static function()use($accepted):array{return $accepted;};
    }
    public function method():string {return $this->method;}
    public function header(string $name):?string {return $this->headers()[strtolower($name)] ?? null;}
    private function headers():array {if(!($this->readHeaders instanceof \Closure)){throw new ConfigurationException('Reload download requests from current HTTP input.','configuration.download_serialization');}return ($this->readHeaders)();}
    public function __debugInfo():array {return ['method'=>$this->method,'headers'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not cache download request contexts.','configuration.download_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload download requests from current HTTP input.','configuration.download_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Download requests are immutable.','configuration.immutable');}
}
