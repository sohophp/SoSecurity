<?php
declare(strict_types=1);
namespace SoSecurity\Link;
use SoSecurity\Authorization\Resource;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Http\Uri;

/** Trusted route/resource snapshot. Load current metadata from the host, never from a token claim. */
final class Target
{
    private $purpose;
    private $resource;
    private $path;
    private $parameters;
    private $method;
    public function __construct(string $purpose,Resource $resource,string $path,array $parameters=[],string $method='GET')
    {
        if (!preg_match('/\A[a-z][a-z0-9_.:-]{0,63}\z/D',$purpose) || !in_array($method,['GET','POST'],true) || $path==='' || strlen($path)>512 || $path[0]!=='/' || strpos($path,'//')!==false || count($parameters)>32) {
            throw new ConfigurationException('Invalid bounded signed-link target.','configuration.link_target');
        }
        try {$uri=Uri::parse('https://signed.invalid'.$path);}catch (\Throwable $error) {throw new ConfigurationException('Invalid canonical link path.','configuration.link_target');}
        if ($uri->path()!==$path) {throw new ConfigurationException('A signed path cannot contain aliases or a query.','configuration.link_target');}
        foreach (explode('/',substr($path,1)) as $segment) {
            $decoded=rawurldecode($segment);
            if (strlen($decoded)>255 || !preg_match('//u',$decoded) || in_array($decoded,['.','..'],true) || preg_match('/[%\\\\\/?#\x00-\x1f\x7f]/',$decoded) || rawurlencode($decoded)!==$segment) {
                throw new ConfigurationException('Use canonical individually encoded path segments.','configuration.link_target');
            }
        }
        $copy=[];
        foreach ($parameters as $key=>$value) {
            if (!is_string($key) || !preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$key) || !is_string($value) || strlen($value)>256 || !preg_match('//u',$value) || preg_match('/[\x00-\x1f\x7f]/',$value)) {
                throw new ConfigurationException('Signed query parameters must be bounded named UTF-8 strings.','configuration.link_target');
            }
            $copy[$key]=$value;
        }
        ksort($copy,SORT_STRING);
        if (strlen(http_build_query($copy,'','&',PHP_QUERY_RFC3986))>1024) {throw new ConfigurationException('Signed query exceeds 1 KiB.','configuration.link_target');}
        $this->purpose=$purpose;$this->resource=$resource;$this->path=$path;$this->parameters=$copy;$this->method=$method;
    }
    public function purpose():string {return $this->purpose;}
    public function resource():Resource {return $this->resource;}
    public function path():string {return $this->path;}
    public function parameters():array {return $this->parameters;}
    public function method():string {return $this->method;}
    public function relativeUrl():string {return $this->path.($this->parameters?'?'.http_build_query($this->parameters,'','&',PHP_QUERY_RFC3986):'');}
    public function fingerprint():string {return hash('sha256',json_encode([$this->purpose,$this->resource->fingerprint(),$this->method,$this->relativeUrl()]));}
    public function __debugInfo():array {return ['purpose'=>$this->purpose,'target'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload current signed-link resource metadata.','configuration.link_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Signed-link targets are immutable.','configuration.immutable');}
}
