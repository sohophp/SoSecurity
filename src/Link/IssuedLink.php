<?php
declare(strict_types=1);
namespace SoSecurity\Link;
use SoSecurity\Exception\ConfigurationException;

/** Sensitive shareable credential. Do not log URLs or serialize this object. */
final class IssuedLink
{
    private $read;
    public function __construct(string $url,string $id,Target $target,int $issuedAt,int $expiresAt,bool $oneTime)
    {
        if (strlen($url)>2048 || !State::hex($id,32) || $issuedAt<0 || $expiresAt<=$issuedAt) {throw new ConfigurationException('Invalid issued signed link.','configuration.link');}
        $this->read=static function()use($url,$id,$target,$issuedAt,$expiresAt,$oneTime):array{return [$url,$id,$target,$issuedAt,$expiresAt,$oneTime];};
    }
    private function data():array {if(!($this->read instanceof \Closure)){throw new ConfigurationException('Reload signed links from current authority.','configuration.link_serialization');}return ($this->read)();}
    public function url():string {return $this->data()[0];}
    public function id():string {return $this->data()[1];}
    public function target():Target {return $this->data()[2];}
    public function issuedAt():int {return $this->data()[3];}
    public function expiresAt():int {return $this->data()[4];}
    public function oneTime():bool {return $this->data()[5];}
    public function __debugInfo():array {return ['id'=>$this->id(),'expires_at'=>$this->expiresAt(),'credential'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize signed link credentials.','configuration.link_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload signed links from current authority.','configuration.link_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Issued links are immutable.','configuration.immutable');}
}
