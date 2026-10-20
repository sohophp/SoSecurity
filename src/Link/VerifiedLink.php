<?php
declare(strict_types=1);
namespace SoSecurity\Link;
use SoSecurity\Exception\ConfigurationException;

/** Immediate verification result, no credential. Never cache as future download/operation permission. */
final class VerifiedLink
{
    private $id;
    private $target;
    private $issued;
    private $expires;
    private $once;
    public function __construct(string $id,Target $target,int $issuedAt,int $expiresAt,bool $oneTime)
    {
        if (!State::hex($id,32) || $issuedAt<0 || $expiresAt<=$issuedAt) {throw new ConfigurationException('Invalid signed-link verification result.','configuration.link');}
        $this->id=$id;$this->target=$target;$this->issued=$issuedAt;$this->expires=$expiresAt;$this->once=$oneTime;
    }
    public function id():string {return $this->id;}
    public function target():Target {return $this->target;}
    public function issuedAt():int {return $this->issued;}
    public function expiresAt():int {return $this->expires;}
    public function oneTime():bool {return $this->once;}
    public function __debugInfo():array {return ['id'=>$this->id,'expires_at'=>$this->expires,'target'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not cache signed-link verification results.','configuration.link_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Verified links are immutable.','configuration.immutable');}
}
