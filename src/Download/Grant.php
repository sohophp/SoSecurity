<?php
declare(strict_types=1);
namespace SoSecurity\Download;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;

/** Immediate request-scoped authorization, created by a trusted Access adapter, never a reusable credential. */
final class Grant
{
    private $fingerprint;
    private $expires;
    private $recheck;
    private $once;
    public function __construct(string $fingerprint,int $expiresAt,callable $recheck,bool $oneTime=false)
    {
        if(!preg_match('/\A[a-f0-9]{64}\z/D',$fingerprint)||$expiresAt<1||$expiresAt>PHP_INT_MAX-86400){throw new ConfigurationException('Invalid download authorization context.','configuration.download_grant');}
        $this->fingerprint=$fingerprint;$this->expires=$expiresAt;$this->recheck=$recheck;$this->once=$oneTime;
    }
    public function expiresAt():int {return $this->expires;}
    public function oneTime():bool {return $this->once;}
    public function check(File $file,int $now):bool
    {
        if($now<0||$now>=$this->expires||!hash_equals($this->fingerprint,$file->fingerprint())){return false;}
        try{return ($this->recheck)($file)===true;}catch(\Throwable $error){throw new DependencyException('Download authorization authority unavailable.','download.authorization_unavailable');}
    }
    public function __debugInfo():array {return ['expires_at'=>$this->expires,'authorization'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize download authorization.','configuration.download_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Download grants are immutable.','configuration.immutable');}
}
