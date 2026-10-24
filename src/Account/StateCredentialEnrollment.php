<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Mfa\Enrollment;
use SoSecurity\Exception\ConfigurationException;
/** Sensitive candidate provisioning, never installation approval. Keep out of logs, caches and ordinary exports. */
final class StateCredentialEnrollment
{
    private $read;
    public function __construct(string $selector,string $password,Enrollment $enrollment){$this->read=static function()use($selector,$password,$enrollment):array{return [$selector,$password,$enrollment];};}
    public function selector():string{return ($this->read)()[0];}
    public function password():string{return ($this->read)()[1];}
    public function enrollment():Enrollment{return ($this->read)()[2];}
    public function __debugInfo():array{return ['state_credential_enrollment'=>'[redacted]'];}
    public function __clone(){throw new ConfigurationException('Do not clone credential provisioning.','configuration.state_credentials');}
    public function __sleep():array{throw new ConfigurationException('Do not serialize plaintext credential provisioning.','configuration.state_credentials');}
    public function __wakeup():void{throw new ConfigurationException('Reload current candidate records.','configuration.state_credentials');}
    public function __set(string $name,$value):void{throw new ConfigurationException('Credential provisioning is immutable.','configuration.immutable');}
}
