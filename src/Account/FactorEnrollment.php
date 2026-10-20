<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Mfa\Enrollment;

/** Sensitive preparation result; preparation grants no authentication or activation authority. */
final class FactorEnrollment
{
    private $read;
    public function __construct(string $selector,Enrollment $enrollment)
    {
        if(!preg_match('/\A[a-f0-9]{64}\z/D',$selector)){throw new ConfigurationException('Use a server-generated factor enrollment selector.','configuration.factor_enrollment');}
        $this->read=static function()use($selector,$enrollment):array{return [$selector,$enrollment];};
    }
    public function selector():string {return ($this->read)()[0];}
    public function enrollment():Enrollment {return ($this->read)()[1];}
    public function __debugInfo():array {return ['factor_enrollment_enrollment'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize factor enrollment provisioning.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload authorized factor enrollment provisioning.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Factor provisioning is immutable.','configuration.immutable');}
}
