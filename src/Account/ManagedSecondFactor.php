<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Auth\SecondFactor;
use SoSecurity\Exception\ConfigurationException;

/** Authentication always resolves the current signed SQL pointer; missing state never falls back to a raw factor. */
final class ManagedSecondFactor implements SecondFactor
{
    private $read;
    public function __construct(FactorRegistry $registry) {$this->read=static function()use($registry):FactorRegistry{return $registry;};}
    public function binding(string $scope,string $subject):?string {return ($this->read)()->binding($scope,$subject);}
    public function verify(string $scope,string $subject,string $expectedBinding,$proof):?string {return ($this->read)()->verify($scope,$subject,$expectedBinding,$proof);}
    public function __debugInfo():array {return ['managed_second_factor'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild current factor resolution.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Rebuild current factor resolution.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Managed factor adapters are immutable.','configuration.immutable');}
}
