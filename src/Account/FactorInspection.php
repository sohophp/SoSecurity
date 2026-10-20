<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;

/** Management-only data, including absent/inactive accounts. Never an identity or destructive-operation grant. */
final class FactorInspection
{
    private $read;
    public function __construct(string $scope,FactorSlot $slot,?AccountRecord $record,bool $retired,string $stamp)
    {
        Guard::label($scope);if(preg_match('//u',$scope)!==1||!preg_match('/\A[a-f0-9]{64}\z/D',$stamp)||($record!==null&&($record->account()->scope()!==$scope||$record->account()->subject()!==$slot->subject()))){throw new ConfigurationException('Use the current exact management inspection.','configuration.account_factor');}
        $this->read=static function()use($scope,$slot,$record,$retired,$stamp):array{return [$scope,$slot,$record,$retired,$stamp];};
    }
    public function scope():string {return ($this->read)()[0];}
    public function subject():string {return $this->slot()->subject();}
    public function slot():FactorSlot {return ($this->read)()[1];}
    public function record():?AccountRecord {return ($this->read)()[2];}
    public function retired():bool {return ($this->read)()[3];}
    public function stamp():string {return ($this->read)()[4];}
    public function __debugInfo():array {return ['factor_inspection'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload current factor management state.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload current factor management state.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Management inspections are immutable.','configuration.immutable');}
}
