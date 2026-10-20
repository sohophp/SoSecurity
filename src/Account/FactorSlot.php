<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;

/** Private pointer snapshot; a constructed value never grants enrollment or activation permission. */
final class FactorSlot
{
    private $read;
    public function __construct(string $subject,string $binding,string $slotScope,string $slotSubject,string $factorId)
    {
        foreach([$subject,$binding] as $value){Guard::label($value);}if(!preg_match('//u',$subject)||!preg_match('/\A[a-f0-9]{64}\z/D',$binding)){throw new ConfigurationException('Use a bounded managed factor binding.','configuration.account_factor');}
        if($factorId===''){if($slotScope!==''||$slotSubject!==''){throw new ConfigurationException('Disabled pointer has no factor slot.','configuration.account_factor');}}
        else{Guard::label($slotScope);Guard::label($slotSubject);if(!preg_match('//u',$slotScope)||!preg_match('//u',$slotSubject)||!preg_match('/\A[a-f0-9]{32}\z/D',$factorId)){throw new ConfigurationException('Use the exact verified factor slot.','configuration.account_factor');}}
        $this->read=static function()use($subject,$binding,$slotScope,$slotSubject,$factorId):array{return [$subject,$binding,$slotScope,$slotSubject,$factorId];};
    }
    public function subject():string {return ($this->read)()[0];}
    public function binding():string {return ($this->read)()[1];}
    public function slotScope():string {return ($this->read)()[2];}
    public function slotSubject():string {return ($this->read)()[3];}
    public function factorId():string {return ($this->read)()[4];}
    public function enabled():bool {return $this->factorId()!=='';}
    public function __debugInfo():array {return ['managed_factor_slot'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload current managed factor pointers.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload current managed factor pointers.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Managed factor snapshots are immutable.','configuration.immutable');}
}
