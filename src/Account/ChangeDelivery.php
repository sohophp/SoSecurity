<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;

/** Sensitive fixed-template worker data only, never an authentication proof or an Outbox lease. */
final class ChangeDelivery
{
    private $read;
    public function __construct(Notice $notice,string $selector)
    {
        $challenge=in_array($notice->type(),['verify_address_old','verify_address_new','cancel_change'],true);
        if(($challenge&&!preg_match('/\A[a-f0-9]{64}\z/D',$selector))||(!$challenge&&($notice->type()!=='address_changed'||$selector!==''))){throw new ConfigurationException('Use a bound address-change delivery.','configuration.account_delivery');}
        $this->read=static function()use($notice,$selector):array{return [$notice,$selector];};
    }
    public function notice():Notice {return ($this->read)()[0];}
    public function selector():string {return ($this->read)()[1];}
    public function __debugInfo():array {return ['address_change_delivery'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize delivery secrets.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload current delivery data.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Delivery values are immutable.','configuration.immutable');}
}
