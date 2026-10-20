<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;

/** Private worker data, not a reusable delivery lease or account grant. */
final class MailboxRecoveryDelivery
{
    private $read;
    public function __construct(Notice $notice,string $selector)
    {
        if(($notice->type()==='recover_address'&&!preg_match('/\A[a-f0-9]{64}\z/D',$selector))||($notice->type()!=='recover_address'&&(!in_array($notice->type(),['address_recovery_started','address_recovered'],true)||$selector!==''))){throw new ConfigurationException('Use the original recovery selector.','configuration.account_delivery');}
        $this->read=static function()use($notice,$selector):array{return [$notice,$selector];};
    }
    public function notice():Notice {return ($this->read)()[0];}
    public function selector():string {return ($this->read)()[1];}
    public function __debugInfo():array {return ['account_delivery'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize account delivery secrets.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload current account delivery data.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Account delivery data is immutable.','configuration.immutable');}
}
