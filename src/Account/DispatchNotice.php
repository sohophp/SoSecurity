<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;

/** Private worker data only. Construction is neither current notification authority nor a delivery lease. */
final class DispatchNotice
{
    private $read;
    public function __construct(Notice $notice,string $selector,string $subject)
    {
        Guard::label($subject);if(preg_match('//u',$subject)!==1||($notice->token()!==''?!preg_match('/\A[a-f0-9]{64}\z/D',$selector):$selector!=='')){throw new ConfigurationException('Use the original authenticated dispatch context.','configuration.account_dispatch');}
        $this->read=static function()use($notice,$selector,$subject):array{return [$notice,$selector,$subject];};
    }
    public function notice():Notice {return ($this->read)()[0];}
    public function selector():string {return ($this->read)()[1];}
    public function subject():string {return ($this->read)()[2];}
    public function fingerprint():string {return hash('sha256',json_encode([$this->notice()->encode(),$this->selector(),$this->subject()]));}
    public function __debugInfo():array {return ['account_dispatch_notice'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize private delivery data.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload current notification authority.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Dispatch data is immutable.','configuration.immutable');}
}
