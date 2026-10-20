<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use SoSecurity\Exception\ConfigurationException;

/** Challenge and notification lifetimes; request budgets remain a required host integration. */
final class Policy
{
    private $values=[];
    public function __construct(array $options=[])
    {
        $defaults=['registration_seconds'=>86400,'address_change_seconds'=>1800,'recovery_seconds'=>900,'notification_seconds'=>86400,'maximum_attempts'=>5,'resend_seconds'=>60,'maximum_resends'=>3,'maximum_entries'=>1000,'io_milliseconds'=>10000,'smtp_utf8'=>false];
        if(array_diff(array_keys($options),array_keys($defaults))){throw new ConfigurationException('Unknown account lifecycle policy.','configuration.account_policy');}
        foreach($defaults as $name=>$default){$value=array_key_exists($name,$options)?$options[$name]:$default;$this->values[$name]=$value;}
        foreach(['registration_seconds','address_change_seconds','recovery_seconds','notification_seconds'] as $name){$this->integer($name,1,604800);}
        $this->integer('maximum_attempts',1,10);$this->integer('resend_seconds',1,86400);$this->integer('maximum_resends',0,10);$this->integer('maximum_entries',1,100000);$this->integer('io_milliseconds',1,30000);
        if(!is_bool($this->values['smtp_utf8'])){throw new ConfigurationException('SMTPUTF8 support must be an explicit boolean.','configuration.account_policy');}
    }
    private function integer(string $name,int $minimum,int $maximum):void
    {
        $value=$this->values[$name];if(!is_int($value)||$value<$minimum||$value>$maximum){throw new ConfigurationException('Account lifecycle policy exceeds its bounds.','configuration.account_policy');}
    }
    public function lifetime(string $type):int
    {
        $map=['verify_registration'=>'registration_seconds','verify_address_old'=>'address_change_seconds','verify_address_new'=>'address_change_seconds','cancel_change'=>'address_change_seconds','recover_account'=>'recovery_seconds','recover_address'=>'recovery_seconds','account_activated'=>'notification_seconds','password_changed'=>'notification_seconds','address_changed'=>'notification_seconds','address_recovery_started'=>'notification_seconds','address_recovered'=>'notification_seconds'];
        if(Notice::supports($type)&&strpos($type,'factor_')===0){return $this->values['notification_seconds'];}
        if(!isset($map[$type])){throw new ConfigurationException('Use a fixed account notification type.','configuration.account_policy');}return $this->values[$map[$type]];
    }
    public function maximumAttempts():int {return $this->values['maximum_attempts'];}
    public function resendSeconds():int {return $this->values['resend_seconds'];}
    public function maximumResends():int {return $this->values['maximum_resends'];}
    public function maximumEntries():int {return $this->values['maximum_entries'];}
    public function ioMilliseconds():int {return $this->values['io_milliseconds'];}
    public function allowsSmtpUtf8():bool {return $this->values['smtp_utf8'];}
    public function options():array {return $this->values;}
    public function fingerprint():string {return hash('sha256',json_encode($this->values));}
    public function __set(string $name,$value):void {throw new ConfigurationException('Account lifecycle policy is immutable.','configuration.immutable');}
    public function __sleep():array {throw new ConfigurationException('Reload account policy explicitly.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload account policy from trusted configuration.','configuration.account_serialization');}
}
