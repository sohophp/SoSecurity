<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Auth\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;

/** Server-built review data. This value is never an approval, identity proof or reusable grant. */
final class RecoveryApproval
{
    private $read;
    public function __construct(string $purpose,string $context,AccountRecord $record,Account $identity,string $factorBinding,Address $target,int $expiresAt)
    {
        if($purpose!=='recover_address'||!preg_match('/\A[a-f0-9]{64}\z/D',$context)||$expiresAt<1||$expiresAt>PHP_INT_MAX-604800||$identity->scope()!==$record->account()->scope()||$identity->subject()!==$record->account()->subject()||$identity->roles()!==$record->account()->roles()||$identity->mfaRequired()!==$record->account()->mfaRequired()||$identity->enabled()!==$record->account()->enabled()||$target->equals($record->address())){throw new ConfigurationException('Use the original bounded recovery review context.','configuration.account_recovery_approval');}
        if($factorBinding!==''){Guard::label($factorBinding);if(preg_match('//u',$factorBinding)!==1){throw new ConfigurationException('Use the current factor binding.','configuration.account_recovery_approval');}}
        $this->read=static function()use($purpose,$context,$record,$identity,$factorBinding,$target,$expiresAt):array{return [$purpose,$context,$record,$identity,$factorBinding,$target,$expiresAt];};
    }
    public function purpose():string {return ($this->read)()[0];}
    public function context():string {return ($this->read)()[1];}
    public function record():AccountRecord {return ($this->read)()[2];}
    public function identity():Account {return ($this->read)()[3];}
    public function factorBinding():string {return ($this->read)()[4];}
    public function target():Address {return ($this->read)()[5];}
    public function expiresAt():int {return ($this->read)()[6];}
    public function __debugInfo():array {return ['recovery_approval'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize recovery review data.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload current recovery review data.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Recovery review data is immutable.','configuration.immutable');}
}
