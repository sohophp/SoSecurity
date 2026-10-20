<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Auth\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;

/** Exact server-built review data. This DTO is never an approval or a grant. */
final class FactorReplacementApproval
{
    private $read;
    public function __construct(string $context,string $selector,AccountRecord $record,Account $identity,FactorSlot $oldSlot,string $preparedScope,string $preparedSubject,string $preparedFactorId,int $expiresAt)
    {
        foreach([$preparedScope,$preparedSubject] as $label){Guard::label($label);if(preg_match('//u',$label)!==1){throw new ConfigurationException('Use bounded UTF-8 prepared factor labels.','configuration.factor_recovery');}}
        if(!preg_match('/\A[a-f0-9]{64}\z/D',$context)||!preg_match('/\A[a-f0-9]{64}\z/D',$selector)||$expiresAt<1||$expiresAt>PHP_INT_MAX-604800||$identity->scope()!==$record->account()->scope()||$identity->subject()!==$record->account()->subject()||$identity->roles()!==$record->account()->roles()||!$identity->enabled()||!$identity->mfaRequired()||!$record->verified()||$record->status()!=='active'||!$oldSlot->enabled()||!$record->account()->mfaRequired()||$oldSlot->subject()!==$identity->subject()||!preg_match('/\A[a-f0-9]{32}\z/D',$preparedFactorId)||($oldSlot->slotScope()===$preparedScope&&$oldSlot->slotSubject()===$preparedSubject)){
            throw new ConfigurationException('Use the current exact factor replacement review.','configuration.factor_recovery');
        }
        $this->read=static function()use($context,$selector,$record,$identity,$oldSlot,$preparedScope,$preparedSubject,$preparedFactorId,$expiresAt):array{return [$context,$selector,$record,$identity,$oldSlot,$preparedScope,$preparedSubject,$preparedFactorId,$expiresAt];};
    }
    public function purpose():string {return 'replace_factor';}
    public function context():string {return ($this->read)()[0];}
    public function selector():string {return ($this->read)()[1];}
    public function record():AccountRecord {return ($this->read)()[2];}
    public function identity():Account {return ($this->read)()[3];}
    public function oldSlot():FactorSlot {return ($this->read)()[4];}
    public function preparedScope():string {return ($this->read)()[5];}
    public function preparedSubject():string {return ($this->read)()[6];}
    public function preparedFactorId():string {return ($this->read)()[7];}
    public function expiresAt():int {return ($this->read)()[8];}
    public function __debugInfo():array {return ['factor_replacement_review'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize factor replacement reviews.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload the current factor replacement review.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Factor replacement reviews are immutable.','configuration.immutable');}
}
