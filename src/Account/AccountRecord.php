<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use SoSecurity\Auth\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;

/** Fresh host account snapshot. It is data, not proof of caller identity or mailbox ownership. */
final class AccountRecord
{
    private $read;
    public function __construct(Account $account,Address $address,string $addressVersion,bool $verified,string $status)
    {
        Guard::label($addressVersion);
        if(preg_match('//u',$addressVersion)!==1||!in_array($status,['pending','active','disabled'],true)||$account->enabled()!==($status==='active')||($status==='pending'&&$verified)){
            throw new ConfigurationException('Host account state differs from its lifecycle contract.','configuration.account_repository');
        }
        $this->read=static function()use($account,$address,$addressVersion,$verified,$status):array{return [$account,$address,$addressVersion,$verified,$status];};
    }
    public function account():Account {return ($this->read)()[0];}
    public function address():Address {return ($this->read)()[1];}
    public function addressVersion():string {return ($this->read)()[2];}
    public function verified():bool {return ($this->read)()[3];}
    public function status():string {return ($this->read)()[4];}
    /** Internal equality check; never publish this as an account-existence or authentication API. */
    public function fingerprint():string {return hash('sha256',json_encode([$this->account()->fingerprint(),$this->address()->value(),$this->addressVersion(),$this->verified(),$this->status()],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));}
    public function __debugInfo():array {return ['account_record'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload current host accounts instead of serializing snapshots.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Host snapshots cannot be deserialized.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Host snapshots are immutable.','configuration.immutable');}
}
