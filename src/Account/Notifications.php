<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use SoSecurity\Crypto\Cipher;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;

/** Encrypt the same-database notice ledger. Outbox stores a stable notice ID, never this mutable envelope. */
final class Notifications
{
    private $cipher;
    private $clock;
    private $observed=0;
    private $smtpUtf8;
    public function __construct(string $current,array $keys,?Clock $clock=null,bool $allowSmtpUtf8=false)
    {
        $cipher=new Cipher($current,$keys,'account.notifications',4096);$source=$clock ?? new SystemClock();
        // var_export() ignores __debugInfo(); captured values are not exported as object properties.
        $this->cipher=static function()use($cipher):Cipher{return $cipher;};$this->clock=static function()use($source):Clock{return $source;};$this->smtpUtf8=$allowSmtpUtf8;
    }
    private function cipher():Cipher {return ($this->cipher)();}
    private function clock():Clock {return ($this->clock)();}
    private function now():int
    {
        try{$now=$this->clock()->now();}catch(\Throwable $error){throw new StorageException('Account notification clock is unavailable.','account.clock');}
        if($now<0||$now>PHP_INT_MAX-604801||$now<$this->observed){throw new StorageException('Account notification clock is invalid or moved backwards.','account.clock');}$this->observed=$now;return $now;
    }
    private function binding(string $scope,string $id,string $type):string
    {
        \SoSecurity\Support\Guard::label($scope);
        if(preg_match('//u',$scope)!==1||!preg_match('/\A[a-f0-9]{64}\z/D',$id)||!Notice::supports($type)){throw new ValidationException('Use the original account notification context.','account.notice');}
        return 'SoSecurity.Account.Notice.1.'.hash('sha256',json_encode([$scope,$id,$type],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
    }
    private function current(Notice $notice,int $now):void
    {
        if($notice->issuedAt()>$now||$notice->expiresAt()<=$now){throw new ValidationException('Account notification is not current.','account.notice_expired');}
        if($notice->recipient()->requiresSmtpUtf8()&&!$this->smtpUtf8){throw new ConfigurationException('SMTPUTF8 delivery requires explicit transport support.','configuration.account_transport');}
    }
    public function seal(Notice $notice):string
    {
        $this->current($notice,$this->now());$encrypted=$this->cipher()->encrypt($notice->encode(),$this->binding($notice->scope(),$notice->id(),$notice->type()));$this->current($notice,$this->now());return $encrypted;
    }
    private function authenticate(string $envelope,string $scope,string $id,string $type):Notice
    {
        $binding=$this->binding($scope,$id,$type);$notice=Notice::decode($this->cipher()->decrypt($envelope,$binding));
        if($notice->scope()!==$scope||$notice->id()!==$id||$notice->type()!==$type){throw new ValidationException('Account notification context changed.','account.notice');}return $notice;
    }
    public function open(string $envelope,string $scope,string $id,string $type):Notice
    {
        $this->now();$notice=$this->authenticate($envelope,$scope,$id,$type);$this->current($notice,$this->now());return $notice;
    }
    /** Maintenance only: authenticate and retain the original expiry, including already expired history. */
    public function reencrypt(string $envelope,string $scope,string $id,string $type):string
    {
        $this->now();$notice=$this->authenticate($envelope,$scope,$id,$type);$encrypted=$this->cipher()->encrypt($notice->encode(),$this->binding($scope,$id,$type));$this->now();return $encrypted;
    }
    /** Maintenance metadata only. Expired history is authenticated without returning recipient or token. */
    public function metadata(string $envelope,string $scope,string $id,string $type):array
    {
        $this->now();$notice=$this->authenticate($envelope,$scope,$id,$type);$this->now();
        $parts=explode('.',$envelope);return ['key_id'=>$parts[1],'issued_at'=>$notice->issuedAt(),'expires_at'=>$notice->expiresAt()];
    }
    /** No I/O: validate injected capability/clock without decrypting or revealing a notice. */
    public function validateConfiguration(?Clock $clock=null,bool $requireSmtpUtf8=false):void
    {
        $source=$this->clock();
        if($clock!==null&&$source!==$clock&&!($source instanceof SystemClock&&$clock instanceof SystemClock)){throw new ConfigurationException('Account notifications must use the lifecycle clock.','configuration.account_notification_clock');}
        if($requireSmtpUtf8&&!$this->smtpUtf8){throw new ConfigurationException('Account SMTPUTF8 policy requires an explicitly capable notification codec.','configuration.account_transport');}
    }
    public function currentId():string {return $this->cipher()->currentId();}
    public function __debugInfo():array {return ['account_notifications'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize account notification keys.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload notification configuration explicitly.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Account notification configuration is immutable.','configuration.immutable');}
}
