<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Support\Guard;

/** Sensitive delivery data only. Neither this value nor its ciphertext authorizes an account mutation. */
final class Notice
{
    private $scope;
    private $id;
    private $type;
    private $recipient;
    private $token;
    private $issued;
    private $expires;
    public function __construct(string $scope,string $id,string $type,Address $recipient,string $token,int $issuedAt,int $expiresAt)
    {
        Guard::label($scope);
        if(preg_match('//u',$scope)!==1||!preg_match('/\A[a-f0-9]{64}\z/D',$id)||!self::supports($type)||$issuedAt<0||$issuedAt>PHP_INT_MAX-604800||$expiresAt<=$issuedAt||$expiresAt-$issuedAt>604800){self::invalid();}
        $challenge=in_array($type,['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account','recover_address'],true);
        if(($challenge&&!preg_match('/\A[a-f0-9]{64}\z/D',$token))||(!$challenge&&$token!=='')){self::invalid();}
        $this->scope=$scope;$this->id=$id;$this->type=$type;$this->recipient=$recipient;$this->token=static function()use($token):string{return $token;};$this->issued=$issuedAt;$this->expires=$expiresAt;
    }
    public static function supports(string $type):bool {return in_array($type,['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account','recover_address','account_activated','password_changed','address_changed','address_recovery_started','address_recovered','factor_management_started','factor_management_completed','factor_management_abandoned','factor_enrollment_started','factor_enrollment_prepared','factor_enrolled','factor_enrollment_cancelled','factor_enrollment_cleaned','factor_management_cleaned','factor_privileged_revoked','factor_recovery_started','factor_replaced','factor_recovery_cancelled','factor_recovery_purged','factor_migration_reserved','factor_migration_completed','factor_migration_activated','factor_migration_cancelled','factor_migration_reapproved','factor_restoration_started','factor_restoration_activated','factor_restoration_cancelled','factor_restoration_cleaned','factor_restoration_previous_cleaned'],true);}
    /** @return never */
    private static function invalid():void {throw new ValidationException('Invalid bounded account notification.','account.notice');}
    public function scope():string {return $this->scope;}
    public function id():string {return $this->id;}
    public function type():string {return $this->type;}
    public function recipient():Address {return $this->recipient;}
    public function token():string {return ($this->token)();}
    public function issuedAt():int {return $this->issued;}
    public function expiresAt():int {return $this->expires;}
    /** Internal transport codec; contains secrets. Never use for logs or public responses. */
    public function encode():string
    {
        return json_encode(['format'=>1,'scope'=>$this->scope,'id'=>$this->id,'type'=>$this->type,'recipient'=>$this->recipient->value(),'smtp_utf8'=>$this->recipient->requiresSmtpUtf8(),'token'=>$this->token(),'issued_at'=>$this->issued,'expires_at'=>$this->expires],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    }
    public static function decode(string $encoded):self
    {
        if(strlen($encoded)>4096){self::invalid();}$data=json_decode($encoded,true,4);
        $fields=['format','scope','id','type','recipient','smtp_utf8','token','issued_at','expires_at'];
        if(!is_array($data)||array_keys($data)!==$fields||$data['format']!==1||!is_bool($data['smtp_utf8'])||!is_int($data['issued_at'])||!is_int($data['expires_at'])){self::invalid();}
        foreach(['scope','id','type','recipient','token'] as $field){if(!is_string($data[$field])){self::invalid();}}
        try{$notice=new self($data['scope'],$data['id'],$data['type'],new Address($data['recipient'],$data['smtp_utf8']),$data['token'],$data['issued_at'],$data['expires_at']);}
        catch(ConfigurationException $error){self::invalid();}catch(ValidationException $error){self::invalid();}
        // Reject duplicate keys, coercion, alternate encodings, unknown fields and noncanonical recipients.
        if($notice->encode()!==$encoded){self::invalid();}return $notice;
    }
    public function __debugInfo():array {return ['account_notice'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize notification recipients or secrets.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Notification values cannot be deserialized.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Account notifications are immutable.','configuration.immutable');}
}
