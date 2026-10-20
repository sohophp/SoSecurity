<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

/** A private immutable single-recipient message. wire() explicitly exports sensitive content to a transport. */
final class MailMessage
{
    private $read;
    public function __construct(Address $sender,Address $recipient,string $messageId,string $subject,string $body,int $createdAt)
    {
        if(strlen($messageId)>254||!preg_match('/\A<sosecurity-[a-f0-9]{64}@[a-z0-9.-]+>\z/D',$messageId)||strlen($subject)>128||!preg_match('/\A[\x20-\x7e]{1,128}\z/D',$subject)||strlen($body)>8192||strpos($body,"\0")!==false||preg_match('//u',$body)!==1||$createdAt<0){throw new ValidationException('Use bounded server-built mail content.','account.mail_message');}
        $wire='Date: '.gmdate('D, d M Y H:i:s +0000',$createdAt)."\r\n".'Message-ID: '.$messageId."\r\n".'From: <'.$sender->value().">\r\n".'To: <'.$recipient->value().">\r\n".'Subject: '.$subject."\r\n"."Auto-Submitted: auto-generated\r\nX-Auto-Response-Suppress: All\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n".chunk_split(base64_encode($body),76,"\r\n");
        $this->read=static function()use($sender,$recipient,$messageId,$subject,$wire):array{return [$sender,$recipient,$messageId,$subject,$wire];};
    }
    public function sender():Address {return ($this->read)()[0];}
    public function recipient():Address {return ($this->read)()[1];}
    public function messageId():string {return ($this->read)()[2];}
    public function wire():string {return ($this->read)()[4];}
    public function requiresSmtpUtf8():bool {return $this->sender()->requiresSmtpUtf8()||$this->recipient()->requiresSmtpUtf8();}
    public function __debugInfo():array {return ['account_mail_message'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize mail content.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload current authorized mail content.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Mail content is immutable.','configuration.immutable');}
}
