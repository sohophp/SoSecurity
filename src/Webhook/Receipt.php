<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use SoSecurity\Exception\ConfigurationException;

/** Inert receive metadata. It is neither a processing result nor reusable business authorization. */
final class Receipt
{
    private $id;
    private $endpoint;
    private $message;
    private $digest;
    private $received;
    private $duplicate;
    public function __construct(string $id,string $endpointKey,string $messageId,string $bodyDigest,int $receivedAt,bool $duplicate)
    {
        if(!preg_match('/\A[a-f0-9]{32}\z/D',$id)||!preg_match('/\A[a-f0-9]{64}\z/D',$endpointKey)||!preg_match('/\A[!-~]{1,256}\z/D',$messageId)||!preg_match('/\A[a-f0-9]{64}\z/D',$bodyDigest)||$receivedAt<0||$receivedAt>PHP_INT_MAX-1024){throw new ConfigurationException('Invalid webhook receive metadata.','configuration.webhook');}
        $this->id=$id;$this->endpoint=$endpointKey;$this->message=$messageId;$this->digest=$bodyDigest;$this->received=$receivedAt;$this->duplicate=$duplicate;
    }
    public function id():string {return $this->id;}
    public function endpointKey():string {return $this->endpoint;}
    public function messageId():string {return $this->message;}
    public function bodyDigest():string {return $this->digest;}
    public function receivedAt():int {return $this->received;}
    public function duplicate():bool {return $this->duplicate;}
    public function toArray():array {return ['id'=>$this->id,'endpoint_key'=>$this->endpoint,'message_id'=>$this->message,'body_digest'=>$this->digest,'received_at'=>$this->received,'duplicate'=>$this->duplicate];}
    public function __debugInfo():array {return ['duplicate'=>$this->duplicate,'receipt'=>'[redacted]'];}
    public function __set(string $name,$value):void {throw new ConfigurationException('Webhook receive metadata is immutable.','configuration.immutable');}
}
