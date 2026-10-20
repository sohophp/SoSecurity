<?php
declare(strict_types=1);
namespace SoSecurity\Outbox;
use SoSecurity\Exception\ConfigurationException;

/** Returned only after claim COMMIT/current-authority checks; token remains secret and is not a delivery ID. */
final class Claim
{
    private $status;
    private $message;
    private $token;
    public function __construct(Status $status,Message $message,string $token)
    {
        if($status->state()!=='leased'||$status->id()!==$message->id()||!preg_match('/\Ac1\.[a-f0-9]{64}\.[a-f0-9]{64}\z/D',$token)){throw new ConfigurationException('Invalid outbox claim.','configuration.outbox');}
        $this->status=$status;$this->message=$message;$this->token=static function()use($token):string{return $token;};
    }
    public function status():Status {return $this->status;}
    public function message():Message {return $this->message;}
    public function token():string {return ($this->token)();}
    public function __debugInfo():array {return ['outbox_claim'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize claim secrets.','configuration.outbox_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload trusted Outbox data; do not deserialize capabilities.','configuration.outbox_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Outbox claims are immutable.','configuration.immutable');}
}
