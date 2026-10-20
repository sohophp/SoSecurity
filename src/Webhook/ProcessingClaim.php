<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use SoSecurity\Exception\ConfigurationException;

/** Claim token is a private worker credential; execute revalidates the sealed database row and current authority. */
final class ProcessingClaim
{
    private $token;
    private $status;
    public function __construct(string $token,ProcessingStatus $status)
    {
        if(!preg_match('/\Awc1\.[a-f0-9]{32}\.[1-9][0-9]{0,18}\.[a-f0-9]{64}\z/D',$token)||$status->status()!=='leased'){throw new ConfigurationException('Invalid processing claim.','configuration.webhook_processing');}$this->token=static function()use($token):string{return $token;};$this->status=$status;
    }
    public function token():string {if(!$this->token instanceof \Closure){throw new ConfigurationException('Reload private processing claim.','configuration.webhook_serialization');}return ($this->token)();}
    public function metadata():ProcessingStatus {return $this->status;}
    public function __debugInfo():array {return ['credential'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize worker credentials.','configuration.webhook_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Rebuild worker credentials from trusted state.','configuration.webhook_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Processing claims are immutable.','configuration.immutable');}
}
