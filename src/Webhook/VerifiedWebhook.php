<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use SoSecurity\Exception\ConfigurationException;

/** Ephemeral authenticated bytes, not a durable business receipt, client session or deserializeable authority. */
final class VerifiedWebhook
{
    private $endpoint;
    private $request;
    private $id;
    private $timestamp;
    private $keyId;
    private $verified;
    public function __construct(Endpoint $endpoint,Request $request,?string $messageId,?int $timestamp,string $keyId,int $verifiedAt)
    {
        $standard=in_array($endpoint->protocol(),['standard-hmac','standard-ed25519'],true);$timed=$endpoint->protocol()!=='github-sha256';
        if(($messageId!==null&&(!preg_match('/\A[!-~]{1,256}\z/D',$messageId)||strpos($messageId,'.')!==false))||($timestamp!==null&&($timestamp<0||$timestamp>PHP_INT_MAX-$endpoint->tolerance()-1))||($messageId!==null)!==$standard||($timestamp!==null)!==$timed||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$keyId)||$verifiedAt<0||$verifiedAt>PHP_INT_MAX-1024||$request->method()!=='POST'||!hash_equals($endpoint->url(),$request->url())||strlen($request->body())>$endpoint->maximumBody()){throw new ConfigurationException('Invalid verified webhook metadata.','configuration.webhook');}
        $this->endpoint=$endpoint;$this->request=$request;$this->id=$messageId;$this->timestamp=$timestamp;$this->keyId=$keyId;$this->verified=$verifiedAt;
    }
    public function endpoint():Endpoint {return $this->endpoint;}
    public function body():string {return $this->request->body();}
    public function bodyDigest():string {return hash('sha256',$this->request->body());}
    public function messageId():?string {return $this->id;}
    public function timestamp():?int {return $this->timestamp;}
    public function keyId():string {return $this->keyId;}
    public function verifiedAt():int {return $this->verified;}
    public function expiresAt():?int {return $this->timestamp===null?null:$this->timestamp+$this->endpoint->tolerance()+1;}
    public function __debugInfo():array {return ['endpoint'=>$this->endpoint->id(),'proof'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize webhook authority.','configuration.webhook_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Webhook proofs are immutable.','configuration.immutable');}
}
