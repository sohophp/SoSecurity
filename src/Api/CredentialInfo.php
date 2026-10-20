<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Exception\ConfigurationException;

/** Inert management metadata; no digest, bearer secret, account identity snapshot or authorization proof. */
final class CredentialInfo
{
    private $values;
    public function __construct(string $id,string $name,array $scopes,int $createdAt,int $issuedAt,int $expiresAt,int $generation,string $keyId,?int $lastUsedAt=null,?string $creatorReference=null,?string $issuerReference=null)
    {
        try{CredentialEncoding::id($id);CredentialEncoding::name($name);$scopes=CredentialEncoding::scopes($scopes);CredentialEncoding::version($generation);}catch(\InvalidArgumentException $error){throw new ConfigurationException('Invalid credential metadata.','configuration.api_credentials');}
        if($createdAt<0||$createdAt>PHP_INT_MAX-31536000||$issuedAt<$createdAt||$expiresAt<=$issuedAt||$expiresAt>$createdAt+31536000||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$keyId)||($lastUsedAt!==null&&($lastUsedAt<$createdAt||$lastUsedAt>=$expiresAt))){throw new ConfigurationException('Invalid bounded credential timestamps.','configuration.api_credentials');}
        foreach([$creatorReference,$issuerReference] as $reference){if($reference!==null&&!CredentialState::hex($reference,64)){throw new ConfigurationException('Invalid credential operator reference.','configuration.api_credentials');}}
        $this->values=['id'=>$id,'name'=>$name,'scopes'=>$scopes,'created_at'=>$createdAt,'issued_at'=>$issuedAt,'expires_at'=>$expiresAt,'generation'=>$generation,'key_id'=>$keyId,'last_used_at'=>$lastUsedAt,'creator_reference'=>$creatorReference,'issuer_reference'=>$issuerReference];
    }
    public function id():string {return $this->values['id'];}
    public function name():string {return $this->values['name'];}
    public function scopes():array {return $this->values['scopes'];}
    public function createdAt():int {return $this->values['created_at'];}
    public function issuedAt():int {return $this->values['issued_at'];}
    public function expiresAt():int {return $this->values['expires_at'];}
    public function generation():int {return $this->values['generation'];}
    public function keyId():string {return $this->values['key_id'];}
    public function lastUsedAt():?int {return $this->values['last_used_at'];}
    public function creatorReference():?string {return $this->values['creator_reference'];}
    public function issuerReference():?string {return $this->values['issuer_reference'];}
    public function toArray():array {return $this->values;}
    public function __debugInfo():array {return ['id'=>$this->id(),'generation'=>$this->generation(),'expires_at'=>$this->expiresAt(),'metadata'=>'[redacted]'];}
    public function __set(string $name,$value):void {CredentialEncoding::immutable();}
}
