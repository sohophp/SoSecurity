<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Exception\ConfigurationException;

/** Plaintext is returned only by this successful issuance/rotation result, never by management queries. */
final class IssuedCredential
{
    private $token;
    private $metadata;
    public function __construct(string $token,CredentialInfo $metadata)
    {
        $parts=CredentialEncoding::parse($token);if($parts===null||$parts['id']!==$metadata->id()||$parts['generation']!==$metadata->generation()||$parts['expires']!==$metadata->expiresAt()||$parts['issued']!==$metadata->issuedAt()||$parts['key_id']!==$metadata->keyId()){throw new ConfigurationException('Invalid issued credential result.','configuration.api_credentials');}$this->token=static function()use($token):string{return $token;};$this->metadata=$metadata;
    }
    public function token():string {if(!$this->token instanceof \Closure){throw new ConfigurationException('Reload private API credential.','configuration.api_credential_serialization');}return ($this->token)();}
    public function metadata():CredentialInfo {return $this->metadata;}
    public function __debugInfo():array {return ['metadata'=>$this->metadata,'token'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize API bearer credentials.','configuration.api_credential_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Rebuild API bearer credentials from trusted state.','configuration.api_credential_serialization');}
    public function __set(string $name,$value):void {CredentialEncoding::immutable();}
}
