<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Auth\Account;
use SoSecurity\Exception\ConfigurationException;

/** Immediate request result. Effective scopes intersect issued capabilities with current server-side entitlement. */
final class VerifiedCredential
{
    private $account;
    private $metadata;
    private $scopes;
    public function __construct(Account $account,CredentialInfo $metadata,array $effectiveScopes)
    {
        $effectiveScopes=CredentialEncoding::scopes($effectiveScopes);if(!$account->enabled()||array_diff($effectiveScopes,$metadata->scopes())){throw new ConfigurationException('Invalid effective credential scope.','configuration.api_credentials');}$this->account=$account;$this->metadata=$metadata;$this->scopes=$effectiveScopes;
    }
    public function id():string {return $this->metadata->id();}
    public function account():Account {return $this->account;}
    public function metadata():CredentialInfo {return $this->metadata;}
    public function scopes():array {return $this->scopes;}
    public function allows(string $scope):bool {return in_array($scope,$this->scopes,true);}
    public function expiresAt():int {return $this->metadata->expiresAt();}
    public function __debugInfo():array {return ['id'=>$this->id(),'expires_at'=>$this->expiresAt(),'authority'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Revalidate actual bearer credentials on every request.','configuration.api_credential_serialization');}
    public function __set(string $name,$value):void {CredentialEncoding::immutable();}
}
