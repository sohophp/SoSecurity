<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Exception\ConfigurationException;

/** Separate server-to-server HMAC material, supplied from private configuration/KMS. Never persisted as a bearer token. */
final class SigningKey
{
    private $secret;
    private $identity;
    public function __construct(string $id,string $secret,string $subject,array $scopes=[])
    {
        if (!preg_match('/\A[A-Za-z0-9._:-]{1,64}\z/D',$id) || strlen($secret)<32 || strlen($secret)>128) { throw new ConfigurationException('HMAC needs a bounded key ID and 32-128 byte secret.'); }
        $this->identity=new Identity($id,$subject,$scopes); $this->secret=$secret;
    }
    public static function generate(string $subject,array $scopes=[]): self { return new self(bin2hex(random_bytes(16)),random_bytes(32),$subject,$scopes); }
    public function secret(): string { return $this->secret; }
    public function identity(): Identity { return $this->identity; }
    public function __debugInfo(): array { return ['identity'=>$this->identity,'secret'=>'[redacted]']; }
    public function __set(string $name,$value): void { throw new ConfigurationException('Signing keys are immutable.','configuration.immutable'); }
}
