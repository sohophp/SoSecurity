<?php
declare(strict_types=1);
namespace SoSecurity\Support;
use SoSecurity\Exception\ConfigurationException;

/** Immutable private key snapshot; separate material for each protocol/application. No plaintext getter. */
final class HmacKeys
{
    private $keys=[];
    private $current;
    public function __construct(string $current,array $keys)
    {
        if (count($keys)<1 || count($keys)>8) { throw new ConfigurationException('Provide 1-8 HMAC keys.','configuration.keys'); }
        foreach ($keys as $id=>$secret) {
            if (!is_string($id) || !preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$id) || !is_string($secret) || strlen($secret)<32 || strlen($secret)>128) {
                throw new ConfigurationException('HMAC key IDs and 32-128 byte secrets are required.','configuration.keys');
            }
            $this->keys[$id]=$secret;
        }
        if (!isset($this->keys[$current])) { throw new ConfigurationException('Current HMAC key is missing.','configuration.keys'); }
        $this->current=$current;
    }
    public function currentId(): string { return $this->current; }
    public function sign(string $message): string
    {
        $this->message($message); return hash_hmac('sha256',$message,$this->keys[$this->current],true);
    }
    public function verify(string $id,string $message,string $mac): bool
    {
        $this->message($message);
        return isset($this->keys[$id]) && strlen($mac)===32 && hash_equals(hash_hmac('sha256',$message,$this->keys[$id],true),$mac);
    }
    private function message(string $message): void
    {
        if (strlen($message)>16384) { throw new ConfigurationException('HMAC message exceeds 16 KiB.','configuration.hmac_message'); }
    }
    public function __debugInfo(): array { return ['current'=>$this->current,'key_ids'=>array_keys($this->keys),'secrets'=>'[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Do not serialize private signing keys.','configuration.keys_serialization'); }
    public function __set(string $name,$value): void { throw new ConfigurationException('HMAC keys are immutable.','configuration.immutable'); }
}
