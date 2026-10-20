<?php
declare(strict_types=1);

namespace SoSecurity\Crypto;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Support\Guard;

/** Versioned XChaCha20-Poly1305 envelopes. Callers supply a stable, trusted object binding. */
final class Cipher
{
    private $current;
    private $keys = [];
    private $purpose;
    private $maximum;

    public function __construct(string $current, array $keys, string $purpose, int $maximumBytes = 65536)
    {
        if (!extension_loaded('sodium') || !function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
            throw new DependencyException('Authenticated encryption requires ext-sodium with XChaCha20-Poly1305.', 'dependency.sodium');
        }
        if (count($keys) < 1 || count($keys) > 8 || $maximumBytes < 1 || $maximumBytes > 1048576) {
            throw new ConfigurationException('Provide 1-8 encryption keys and a 1 byte to 1 MiB plaintext budget.', 'configuration.encryption');
        }
        foreach ($keys as $id => $key) {
            if (!is_string($id) || !preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D', $id)
                || !is_string($key) || strlen($key) !== 32) {
                throw new ConfigurationException('Encryption keys require a named ID and exactly 32 random bytes.', 'configuration.encryption_keys');
            }
            $this->keys[$id]=static function()use($key):string{return $key;};
        }
        if (!isset($this->keys[$current])) { throw new ConfigurationException('Current encryption key is missing.', 'configuration.encryption_keys'); }
        $this->current = $current;
        $this->purpose = Guard::label($purpose);
        $this->maximum = $maximumBytes;
    }

    public function encrypt(string $plaintext, string $binding): string
    {
        if (strlen($plaintext) > $this->maximum) { throw new ValidationException('Plaintext exceeds its budget.', 'crypto.size'); }
        $aad = $this->aad($this->current, $binding);
        $nonce = random_bytes(24);
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $this->secret($this->current));
        return 'sosc1.' . $this->current . '.' . rtrim(strtr(base64_encode($nonce . $ciphertext), '+/', '-_'), '=');
    }

    public function decrypt(string $envelope, string $binding): string
    {
        // Bound input before decoding. Authenticate the envelope version, key ID, purpose and object binding.
        if (strlen($envelope) > (int) ceil(($this->maximum + 40) / 3) * 4 + 40
            || !preg_match('/\Asosc1\.([A-Za-z][A-Za-z0-9_-]{0,31})\.([A-Za-z0-9_-]+)\z/D', $envelope, $parts)) {
            throw new ValidationException('Invalid encrypted envelope.', 'crypto.envelope');
        }
        $aad = $this->aad($parts[1], $binding);
        if (!isset($this->keys[$parts[1]])) { throw new ValidationException('Encrypted envelope cannot be authenticated.', 'crypto.authentication'); }
        $raw = base64_decode(strtr($parts[2], '-_', '+/'), true);
        if (!is_string($raw) || strlen($raw) < 40 || strlen($raw) > $this->maximum + 40
            || rtrim(strtr(base64_encode($raw), '+/', '-_'), '=') !== $parts[2]) {
            throw new ValidationException('Invalid encrypted envelope.', 'crypto.envelope');
        }
        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(substr($raw, 24), $aad, substr($raw, 0, 24), $this->secret($parts[1]));
        if (!is_string($plaintext)) { throw new ValidationException('Encrypted envelope cannot be authenticated.', 'crypto.authentication'); }
        return $plaintext;
    }

    /** Re-authenticate before replacing an envelope; caller saves with a compare-and-swap/transaction. */
    public function reencrypt(string $envelope, string $binding): string
    {
        return $this->encrypt($this->decrypt($envelope, $binding), $binding);
    }

    public function currentId(): string { return $this->current; }

    private function aad(string $id, string $binding): string
    {
        Guard::key('encryption', $this->purpose, $binding);
        // Length prefixes accept binary bindings and avoid ambiguous concatenation.
        return 'SoSecurity.AEAD.1.' . strlen($id) . ':' . $id . strlen($this->purpose) . ':' . $this->purpose . strlen($binding) . ':' . $binding;
    }

    /** Keep raw key bytes out of var_export; reject unsupported reconstructed object state. */
    private function secret(string $id):string
    {
        $value=$this->keys[$id] ?? null;
        if(!$value instanceof \Closure){throw new ConfigurationException('Reload private key configuration.','configuration.encryption_keys');}
        return $value();
    }

    public function __debugInfo(): array { return ['current' => $this->current, 'key_ids' => array_keys($this->keys), 'purpose' => $this->purpose, 'keys' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Do not serialize encryption keys.', 'configuration.keys_serialization'); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Cipher configuration is immutable.', 'configuration.immutable'); }
}
