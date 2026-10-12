<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Exception\ConfigurationException;

/** Immutable configuration snapshot. Rotation/revocation deploys a new ring to all verifiers, or uses a live KeyProvider. */
final class KeyRing implements KeyProvider
{
    private $keys=[];
    public function __construct(array $keys)
    {
        if (count($keys)>128) { throw new ConfigurationException('Too many signing keys.'); }
        foreach ($keys as $key) {
            if (!$key instanceof SigningKey || isset($this->keys[$key->identity()->id()])) { throw new ConfigurationException('Provide distinct SigningKey objects.'); }
            $this->keys[$key->identity()->id()]=$key;
        }
    }
    public function find(string $id): ?SigningKey { return $this->keys[$id] ?? null; }
}
