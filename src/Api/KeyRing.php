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
    /** Actual immutable key material/identity snapshot; no raw secret or caller data is exported. */
    public function stateDigest():string
    {
        $rows=[];foreach($this->keys as $id=>$key){$identity=$key->identity();$scopes=$identity->scopes();sort($scopes,SORT_STRING);$rows[$id]=[$identity->subject(),$scopes,bin2hex(Hmac::sign('SoSecurity.Api.KeyRing.Material.1.',$key->secret()))];}ksort($rows,SORT_STRING);return hash('sha256','SoSecurity.Api.KeyRing.State.1.'.json_encode($rows,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
    }
    public function find(string $id): ?SigningKey { return $this->keys[$id] ?? null; }
}
