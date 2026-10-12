<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Exception\ConfigurationException;

/** RFC 9421 hmac-sha256 cryptographic primitive; profile/parser/replay requirements are enforced by Signer/Verifier. */
final class Hmac
{
    public static function sign(string $base,string $secret): string
    {
        if (strlen($secret)<32 || strlen($secret)>128) { throw new ConfigurationException('Use a 32-128 byte HMAC secret.'); }
        return hash_hmac('sha256',$base,$secret,true);
    }
}
