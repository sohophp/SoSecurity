<?php
declare(strict_types=1);
namespace SoSecurity\Examples;
use SoSecurity\Api\HmacVerifier;
use SoSecurity\Api\Identity;

/** Origin is trusted deployment configuration; target/body/headers are the unmodified request seen by this verifier. */
function authenticateSignedRequest(HmacVerifier $verifier,string $method,string $trustedOrigin,string $requestTarget,string $rawBody,array $headers,string $requiredScope): ?Identity
{
    if ($requestTarget==='' || $requestTarget[0]!=='/' || substr($requestTarget,0,2)==='//') { return null; }
    // No Host/X-Forwarded-* lookup, query parsing, percent decoding, JSON re-encoding or business side effects.
    return $verifier->verify($method,$trustedOrigin.$requestTarget,$rawBody,$headers,$requiredScope);
}
