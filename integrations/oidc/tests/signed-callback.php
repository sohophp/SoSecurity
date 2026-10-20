<?php
declare(strict_types=1);
require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__, 3) . '/tests/bootstrap.php';

use Jumbojett\OpenIDConnectClientException;
use SoSecurity\Oidc\StrictClient;
use SoSecurity\Oidc\VerifiedSubject;

final class LocalSignedOidcClient extends StrictClient
{
    public $redirectUrl;
    public $idToken;
    public $jwks;
    public $tokenRequests = 0;
    public $keyRequests = 0;

    public function redirect(string $url) { $this->redirectUrl = $url; }

    protected function fetchURL(string $url, string $post_body = null, array $headers = [])
    {
        if ($url === 'https://issuer.example.test/keys') {
            ++$this->keyRequests;
            return json_encode($this->jwks);
        }
        if ($url === 'https://issuer.example.test/token') {
            ++$this->tokenRequests;
            parse_str((string)$post_body, $fields);
            if (($fields['code'] ?? null) !== 'single-use-code'
                || ($fields['code_verifier'] ?? null) !== ($_SESSION['openid_connect_code_verifier'] ?? null)
                || count($headers) !== 1 || strpos($headers[0], 'Authorization: Basic ') !== 0) {
                throw new RuntimeException('Invalid local token exchange.');
            }
            return json_encode(['access_token' => 'local-access-token', 'id_token' => $this->idToken]);
        }
        throw new RuntimeException('Unexpected OIDC endpoint.');
    }
}

function localSignedClient(): LocalSignedOidcClient
{
    return new LocalSignedOidcClient('https://issuer.example.test', 'registered-client', str_repeat('s', 32),
        'https://site.example.test/oidc/callback', 'https://issuer.example.test/authorize',
        'https://issuer.example.test/token', 'https://issuer.example.test/keys');
}

function url64(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function signedIdToken($key, array $claims, string $algorithm = 'RS256'): string
{
    $header = url64(json_encode(['typ' => 'JWT', 'alg' => $algorithm, 'kid' => 'local-key']));
    $body = url64(json_encode($claims));
    $signed = $header . '.' . $body;
    if (!openssl_sign($signed, $signature, $key, $algorithm === 'RS384' ? OPENSSL_ALGO_SHA384 : OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException('Could not sign local ID token.');
    }
    return $signed . '.' . url64($signature);
}

$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
if ($key === false) { throw new RuntimeException('Local RSA key generation failed.'); }
$details = openssl_pkey_get_details($key);
$jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'local-key', 'alg' => 'RS256', 'use' => 'sig',
    'n' => url64($details['rsa']['n']), 'e' => url64($details['rsa']['e'])]]];
$testSessionDir = privateDirectory();
$oldSessionPath = session_save_path($testSessionDir);
session_id('oidc-' . bin2hex(random_bytes(8)));
$originalRequest = $_REQUEST;
try {
    foreach (['valid', 'wrong-state', 'bad-signature', 'wrong-nonce', 'wrong-audience',
        'wrong-issuer', 'nul-subject', 'future-issued', 'expired', 'bad-algorithm'] as $case) {
        $_REQUEST = [];
        $client = localSignedClient();
        $client->jwks = $jwks;
        Check::same(null, $client->authenticateSubject());
        parse_str(parse_url($client->redirectUrl, PHP_URL_QUERY), $authorization);
        Check::same('code', $authorization['response_type'] ?? null);
        Check::same('S256', $authorization['code_challenge_method'] ?? null);
        if (session_status() !== PHP_SESSION_ACTIVE) { session_start(); }
        $verifier = $_SESSION['openid_connect_code_verifier'] ?? null;
        Check::same(url64(hash('sha256', $verifier, true)), $authorization['code_challenge'] ?? null);
        Check::same($_SESSION['openid_connect_nonce'] ?? null, $authorization['nonce'] ?? null);
        Check::same($_SESSION['openid_connect_state'] ?? null, $authorization['state'] ?? null);
        $claims = ['iss' => 'https://issuer.example.test', 'sub' => 'external-subject', 'sid' => 'provider-session',
            'aud' => 'registered-client', 'nonce' => $authorization['nonce'],
            'iat' => time(), 'exp' => time() + 300];
        if ($case === 'wrong-nonce') { $claims['nonce'] = 'other-nonce'; }
        if ($case === 'wrong-audience') { $claims['aud'] = 'other-client'; }
        if ($case === 'wrong-issuer') { $claims['iss'] = 'https://other.example.test'; }
        if ($case === 'nul-subject') { $claims['sub'] = "bad\0subject"; }
        if ($case === 'future-issued') { $claims['iat'] = time() + 120; }
        if ($case === 'expired') { $claims['exp'] = time() - 1; }
        $client->idToken = signedIdToken($key, $claims, $case === 'bad-algorithm' ? 'RS384' : 'RS256');
        if ($case === 'bad-signature') {
            $parts = explode('.', $client->idToken);
            $parts[2][0] = $parts[2][0] === 'A' ? 'B' : 'A';
            $client->idToken = implode('.', $parts);
        }
        $_REQUEST = ['code' => 'single-use-code', 'state' => $case === 'wrong-state' ? 'wrong-state' : $authorization['state']];
        if ($case === 'valid') {
            Check::same(['issuer' => 'https://issuer.example.test', 'subject' => 'external-subject',
                'issued_at' => $claims['iat'], 'sid' => 'provider-session'],
                $client->authenticateSubject());
            Check::same(1, $client->tokenRequests);
            Check::same(1, $client->keyRequests);
            Check::throws(RuntimeException::class, static function () use ($client): void {
                VerifiedSubject::fromClient($client);
            });
        } elseif ($case === 'wrong-state') {
            Check::throws(RuntimeException::class, static function () use ($client): void { $client->authenticateSubject(); });
            Check::same(0, $client->tokenRequests);
            Check::same(0, $client->keyRequests);
        } else {
            Check::throws(OpenIDConnectClientException::class, static function () use ($client): void {
                $client->authenticateSubject();
            });
            Check::same(1, $client->tokenRequests);
        }
    }
} finally {
    $_REQUEST = $originalRequest;
    if (session_status() === PHP_SESSION_ACTIVE) { session_write_close(); }
    cleanDirectory($testSessionDir);
    session_save_path($oldSessionPath);
}
echo 'PASS local signed OIDC callback: ' . Check::$assertions . ' assertions PHP ' . PHP_VERSION . "\n";
