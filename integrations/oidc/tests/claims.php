<?php
declare(strict_types=1);
require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';

use SoSecurity\Oidc\StrictClient;

class TestStrictClient extends StrictClient
{
    private $testNonce = 'fixed-test-nonce';
    protected function getState() { return 'fixed-test-state'; }
    protected function getNonce() { return $this->testNonce; }
    public function nonce(string $value): void { $this->testNonce = $value; }
    public function probe(object $claims, string $algorithm = 'RS256'): bool
    {
        $header = rtrim(strtr(base64_encode(json_encode(['alg' => $algorithm])), '+/', '-_'), '=');
        $body = rtrim(strtr(base64_encode(json_encode($claims)), '+/', '-_'), '=');
        $this->idToken = $header . '.' . $body . '.test';
        return $this->verifyJWTClaims($claims);
    }
    public function authenticate(): bool { return true; }
    public function claims($claims): void { $this->verifiedClaims = $claims; }
}

$checks = 0;
$check = static function ($expected, $actual) use (&$checks): void {
    ++$checks;
    if ($expected !== $actual) { throw new RuntimeException('Unexpected OIDC claim decision.'); }
};
$config = ['https://issuer.example.test', 'registered-client', str_repeat('s', 32),
    'https://site.example.test/oidc/callback', 'https://issuer.example.test/authorize',
    'https://issuer.example.test/token', 'https://issuer.example.test/keys'];
$client = new TestStrictClient(...$config);
foreach ([
    static function () use ($client): void { $client->setVerifyPeer(false); },
    static function () use ($client): void { $client->setVerifyHost(false); },
    static function () use ($client): void { $client->setAllowImplicitFlow(true); },
    static function () use ($client): void { $client->setIssuerValidator(static function (): bool { return true; }); },
    static function () use ($client): void { $client->setResponseTypes(['id_token']); },
    static function () use ($client): void { $client->setCodeChallengeMethod('plain'); },
    static function () use ($client): void { $client->providerConfigParam(['jwks_uri' => 'https://other.example.test']); },
    static function () use ($client): void { $client->setClientID('other-client'); },
    static function () use ($client): void { $client->setHttpProxy('http://127.0.0.1:8080'); },
] as $mutation) {
    try { $mutation(); throw new RuntimeException('OIDC configuration mutation accepted.'); }
    catch (RuntimeException $e) { if ($e->getMessage() === 'OIDC configuration mutation accepted.') { throw $e; } ++$checks; }
}
$now = time();
$valid = (object)['iss' => $config[0], 'sub' => 'subject-123', 'sid' => 'provider-session', 'aud' => $config[1],
    'nonce' => 'fixed-test-nonce', 'iat' => $now, 'exp' => $now + 300];
$check(true, $client->probe($valid));
$withoutSid = clone $valid;
unset($withoutSid->sid);
$check(true, $client->probe($withoutSid));
$nullSid = clone $valid;
$nullSid->sid = null;
$check(false, $client->probe($nullSid));
foreach ([
    ['nonce', null], ['nonce', 'other'], ['iss', 'https://other.example.test'], ['sub', ''],
    ['sub', "bad\0sub"], ['sid', "bad\0sid"], ['sid', str_repeat('s', 256)],
    ['aud', 'other-client'], ['aud', [$config[1]]], ['exp', null],
    ['exp', $now - 1], ['exp', $now + 90000], ['iat', null], ['iat', $now + 70],
    ['iat', $now - 90000], ['azp', 'other-client'], ['auth_time', $now + 70],
] as $case) {
    $claims = clone $valid;
    if ($case[1] === null) { unset($claims->{$case[0]}); }
    else { $claims->{$case[0]} = $case[1]; }
    $check(false, $client->probe($claims));
}
$check(false, $client->probe($valid, 'HS256'));
$client->nonce('different'); $check(false, $client->probe($valid));
$client->nonce('fixed-test-nonce');
$client->claims($valid);
$check(['issuer' => $config[0], 'subject' => 'subject-123', 'issued_at' => $now, 'sid' => 'provider-session'], $client->authenticateSubject());
$originalRequest = $_REQUEST;
try {
    foreach ([
        ['code' => 'test-code', 'state' => 'wrong-state'],
        ['code' => ['bad'], 'state' => 'fixed-test-state'],
        ['code' => str_repeat('c', 2049), 'state' => 'fixed-test-state'],
        ['code' => 'test-code'],
    ] as $request) {
        $_REQUEST = $request;
        try { $client->authenticateSubject(); throw new RuntimeException('Forged callback accepted.'); }
        catch (RuntimeException $e) { if ($e->getMessage() === 'Forged callback accepted.') { throw $e; } ++$checks; }
    }
    $_REQUEST = ['code' => 'test-code', 'state' => 'fixed-test-state'];
    $client->claims($valid);
    $check(['issuer' => $config[0], 'subject' => 'subject-123', 'issued_at' => $now, 'sid' => 'provider-session'], $client->authenticateSubject());
} finally { $_REQUEST = $originalRequest; }
$client->claims((object)['iss' => $config[0], 'sub' => "bad\0sub"]);
try { $client->authenticateSubject(); throw new RuntimeException('Invalid verified subject accepted.'); }
catch (RuntimeException $e) { if ($e->getMessage() === 'Invalid verified subject accepted.') { throw $e; } ++$checks; }
foreach (['http://issuer.example.test', 'https://127.0.0.1', 'https://user@issuer.example.test',
    'https://issuer.example.test/path#fragment', 'https://issuer.example.test/path?query=1'] as $uri) {
    $bad = $config; $bad[0] = $uri;
    try { new TestStrictClient(...$bad); throw new RuntimeException('Unsafe OIDC URL accepted.'); }
    catch (InvalidArgumentException $e) { ++$checks; }
}
echo 'PASS strict OIDC claim boundary: ' . $checks . ' assertions PHP ' . PHP_VERSION . "\n";
