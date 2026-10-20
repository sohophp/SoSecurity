<?php
declare(strict_types=1);
require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__, 3) . '/tests/bootstrap.php';

use SoSecurity\Oidc\StrictClient;

$secret = 'synthetic-private-oidc-secret-9384';
$client = new StrictClient('https://issuer.example.test', 'registered-client', $secret,
    'https://site.example.test/oidc/callback', 'https://issuer.example.test/authorize',
    'https://issuer.example.test/token', 'https://issuer.example.test/keys');
ob_start(); var_dump($client); $dump = ob_get_clean();
foreach ([print_r($client, true), $dump, json_encode($client)] as $rendered) {
    Check::same(false, strpos($rendered, $secret) !== false);
}
Check::same(false, strpos(var_export($client, true), $secret) !== false);
Check::throws(RuntimeException::class, static function () use ($client): void { $client->getClientSecret(); });
Check::throws(RuntimeException::class, static function () use ($client): void { $client->authenticate(); });
Check::throws(RuntimeException::class, static function () use ($client): void { $client->redirect('https://other.example.test/'); });
Check::throws(RuntimeException::class, static function () use ($client): void { $client->setAccessToken('secret-access-token'); });
Check::throws(RuntimeException::class, static function () use ($client): void { $client->setIdToken('secret-id-token'); });
Check::throws(RuntimeException::class, static function () use ($client): void { $client->refreshToken('secret-refresh-token'); });
Check::throws(RuntimeException::class, static function () use ($client): void { $client->verifyLogoutToken(); });
foreach ([
    static function () use ($client): void { $client->setTokenEndpointAuthMethodsSupported(['none']); },
    static function () use ($client): void { $client->addRegistrationParam(['redirect_uris' => ['https://other.example.test']]); },
    static function () use ($client): void { $client->verifyLogoutTokenClaims((object)[]); },
    static function () use ($client): void { $client->requestClientCredentialsToken(); },
    static function () use ($client): void { $client->requestResourceOwnerToken(true); },
    static function () use ($client): void { $client->requestTokenExchange('opaque', 'urn:example:type'); },
    static function () use ($client): void { $client->signOut('opaque', 'https://site.example.test/logout'); },
    static function () use ($client): void { $client->register(); },
    static function () use ($client): void { $client->requestUserInfo(); },
    static function () use ($client): void { $client->introspectToken('opaque'); },
    static function () use ($client): void { $client->revokeToken('opaque'); },
] as $unsupported) { Check::throws(RuntimeException::class, $unsupported); }
Check::throws(RuntimeException::class, static function () use ($client): void { serialize($client); });
Check::throws(RuntimeException::class, static function (): void {
    unserialize('O:' . strlen(StrictClient::class) . ':"' . StrictClient::class . '":0:{}');
});
echo 'PASS OIDC client debug redaction: ' . Check::$assertions . ' assertions PHP ' . PHP_VERSION . "\n";
