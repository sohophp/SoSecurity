<?php
declare(strict_types=1);

if ($argc !== 7) { fwrite(STDERR, "Expected autoload, issuer, session dir, session id, mode, and callback state.\n"); exit(2); }
require $argv[1];

use SoSecurity\Oidc\StrictClient;
use SoSecurity\Oidc\VerifiedSubject;
use SoSecurity\Oidc\VerifiedLogout;
use SoSecurity\Oidc\LogoutProcessor;
use SoSecurity\Oidc\LogoutFence;
use SoSecurity\Oidc\FederatedSessions;
use SoSecurity\Oidc\LinkRegistry;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\FileStore;

$issuer = $argv[2];
session_save_path($argv[3]);
session_id($argv[4]);
$client = new StrictClient($issuer, 'registered-client', str_repeat('s', 32),
    'https://site.example.test/oidc/callback', $issuer . '/authorize',
    $issuer . '/token', $issuer . '/keys');
$assertClientCleared = static function () use ($client): void {
    $export = var_export($client, true);
    if (strpos($export, str_repeat('s', 32)) !== false
        || strpos($export, 'local-access-token') !== false
        || strpos($export, 'external-subject') !== false
        || strpos($export, 'provider-session') !== false
        || $client->getAccessToken() !== null || $client->getIdToken() !== null
        || $client->getRefreshToken() !== null || $client->getTokenResponse() !== null
        || get_object_vars($client->getVerifiedClaims()) !== []) {
        throw new RuntimeException('OIDC client retained callback credentials.');
    }
};

if ($argv[5] === 'logout_process') {
    $store = new FileStore($argv[3], 'oidc-logout-test');
    $processor = new LogoutProcessor($store, $client);
    $calls = 0;
    $token = stream_get_contents(STDIN, 16385);
    $marker = $argv[3] . '/logout-revoked-' . hash('sha256', $token);
    try {
        $done = $processor->process('tenant', $token, static function (VerifiedLogout $proof, string $scope) use (&$calls, $marker, $argv): bool {
            ++$calls;
            if ($scope !== 'tenant' || $proof->issuer() === '') { throw new RuntimeException('Invalid logout callback.'); }
            if ($argv[6] === 'fail') { return false; }
            if ($argv[6] === 'throw') { throw new RuntimeException('Local host revocation failed.'); }
            if (file_put_contents($marker, 'revoked', LOCK_EX) !== 7) { throw new RuntimeException('Local revoke write failed.'); }
            if ($argv[6] === 'abort') { exit(7); }
            return true;
        });
        echo json_encode(['ok' => $done, 'calls' => $calls, 'revoked' => is_file($marker)]);
    } catch (Throwable $error) {
        echo json_encode(['ok' => false, 'calls' => $calls, 'revoked' => is_file($marker)]);
    }
    exit;
}

if ($argv[5] === 'logout') {
    try {
        $proof = VerifiedLogout::fromToken($client, stream_get_contents(STDIN, 16385));
        echo json_encode(['ok' => true, 'issuer' => $proof->issuer(), 'subject' => $proof->subject(),
            'sid' => $proof->sessionId(), 'jti' => $proof->tokenId()]);
    } catch (Throwable $error) {
        echo json_encode(['ok' => false, 'error' => get_class($error)]);
    }
    exit;
}

if ($argv[5] === 'begin') {
    register_shutdown_function(static function (): void {
        if (session_status() !== PHP_SESSION_ACTIVE) { session_start(); }
        echo json_encode(['state' => $_SESSION['openid_connect_state'] ?? null,
            'nonce' => $_SESSION['openid_connect_nonce'] ?? null,
            'verifier' => $_SESSION['openid_connect_code_verifier'] ?? null]);
        session_write_close();
    });
    VerifiedSubject::fromClient($client);
    exit(3);
}

$_REQUEST = ['code' => 'single-use-code', 'state' => $argv[6]];
try {
    $proof = VerifiedSubject::fromClient($client);
    if ($proof === null) { throw new RuntimeException('Callback did not produce a subject.'); }
    $assertClientCleared();
    $store = new MemoryStore();
    $account = new Account('tenant', 'local-alice', '1');
    $identity = new CallbackIdentityProvider(
        static function (string $scope, string $identifier, string $password) use ($account): ?Account {
            return $scope === 'tenant' && $identifier === 'local-alice' && $password === 'local-secret' ? $account : null;
        },
        static function (string $scope, string $subject) use ($account): ?Account {
            return $scope === 'tenant' && $subject === 'local-alice' ? $account : null;
        }
    );
    $guard = static function (): bool { return true; }; // Local test only; host protection is separate.
    $sessions = new SessionRegistry($store, $identity);
    $flow = new AuthenticationFlow($store, $identity, $sessions, $guard);
    $local = $flow->password('tenant', 'local-browser', 'local-alice', 'local-secret')->credential();
    $fence = new LogoutFence($store);
    $links = new LinkRegistry($store, $identity, $sessions, $guard, null, $fence);
    $links->link('tenant', 'local-alice', $local->token(), $proof);
    $resolved = $links->resolve('tenant', $proof);
    if ($resolved === null) { throw new RuntimeException('Verified external identity did not resolve.'); }
    $federation = new FederatedSessions($store, $identity, $links, $fence, $guard);
    $federated = $federation->issue('tenant', $proof);
    if ($federated === null || $federation->verify('tenant', 'local-alice', $federated->token()) === null) {
        throw new RuntimeException('Verified external identity did not issue a federated session.');
    }
    $fenced = null;
    if ($argv[5] === 'callback_fence') {
        $processor = new LogoutProcessor($store, $client);
        $processor->process('tenant', stream_get_contents(STDIN, 16385), [$federation, 'revokeFromProvider']);
        $fenced = $links->resolve('tenant', $proof) === null
            && $federation->verify('tenant', 'local-alice', $federated->token()) === null
            && $sessions->verify('tenant', 'local-alice', $local->token()) !== null;
        if (!$fenced) { throw new RuntimeException('Signed logout did not fence the external identity.'); }
    }
    echo json_encode(['ok' => true, 'issuer' => $proof->issuer(), 'subject' => $proof->subject(),
        'sid' => $proof->providerSessionId(), 'issued_at' => $proof->issuedAt(),
        'linked' => $resolved->subject(), 'federated' => true, 'fenced' => $fenced]);
} catch (Throwable $error) {
    $assertClientCleared();
    echo json_encode(['ok' => false, 'error' => get_class($error)]);
}
