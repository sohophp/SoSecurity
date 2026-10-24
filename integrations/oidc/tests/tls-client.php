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
    $withMfa = $argv[5] === 'callback_mfa';
    $clock = $withMfa ? new class implements \SoSecurity\Support\Clock {
        public $time;
        public function __construct() { $this->time = time() - 60; }
        public function now(): int { return $this->time; }
    } : null;
    $store = new MemoryStore($clock);
    $account = new Account('tenant', 'local-alice', '1', true, [], $withMfa);
    $factor = null;
    if ($withMfa) {
        $totp = new \SoSecurity\Mfa\Totp();
        $mfa = new \SoSecurity\Mfa\TotpFactors($store, new \SoSecurity\Crypto\Cipher('test', ['test' => str_repeat('K', 32)], 'oidc-tls-mfa'), 'Test', $clock);
        $enrollment = $mfa->begin('tenant', 'local-alice', 'alice@example.test');
        parse_str(parse_url($enrollment->provisioningUri(), PHP_URL_QUERY), $parts);
        $secret = $parts['secret'];
        if ($mfa->confirm('tenant', 'local-alice', $enrollment->id(), $totp->codeAt($secret, $clock->time)) === null) { throw new RuntimeException('Local factor enrollment failed.'); }
        $factor = new \SoSecurity\Auth\TotpSecondFactor($mfa);
    }
    $identity = new CallbackIdentityProvider(
        static function (string $scope, string $identifier, string $password) use ($account): ?Account {
            return $scope === 'tenant' && $identifier === 'local-alice' && $password === 'local-secret' ? $account : null;
        },
        static function (string $scope, string $subject) use ($account): ?Account {
            return $scope === 'tenant' && $subject === 'local-alice' ? $account : null;
        }
    );
    $guard = static function (): bool { return true; }; // Local test only; host protection is separate.
    $sessions = new SessionRegistry($store, $identity, $factor, $clock);
    $flow = new AuthenticationFlow($store, $identity, $sessions, $guard, $factor, $clock);
    $localResult = $flow->password('tenant', 'local-browser', 'local-alice', 'local-secret');
    if ($withMfa) {
        $clock->time += 30;
        $localResult = $flow->secondFactor('tenant', 'local-browser', $localResult->challenge(), ['type' => 'totp', 'code' => $totp->codeAt($secret, $clock->time)]);
    }
    $local = $localResult->credential();
    $fence = new LogoutFence($store, $clock);
    $links = new LinkRegistry($store, $identity, $sessions, $guard, $clock, $fence);
    $links->link('tenant', 'local-alice', $local->token(), $proof);
    $resolved = $links->resolve('tenant', $proof);
    if ($resolved === null) { throw new RuntimeException('Verified external identity did not resolve.'); }
    $federation = new FederatedSessions($store, $identity, $links, $fence, $guard, $factor, $clock);
    if ($withMfa) {
        if ($federation->issue('tenant', $proof) !== null) { throw new RuntimeException('MFA was bypassed by issue.'); }
        $pending = $federation->begin('tenant', 'oidc-browser', $proof);
        if ($pending->status() !== 'mfa_required') { throw new RuntimeException('MFA challenge was not required.'); }
        $clock->time += 30;
        $completed = $federation->secondFactor('tenant', 'oidc-browser', $pending->challenge(), ['type' => 'totp', 'code' => $totp->codeAt($secret, $clock->time)]);
        $federated = $completed->credential();
    } else { $federated = $federation->issue('tenant', $proof); }
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
    $result = ['ok' => true, 'issuer' => $proof->issuer(), 'subject' => $proof->subject(),
        'sid' => $proof->providerSessionId(), 'issued_at' => $proof->issuedAt(),
        'linked' => $resolved->subject(), 'federated' => true, 'fenced' => $fenced];
    if ($withMfa) { $result['mfa'] = $federation->verify('tenant', 'local-alice', $federated->token())->secondFactorMethod(); }
    echo json_encode($result);
} catch (Throwable $error) {
    $assertClientCleared();
    echo json_encode(['ok' => false, 'error' => get_class($error)]);
}
