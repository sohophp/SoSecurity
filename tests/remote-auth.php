<?php
declare(strict_types=1);
// Isolated CLI client of a loopback-only test authority; its HTTP transport is not a production SDK.
require __DIR__ . '/bootstrap.php';
require dirname(__DIR__) . '/examples/identity-providers.php';
$input = json_decode(stream_get_contents(STDIN), true); $base = getenv('SOSECURITY_TEST_AUTHORITY');
if (!is_string($base) || !preg_match('/\Ahttp:\/\/127\.0\.0\.1:[0-9]{1,5}\z/D', $base)) { throw new RuntimeException('Isolated test authority required.'); }
$send = static function (string $path, array $payload) use ($base) {
    $body = ''; $curl = curl_init($base . $path);
    curl_setopt_array($curl, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Authorization: Bearer fixed-integration-service'],
        CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROXY => '', CURLOPT_TIMEOUT_MS => 500, CURLOPT_CONNECTTIMEOUT_MS => 200,
        CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$body): int {
            if (strlen($body) + strlen($chunk) > 4096) { return 0; } $body .= $chunk; return strlen($chunk);
        }]);
    $ok = curl_exec($curl); $status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    // curl handle cleanup uses normal scope lifetime on modern PHP; no deprecated curl_close call.
    unset($curl);
    if ($ok === false || !in_array($status, [200, 401], true)) { throw new SoSecurity\Exception\SecurityException('Isolated authority unavailable.', 'auth.source_unavailable'); }
    if ($status === 401) { return null; }
    $result = json_decode($body, true, 8);
    if (!is_array($result) || !array_key_exists('account', $result)) { throw new SoSecurity\Exception\SecurityException('Invalid authority response.', 'auth.provider'); }
    return $result['account'];
};
$provider = SoSecurity\Examples\remoteIdentityProvider(
    static function (string $scope, string $id, string $password) use ($send) { return $send('/authenticate', ['scope' => $scope, 'identifier' => $id, 'password' => $password]); },
    static function (string $scope, string $subject) use ($send) { return $send('/current', ['scope' => $scope, 'subject' => $subject]); });
$store = new SoSecurity\Storage\FileStore(getenv('SOSECURITY_TEST_AUTHORITY_STORAGE'), 'remote-auth');
$sessions = new SoSecurity\Auth\SessionRegistry($store, $provider);
try {
    if ($input['operation'] === 'login') {
        $flow = new SoSecurity\Auth\AuthenticationFlow($store, $provider, $sessions, static function (): bool { return true; });
        $result = $flow->password('tenant', 'browser', 'demo', $input['password']);
        echo json_encode(['status' => $result->status(), 'token' => $result->credential() === null ? null : $result->credential()->token()]);
    } else {
        $verified = $sessions->verify('tenant', 'remote-subject', $input['token']);
        echo json_encode(['valid' => $verified !== null, 'subject' => $verified === null ? null : $verified->account()->subject()]);
    }
} catch (SoSecurity\Exception\SecurityException $e) { echo json_encode(['error' => $e->reason()]); }
