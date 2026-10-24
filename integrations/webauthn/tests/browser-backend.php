<?php
declare(strict_types=1);

require getenv('SOSECURITY_WEBAUTHN_TEST_AUTOLOAD');

use SoSecurity\Storage\FileStore;
use SoSecurity\WebAuthn\BoundCeremonies;
use SoSecurity\WebAuthn\Ceremonies;
use SoSecurity\WebAuthn\ChallengeStore;
use SoSecurity\WebAuthn\DeviceAuthority;
use SoSecurity\WebAuthn\DeviceManager;
use SoSecurity\WebAuthn\PersistedCeremonies;
use SoSecurity\WebAuthn\SqlCredentialRepository;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredentialUserEntity;

$directory = realpath(getenv('SOSECURITY_WEBAUTHN_TEST_DIR') ?: '');
$origin = getenv('SOSECURITY_WEBAUTHN_TEST_ORIGIN');
if ($directory === false || !is_file($directory . '/owned-webauthn-test') ||
    !is_dir($directory . '/state') || !is_string($origin)) {
    throw new RuntimeException('Private WebAuthn browser test environment required');
}
$pdo = new PDO('sqlite:' . $directory . '/credentials.sqlite', null, null,
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$repository = new SqlCredentialRepository($pdo, 'browser-test');
$ceremonies = new Ceremonies('SoSecurity Browser Test', 'localhost', $origin);
$flow = new PersistedCeremonies(new BoundCeremonies($ceremonies,
    new ChallengeStore(new FileStore($directory . '/state', 'browser-test'), 'browser-test')),
    $repository);
$serializer = (new WebauthnSerializerFactory(AttestationStatementSupportManager::create([
    NoneAttestationStatementSupport::create(),
])))->create();
$user = PublicKeyCredentialUserEntity::create('alice', 'alice-id', 'Alice');
$session = 'browser-session';
$action = $argv[1] ?? '';
$handle = $argv[2] ?? '';
$readResponse = static function (): string {
    $body = stream_get_contents(STDIN, 65537);
    if (!is_string($body) || $body === '' || strlen($body) > 65536) {
        throw new InvalidArgumentException('Invalid browser response length');
    }
    return $body;
};
$b64 = static function (string $bytes): string { return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '='); };

if ($action === 'begin-register') {
    $pending = $flow->beginRegistration($user, $session);
    echo json_encode(['handle' => $pending['handle'],
        'options' => json_decode($serializer->serialize($pending['options'], 'json'), true)], JSON_THROW_ON_ERROR);
} elseif ($action === 'finish-register') {
    $record = $flow->finishRegistration($handle, $user->id, $session, $readResponse());
    echo json_encode(['id' => $b64($record->publicKeyCredentialId),
        'generation' => $repository->generation($user->id)], JSON_THROW_ON_ERROR);
} elseif ($action === 'begin-login') {
    $pending = $flow->beginAuthentication($user->id, $session);
    echo json_encode(['handle' => $pending['handle'],
        'options' => json_decode($serializer->serialize($pending['options'], 'json'), true)], JSON_THROW_ON_ERROR);
} elseif ($action === 'finish-login') {
    $encoded = $argv[3] ?? '';
    if (!preg_match('/\A[A-Za-z0-9_-]{1,1366}\z/D', $encoded)) {
        throw new InvalidArgumentException('Invalid credential ID encoding');
    }
    $id = base64_decode(strtr($encoded, '-_', '+/'), true);
    if (!is_string($id) || $id === '' || strlen($id) > 1024 || $b64($id) !== $encoded) {
        throw new InvalidArgumentException('Invalid credential ID');
    }
    $verified = $flow->finishAuthentication($handle, $user->id, $session, $readResponse(), $id);
    echo json_encode(['id' => $b64($verified->publicKeyCredentialId),
        'counter' => $verified->counter], JSON_THROW_ON_ERROR);
} elseif ($action === 'status') {
    echo json_encode(['devices' => count($repository->forUser($user->id)),
        'generation' => $repository->generation($user->id)], JSON_THROW_ON_ERROR);
} elseif ($action === 'signal') {
    $remaining = [];
    foreach ($repository->forUser($user->id) as $stored) {
        $remaining[] = $stored->record();
    }
    echo $ceremonies->acceptedCredentialsSignal($user, $remaining);
} elseif ($action === 'remove') {
    $encoded = $argv[3] ?? '';
    if (!preg_match('/\A[A-Za-z0-9_-]{1,1366}\z/D', $encoded)) {
        throw new InvalidArgumentException('Invalid credential ID encoding');
    }
    $id = base64_decode(strtr($encoded, '-_', '+/'), true);
    if (!is_string($id) || $id === '' || strlen($id) > 1024 || $b64($id) !== $encoded) {
        throw new InvalidArgumentException('Invalid credential ID');
    }
    $authority = new class implements DeviceAuthority {
        public function allow(string $phase, string $scope, string $userHandle, string $credentialId,
            $proof, int $now): bool
        {
            return ($phase === 'before' || $phase === 'current' || $phase === 'return') && $scope === 'browser-test' &&
                $userHandle === 'alice-id' && $proof === 'browser-test-recent-proof';
        }
    };
    $manager = new DeviceManager($repository, $authority, static function (): void {});
    echo json_encode(['removed' => $manager->remove($user->id, $id, 'browser-test-recent-proof')], JSON_THROW_ON_ERROR);
} else {
    throw new InvalidArgumentException('Unknown browser test action');
}
