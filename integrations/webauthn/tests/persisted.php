<?php
declare(strict_types=1);

require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';

use SoSecurity\Storage\MemoryStore;
use SoSecurity\Support\Clock;
use SoSecurity\WebAuthn\BoundCeremonies;
use SoSecurity\WebAuthn\Ceremonies;
use SoSecurity\WebAuthn\ChallengeStore;
use SoSecurity\WebAuthn\PersistedCeremonies;
use SoSecurity\WebAuthn\SqlCredentialRepository;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

$pdo = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$pdo->exec(file_get_contents(dirname(__DIR__) . '/schema.sqlite.sql'));
$repository = new SqlCredentialRepository($pdo, 'test');
$clock = new class implements Clock {
    public function now(): int { return 1000; }
};
$challenges = new ChallengeStore(new MemoryStore($clock), 'test', $clock);
$flow = new PersistedCeremonies(new BoundCeremonies(
    new Ceremonies('Test', 'example.test', 'https://example.test'), $challenges), $repository, $clock);
$record = CredentialRecord::create('device-one', 'public-key', [], 'none', EmptyTrustPath::create(),
    Uuid::v4(), 'not-a-real-key', 'alice', 1);
$repository->register($record, 900, 0);
$user = PublicKeyCredentialUserEntity::create('alice', 'alice', 'Alice');
$checks = 0;
$registration = $flow->beginRegistration($user, 'session-a');
if (count($registration['options']->excludeCredentials) !== 1) {
    throw new RuntimeException('Existing authenticator not excluded');
}
++ $checks;
$authentication = $flow->beginAuthentication('alice', 'session-a');
if (count($authentication['options']->allowCredentials) !== 1) {
    throw new RuntimeException('Stored authenticator not allowed');
}
++ $checks;
try {
    $flow->finishAuthentication($authentication['handle'], 'alice', 'session-a', '{}', 'missing');
    throw new RuntimeException('Unknown credential accepted');
} catch (InvalidArgumentException $e) { ++$checks; }
try {
    $flow->finishAuthentication($authentication['handle'], 'alice', 'session-a', '{}', 'device-one');
    throw new RuntimeException('Unknown credential did not burn challenge');
} catch (InvalidArgumentException $e) {
    if ($e->getMessage() !== 'WebAuthn authentication challenge is unavailable') { throw $e; }
    ++$checks;
}
$authentication = $flow->beginAuthentication('alice', 'session-a');
try {
    $flow->finishAuthentication($authentication['handle'], 'alice', 'session-a', str_repeat('x', 65537), 'device-one');
    throw new RuntimeException('Oversize assertion accepted');
} catch (InvalidArgumentException $e) { ++$checks; }
if ($repository->find('device-one', 'alice')->record()->counter !== 1) {
    throw new RuntimeException('Rejected assertion changed credential');
}
++ $checks;
echo "WebAuthn persisted ceremony: {$checks} checks passed\n";
