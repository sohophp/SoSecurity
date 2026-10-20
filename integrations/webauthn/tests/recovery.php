<?php
declare(strict_types=1);

require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';

use SoSecurity\Storage\MemoryStore;
use SoSecurity\Support\Clock;
use SoSecurity\WebAuthn\BoundCeremonies;
use SoSecurity\WebAuthn\Ceremonies;
use SoSecurity\WebAuthn\ChallengeStore;
use SoSecurity\WebAuthn\PersistedCeremonies;
use SoSecurity\WebAuthn\RecoveryAuthority;
use SoSecurity\WebAuthn\RecoveryManager;
use SoSecurity\WebAuthn\SqlCredentialRepository;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

$pdo = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$pdo->exec(file_get_contents(dirname(__DIR__) . '/schema.sqlite.sql'));
$repository = new SqlCredentialRepository($pdo, 'recover-site');
$clock = new class implements Clock { public function now(): int { return 1000; } };
$authority = new class implements RecoveryAuthority {
    public $blocked = false;
    public $failComplete = false;
    public function begin(string $scope, string $userHandle, $proof, int $now): bool
    {
        if ($scope !== 'recover-site' || $userHandle !== 'alice' || $proof !== 'strong-approval') {
            return false;
        }
        $this->blocked = true;
        return true;
    }
    public function complete(string $scope, string $userHandle, int $generation, int $now): bool
    {
        return $this->blocked && !$this->failComplete && $generation > 0;
    }
};
$manager = new RecoveryManager($repository, $authority, $clock);
$challenges = new ChallengeStore(new MemoryStore($clock), 'recover-site', $clock);
$flow = new PersistedCeremonies(new BoundCeremonies(
    new Ceremonies('Test', 'example.test', 'https://example.test'), $challenges), $repository, $clock);
$record = static function (string $id): CredentialRecord {
    return CredentialRecord::create($id, 'public-key', [], 'none', EmptyTrustPath::create(),
        Uuid::v4(), 'not-a-real-key', 'alice', 0);
};
$repository->register($record('old-one'), 900, 0);
$repository->register($record('old-two'), 900, 0);
$user = PublicKeyCredentialUserEntity::create('alice', 'alice', 'Alice');
$oldRegistration = $flow->beginRegistration($user, 'session-a');
$oldLogin = $flow->beginAuthentication('alice', 'session-a');
$checks = 0;
if ($manager->recover('alice', 'bad-proof') !== null ||
    !$repository->find('old-one', 'alice') || $authority->blocked) {
    throw new RuntimeException('Denied recovery changed state');
}
++ $checks;
$generation = $manager->recover('alice', 'strong-approval');
if ($generation !== 1 || $repository->generation('alice') !== 1 ||
    $repository->forUser('alice') !== [] || !$authority->blocked) {
    throw new RuntimeException('Recovery did not revoke old devices');
}
++ $checks;
try {
    $flow->finishRegistration($oldRegistration['handle'], 'alice', 'session-a', '{}');
    throw new RuntimeException('Old enrollment challenge survived recovery');
} catch (InvalidArgumentException $e) {
    if ($e->getMessage() !== 'WebAuthn registration challenge is unavailable') { throw $e; }
    ++$checks;
}
try {
    $flow->finishAuthentication($oldLogin['handle'], 'alice', 'session-a', '{}', 'old-one');
    throw new RuntimeException('Old login challenge survived recovery');
} catch (InvalidArgumentException $e) {
    if ($e->getMessage() !== 'WebAuthn authentication challenge is unavailable') { throw $e; }
    ++$checks;
}
$newRegistration = $flow->beginRegistration($user, 'session-a');
try {
    $flow->finishRegistration($newRegistration['handle'], 'alice', 'session-a', '{}');
    throw new RuntimeException('Invalid WebAuthn attestation accepted');
} catch (InvalidArgumentException $e) {
    if ($e->getMessage() === 'WebAuthn registration challenge is unavailable') { throw $e; }
    ++$checks;
}
$repository->register($record('current'), 1100, 1);
$authority->failComplete = true;
try {
    $manager->recover('alice', 'strong-approval');
    throw new RuntimeException('Unknown recovery outcome was reported as success');
} catch (RuntimeException $e) {
    if ($e->getMessage() !== 'WebAuthn recovery outcome requires reconciliation') { throw $e; }
    ++$checks;
}
if ($repository->generation('alice') !== 2 || $repository->forUser('alice') !== []) {
    throw new RuntimeException('Unknown recovery outcome did not preserve SQL result');
}
++ $checks;
echo "WebAuthn recovery boundary: {$checks} checks passed\n";
