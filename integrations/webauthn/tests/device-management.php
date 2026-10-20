<?php
declare(strict_types=1);

require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';

use SoSecurity\Support\Clock;
use SoSecurity\WebAuthn\DeviceAuthority;
use SoSecurity\WebAuthn\DeviceManager;
use SoSecurity\WebAuthn\SqlCredentialRepository;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

$pdo = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$pdo->exec(file_get_contents(dirname(__DIR__) . '/schema.sqlite.sql'));
$repository = new SqlCredentialRepository($pdo, 'device-test');
$record = static function (string $id): CredentialRecord {
    return CredentialRecord::create($id, 'public-key', [], 'none', EmptyTrustPath::create(),
        Uuid::v4(), 'not-a-real-key', 'alice', 0);
};
$repository->register($record('one'), 100, 0);
$repository->register($record('two'), 100, 0);
$clock = new class implements Clock { public function now(): int { return 200; } };
$authority = new class implements DeviceAuthority {
    public $denyReturn = false;
    public $calls = 0;
    public function allow(string $phase, string $scope, string $userHandle, string $credentialId,
        $proof, int $now): bool
    {
        ++$this->calls;
        return $scope === 'device-test' && $userHandle === 'alice' && $proof === 'recent-proof' &&
            ($phase !== 'return' || !$this->denyReturn);
    }
};
$notices = [];
$manager = new DeviceManager($repository, $authority,
    static function (string $owner, string $id) use (&$notices): void { $notices[] = [$owner, $id]; }, $clock);
$checks = 0;
try { $manager->remove('alice', str_repeat('x', 1025), 'recent-proof'); }
catch (InvalidArgumentException $e) { ++$checks; }
if ($authority->calls !== 0) { throw new RuntimeException('Oversize ID reached authority'); }
if ($manager->remove('alice', 'one', 'wrong-proof') || count($repository->forUser('alice')) !== 2) {
    throw new RuntimeException('Unapproved removal changed devices');
}
++ $checks;
if ($manager->remove('bob', 'one', 'recent-proof') || count($repository->forUser('alice')) !== 2) {
    throw new RuntimeException('Cross-user removal changed devices');
}
++ $checks;
if (!$manager->remove('alice', 'one', 'recent-proof') || $repository->find('one', 'alice') !== null ||
    $notices !== [['alice', 'one']]) {
    throw new RuntimeException('Approved removal or notice failed');
}
++ $checks;
if ($manager->remove('alice', 'two', 'recent-proof') || count($repository->forUser('alice')) !== 1) {
    throw new RuntimeException('Last device removed without recovery');
}
++ $checks;
$repository->register($record('three'), 201, 1);
$authority->denyReturn = true;
try {
    $manager->remove('alice', 'three', 'recent-proof');
    throw new RuntimeException('Unknown outcome was reported as success');
} catch (RuntimeException $e) {
    if ($e->getMessage() === 'Unknown outcome was reported as success') { throw $e; }
    ++$checks;
}
if ($repository->find('three', 'alice') !== null || count($notices) !== 1) {
    throw new RuntimeException('Unknown outcome did not preserve actual SQL result');
}
++ $checks;
echo "WebAuthn guarded device management: {$checks} checks passed\n";
