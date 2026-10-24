<?php
declare(strict_types=1);

require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';

use SoSecurity\Auth\Account;
use SoSecurity\Auth\IdentityProvider;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Support\Clock;
use SoSecurity\WebAuthn\DeviceManager;
use SoSecurity\WebAuthn\SessionDeviceAuthority;
use SoSecurity\WebAuthn\SqlCredentialRepository;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

$clock = new class implements Clock {
    public $time = 1000;
    public function now(): int { return $this->time; }
};
$account = new Account('host-test', 'alice', 'v1');
$provider = new class($account) implements IdentityProvider {
    private $account;
    public function __construct(Account $account) { $this->account = $account; }
    public function authenticate(string $scope, string $identifier, string $password): ?Account { return null; }
    public function find(string $scope, string $subject): ?Account
    {
        return $scope === 'host-test' && $subject === 'alice' ? $this->account : null;
    }
};
$store = new MemoryStore($clock);
$sessions = new SessionRegistry($store, $provider, null, $clock, 600, 1200);
$csrf = new CsrfTokens($store, 600, 16, $clock);
$epoch = $sessions->epoch('host-test', 'alice');
$fingerprint = hash('sha256', $account->fingerprint() . ':none');
$credential = $sessions->register('host-test', 'alice', $fingerprint, $epoch, 'webauthn');
if ($credential === null) { throw new RuntimeException('Cannot establish trusted test session'); }
$current = ['subject' => 'alice', 'token' => $credential->token(), 'binding' => 'host-session-binding'];
$calls = 0;
$revokeOnCall = 0;
$reference = static function () use (&$current, &$calls, &$revokeOnCall, $sessions): array {
    ++$calls;
    if ($revokeOnCall > 0 && $calls === $revokeOnCall) {
        $sessions->revoke('host-test', 'alice', SessionRegistry::reference($current['token'])['id']);
    }
    return $current;
};
$authority = new SessionDeviceAuthority('host-test', $sessions, $csrf, $reference, $clock);
$pdo = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$pdo->exec(file_get_contents(dirname(__DIR__) . '/schema.sqlite.sql'));
$repository = new SqlCredentialRepository($pdo, 'host-test');
$record = static function (string $id): CredentialRecord {
    return CredentialRecord::create($id, 'public-key', [], 'none', EmptyTrustPath::create(),
        Uuid::v4(), 'not-a-real-key', 'alice', 0);
};
$repository->register($record('first'), 900, 0);
$repository->register($record('second'), 900, 0);
$notices = [];
$manager = new DeviceManager($repository, $authority,
    static function (string $owner, string $id) use (&$notices): void { $notices[] = [$owner, $id]; }, $clock);
$checks = 0;

$proof = $authority->issueRemovalProof('alice', 'first');
if ($manager->remove('alice', 'first', 'bad-proof') || count($repository->forUser('alice')) !== 2) {
    throw new RuntimeException('Invalid proof changed devices');
}
++ $checks;
if ($manager->remove('alice', 'second', $proof) || count($repository->forUser('alice')) !== 2) {
    throw new RuntimeException('Proof was not bound to exact device');
}
++ $checks;
$current['subject'] = 'bob';
if ($manager->remove('alice', 'first', $proof) || count($repository->forUser('alice')) !== 2) {
    throw new RuntimeException('Other subject could remove device');
}
++ $checks;
$current['subject'] = 'alice';
$interrupted = $authority->issueRemovalProof('alice', 'second');
if (!$authority->allow('before', 'host-test', 'alice', 'second', $interrupted, $clock->now())) {
    throw new RuntimeException('Valid return-phase test proof was not accepted');
}
$current['subject'] = 'bob';
if ($authority->allow('return', 'host-test', 'alice', 'second', $interrupted, $clock->now())) {
    throw new RuntimeException('Changed subject passed return-phase check');
}
++ $checks;
$current['subject'] = 'alice';
if ($authority->allow('return', 'host-test', 'alice', 'second', $interrupted, $clock->now())) {
    throw new RuntimeException('Denied return-phase authorization was replayed');
}
++ $checks;
if (!$manager->remove('alice', 'first', $proof) || $repository->find('first', 'alice') !== null ||
    $notices !== [['alice', 'first']]) {
    throw new RuntimeException('Current session did not authorize removal');
}
++ $checks;
if ($authority->allow('return', 'host-test', 'alice', 'first', $proof, $clock->now())) {
    throw new RuntimeException('Return-phase authorization was replayed');
}
++ $checks;
if ($manager->remove('alice', 'first', $proof) || count($repository->forUser('alice')) !== 1) {
    throw new RuntimeException('One-use proof was replayed');
}
++ $checks;
$lastProof = $authority->issueRemovalProof('alice', 'second');
if ($manager->remove('alice', 'second', $lastProof) || count($repository->forUser('alice')) !== 1) {
    throw new RuntimeException('Last device was removed');
}
++ $checks;
$clock->time = 1300;
try {
    $authority->issueRemovalProof('alice', 'second');
    throw new RuntimeException('Stale authentication issued removal proof');
} catch (SecurityException $e) { ++$checks; }
$epoch = $sessions->epoch('host-test', 'alice');
$replacement = $sessions->register('host-test', 'alice', $fingerprint, $epoch, 'webauthn');
if ($replacement === null) { throw new RuntimeException('Cannot renew trusted test session'); }
$current['token'] = $replacement->token();
$repository->register($record('third'), 1300, 1);
$proof = $authority->issueRemovalProof('alice', 'third');
$calls = 0;
$revokeOnCall = 3; // before, current, then the post-mutation return phase.
try {
    $manager->remove('alice', 'third', $proof);
    throw new RuntimeException('Revoked session reported a certain outcome');
} catch (RuntimeException $e) {
    if ($e->getMessage() !== 'WebAuthn removal outcome requires reconciliation') { throw $e; }
    ++$checks;
}
if ($repository->find('third', 'alice') !== null || count($notices) !== 1) {
    throw new RuntimeException('Unknown outcome was not preserved for reconciliation');
}
++ $checks;
$revokeOnCall = 0;
$replacement = $sessions->register('host-test', 'alice', $fingerprint,
    $sessions->epoch('host-test', 'alice'), 'webauthn');
if ($replacement === null) { throw new RuntimeException('Cannot renew trusted session for current-phase test'); }
$current['token'] = $replacement->token();
$repository->register($record('fourth'), 1300, $repository->generation('alice'));
$proof = $authority->issueRemovalProof('alice', 'fourth');
$calls = 0;
$revokeOnCall = 2;
if ($manager->remove('alice', 'fourth', $proof) || $repository->find('fourth', 'alice') === null ||
    count($repository->forUser('alice')) !== 2 || count($notices) !== 1) {
    throw new RuntimeException('Current-phase session withdrawal changed devices');
}
++$checks;
if ($authority->allow('return', 'host-test', 'alice', 'fourth', $proof, $clock->now())) {
    throw new RuntimeException('Denied current-phase authority retained a return grant');
}
++$checks;
echo "WebAuthn host session device authority: {$checks} checks passed\n";
