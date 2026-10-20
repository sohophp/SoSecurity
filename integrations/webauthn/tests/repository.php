<?php
declare(strict_types=1);

require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';

use SoSecurity\WebAuthn\SqlCredentialRepository;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

$backend = $argv[2] ?? 'sqlite';
if ($backend === 'mysql') {
    $socket = getenv('SOSECURITY_TEST_MYSQL_SOCKET');
    if (!is_string($socket) || $socket === '') { throw new RuntimeException('Private MySQL test socket required'); }
    $pdo = new PDO('mysql:unix_socket=' . $socket . ';dbname=sosecurity_test;charset=utf8mb4',
        'sosecurity_test', 'integration-only', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false]);
    foreach (explode(';', file_get_contents(dirname(__DIR__) . '/schema.mysql.sql')) as $sql) {
        if (trim($sql) !== '') { $pdo->exec($sql); }
    }
} elseif ($backend === 'sqlite') {
    $pdo = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo->exec(file_get_contents(dirname(__DIR__) . '/schema.sqlite.sql'));
} else { throw new RuntimeException('Unknown test backend'); }
$repo = new SqlCredentialRepository($pdo, 'site-a');
$other = new SqlCredentialRepository($pdo, 'site-b');
$checks = 0;
$check = static function ($condition, string $message) use (&$checks): void {
    if (!$condition) { throw new RuntimeException($message); }
    ++$checks;
};
$record = static function (string $id, string $owner, int $counter = 0): CredentialRecord {
    return CredentialRecord::create($id, 'public-key', [], 'none', EmptyTrustPath::create(),
        Uuid::v4(), 'not-a-real-key', $owner, $counter);
};
$first = $record("device\0one", 'alice', 1);
$repo->register($first, 1000, 0);
$check($repo->generation('alice') === 0, 'Initial account generation incorrect');
$check($repo->find("device\0one", 'alice') !== null, 'NUL credential ID not found');
$check($repo->find("device\0one", 'bob') === null, 'Cross-user credential found');
$check($other->find("device\0one", 'alice') === null, 'Cross-site credential found');
$check(count($repo->forUser('alice')) === 1, 'User listing incorrect');
$check(count($repo->forUser('bob')) === 0, 'Other user listing incorrect');

$duplicate = false;
try { $repo->register($record("device\0one", 'bob'), 1001, 0); }
catch (PDOException $e) { $duplicate = true; }
$check($duplicate && $repo->find("device\0one", 'alice') !== null &&
    count($repo->forUser('bob')) === 0, 'Duplicate credential changed ownership');

$snapshot = $repo->find("device\0one", 'alice');
$updated = $snapshot->record();
$updated->counter = 2;
$check($repo->commitAssertion($snapshot, $updated, 1002), 'First assertion commit failed');
$check(!$repo->commitAssertion($snapshot, $updated, 1003), 'Stale assertion commit succeeded');
$check($repo->find("device\0one", 'alice')->record()->counter === 2, 'Counter not persisted');
$rollback = $repo->find("device\0one", 'alice');
$regressed = $rollback->record();
$regressed->counter = 1;
try { $repo->commitAssertion($rollback, $regressed, 1004); throw new RuntimeException('Counter rollback accepted'); }
catch (InvalidArgumentException $e) { ++$checks; }

$check($repo->revoke($rollback, 1005), 'Revocation failed');
$check(!$repo->revoke($rollback, 1006), 'Repeated revocation succeeded');
$check($repo->find("device\0one", 'alice') === null && count($repo->forUser('alice')) === 0,
    'Revoked credential remains active');
$check($repo->generation('alice') === 1, 'Device removal did not advance generation');
try { $repo->register($record('stale-device', 'alice'), 1007, 0); throw new RuntimeException('Stale generation registered'); }
catch (RuntimeException $e) {
    if ($e->getMessage() === 'Stale generation registered') { throw $e; }
    ++$checks;
}
$repo->register($record('device-two', 'alice'), 1007, 1);
$hash = hash('sha256', 'device-two');
$validJson = $backend === 'sqlite' ? $pdo->query('SELECT record_json FROM sosecurity_webauthn_credential '
    . "WHERE credential_key='" . $hash . "'")->fetchColumn() : null;
$sql = $backend === 'mysql'
    ? 'ALTER TABLE sosecurity_webauthn_credential MODIFY record_json LONGBLOB NOT NULL'
    : null;
if ($sql !== null) { $pdo->exec($sql); }
$sql = $backend === 'mysql'
    ? 'UPDATE sosecurity_webauthn_credential SET record_json=REPEAT(0x00,16777216) WHERE credential_key=:key'
    : 'UPDATE sosecurity_webauthn_credential SET record_json=zeroblob(16777216) WHERE credential_key=:key';
$pdo->prepare($sql)
    ->execute(['key' => $hash]);
try { $repo->find('device-two', 'alice'); throw new RuntimeException('Oversize record accepted'); }
catch (RuntimeException $e) {
    if ($e->getMessage() === 'Oversize record accepted') { throw $e; }
    ++$checks;
}
try { $repo->forUser('alice'); throw new RuntimeException('Oversize list record accepted'); }
catch (RuntimeException $e) {
    if ($e->getMessage() === 'Oversize list record accepted') { throw $e; }
    ++$checks;
}
if ($backend === 'sqlite') {
    // SQLite BLOB affinity still accepts TEXT; length(TEXT) stops at the first NUL.
    $pdo->prepare('UPDATE sosecurity_webauthn_credential SET record_json=CAST(zeroblob(16777216) AS TEXT) '
        . 'WHERE credential_key=:key')->execute(['key' => $hash]);
    $storedType = $pdo->query('SELECT typeof(record_json),length(record_json),'
        . 'length(CAST(record_json AS BLOB)) FROM sosecurity_webauthn_credential '
        . "WHERE credential_key='" . $hash . "'")->fetch(PDO::FETCH_NUM);
    $check($storedType === ['text', 0, 16777216] || $storedType === ['text', '0', '16777216'],
        'SQLite NUL TEXT test data was not created');
    try { $repo->find('device-two', 'alice'); throw new RuntimeException('Oversize NUL TEXT accepted'); }
    catch (RuntimeException $e) {
        if ($e->getMessage() === 'Oversize NUL TEXT accepted') { throw $e; }
        ++$checks;
    }
    try { $repo->forUser('alice'); throw new RuntimeException('Oversize NUL TEXT listed'); }
    catch (RuntimeException $e) {
        if ($e->getMessage() === 'Oversize NUL TEXT listed') { throw $e; }
        ++$checks;
    }
    $pdo->prepare('UPDATE sosecurity_webauthn_user SET generation=CAST(zeroblob(16777216) AS TEXT) '
        . 'WHERE user_key=:key')->execute(['key' => hash('sha256', 'alice')]);
    try { $repo->generation('alice'); throw new RuntimeException('Oversize generation accepted'); }
    catch (RuntimeException $e) {
        if ($e->getMessage() === 'Oversize generation accepted') { throw $e; }
        ++$checks;
    }
    $pdo->prepare('UPDATE sosecurity_webauthn_user SET generation=1 WHERE user_key=:key')
        ->execute(['key' => hash('sha256', 'alice')]);
    $pdo->prepare('UPDATE sosecurity_webauthn_credential SET record_json=:record, '
        . 'credential_key=CAST(zeroblob(16777216) AS TEXT) WHERE credential_key=:key')
        ->execute(['record' => $validJson, 'key' => $hash]);
    try { $repo->forUser('alice'); throw new RuntimeException('Oversize credential key listed'); }
    catch (RuntimeException $e) {
        if ($e->getMessage() === 'Oversize credential key listed') { throw $e; }
        ++$checks;
    }
    $pdo->prepare('UPDATE sosecurity_webauthn_credential SET credential_key=:key '
        . "WHERE typeof(credential_key)='text' AND length(CAST(credential_key AS BLOB))=16777216")
        ->execute(['key' => $hash]);
    $pdo->prepare('UPDATE sosecurity_webauthn_credential SET revision=CAST(zeroblob(16777216) AS TEXT) '
        . 'WHERE credential_key=:key')->execute(['key' => $hash]);
    try { $repo->forUser('alice'); throw new RuntimeException('Oversize revision listed'); }
    catch (RuntimeException $e) {
        if ($e->getMessage() === 'Oversize revision listed') { throw $e; }
        ++$checks;
    }
    $pdo->exec('PRAGMA ignore_check_constraints=ON');
    $pdo->prepare('UPDATE sosecurity_webauthn_user SET active_count=CAST(zeroblob(16777216) AS TEXT) '
        . 'WHERE user_key=:key')->execute(['key' => hash('sha256', 'alice')]);
    try { $repo->register($record('alice-new', 'alice'), 1010, 1);
        throw new RuntimeException('Oversize device count accepted'); }
    catch (RuntimeException $e) {
        if ($e->getMessage() === 'Oversize device count accepted') { throw $e; }
        ++$checks;
    }
    $pdo->prepare('UPDATE sosecurity_webauthn_user SET active_count=1 WHERE user_key=:key')
        ->execute(['key' => hash('sha256', 'alice')]);
    $pdo->exec('PRAGMA ignore_check_constraints=OFF');
}
for ($i = 0; $i < 32; ++$i) { $repo->register($record('bob-' . $i, 'bob'), 2000 + $i, 0); }
$check(count($repo->forUser('bob')) === 32, 'Device capacity count incorrect');
try { $repo->register($record('bob-32', 'bob'), 2032, 0); throw new RuntimeException('Capacity overflow accepted'); }
catch (RuntimeException $e) {
    if ($e->getMessage() === 'Capacity overflow accepted') { throw $e; }
    ++$checks;
}
$check(count($repo->forUser('bob')) === 32, 'Capacity rejection changed stored devices');
$generation = $repo->revokeAllForRecovery('bob', 2100);
$check($generation === 1 && $repo->generation('bob') === 1 && $repo->forUser('bob') === [],
    'Recovery failed to revoke all devices and advance generation');
try { $repo->register($record('bob-old-challenge', 'bob'), 2101, 0); throw new RuntimeException('Old recovery challenge registered'); }
catch (RuntimeException $e) {
    if ($e->getMessage() === 'Old recovery challenge registered') { throw $e; }
    ++$checks;
}
$repo->register($record('bob-new-challenge', 'bob'), 2102, 1);
$check(count($repo->forUser('bob')) === 1, 'Current recovery generation could not re-enroll');
$check($repo->revokeAllForRecovery('no-device', 2200) === 1 &&
    $repo->generation('no-device') === 1, 'Empty-account recovery did not advance generation');
$repo->register($record('carol-one', 'carol'), 3000, 0);
$repo->register($record('carol-two', 'carol'), 3000, 0);
$check($repo->revokeKeepingOne($repo->find('carol-one', 'carol'), 3001), 'First guarded revocation failed');
$check(!$repo->revokeKeepingOne($repo->find('carol-two', 'carol'), 3002) &&
    count($repo->forUser('carol')) === 1, 'Last-device guard failed');
echo "WebAuthn {$backend} repository: {$checks} checks passed\n";
