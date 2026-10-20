<?php
declare(strict_types=1);

require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';

use SoSecurity\WebAuthn\SqlCredentialRepository;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

$pdo = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$schema = file_get_contents(dirname(__DIR__) . '/schema.sqlite.sql');
$old = preg_replace('/^    generation INTEGER NOT NULL DEFAULT 0 CHECK \(generation >= 0\),\n/m', '', $schema, 1, $count);
if ($count !== 1 || $old === null) { throw new RuntimeException('Old schema test setup failed'); }
$pdo->exec($old);
$scope = hash('sha256', 'migration-site');
$user = hash('sha256', 'alice');
$pdo->prepare('INSERT INTO sosecurity_webauthn_user (scope_hash,user_key,active_count) VALUES (:scope,:user,0)')
    ->execute(['scope' => $scope, 'user' => $user]);
$pdo->exec(file_get_contents(dirname(__DIR__) . '/migrations/001_generation.sqlite.sql'));
$repo = new SqlCredentialRepository($pdo, 'migration-site');
if ($repo->generation('alice') !== 0) { throw new RuntimeException('Migrated account generation changed'); }
$record = CredentialRecord::create('new-device', 'public-key', [], 'none', EmptyTrustPath::create(),
    Uuid::v4(), 'not-a-real-key', 'alice', 0);
$repo->register($record, 100, 0);
if (count($repo->forUser('alice')) !== 1) { throw new RuntimeException('Registration after migration failed'); }
echo "WebAuthn SQLite generation migration: existing account preserved\n";
