<?php
declare(strict_types=1);

require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';

use SoSecurity\WebAuthn\SqlCredentialRepository;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

if (!extension_loaded('pcntl')) { fwrite(STDERR, "NOT RUN: pcntl required\n"); exit(2); }
$file = tempnam(sys_get_temp_dir(), 'sosecurity-webauthn-recovery-');
if ($file === false) { throw new RuntimeException('Cannot allocate local test database'); }
try {
    $connect = static function () use ($file): PDO {
        $pdo = new PDO('sqlite:' . $file, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $pdo->exec('PRAGMA busy_timeout=5000');
        return $pdo;
    };
    $pdo = $connect();
    $pdo->exec(file_get_contents(dirname(__DIR__) . '/schema.sqlite.sql'));
    $parent = new SqlCredentialRepository($pdo, 'race');
    $parent->register(CredentialRecord::create('original', 'public-key', [], 'none',
        EmptyTrustPath::create(), Uuid::v4(), 'not-a-real-key', 'alice', 0), 100, 0);
    $children = [];
    foreach (['register', 'recover'] as $action) {
        $pid = pcntl_fork();
        if ($pid === -1) { throw new RuntimeException('Cannot fork recovery racer'); }
        if ($pid === 0) {
            try {
                $repo = new SqlCredentialRepository($connect(), 'race');
                if ($action === 'recover') { exit($repo->revokeAllForRecovery('alice', 200) === 1 ? 0 : 2); }
                $record = CredentialRecord::create('late', 'public-key', [], 'none',
                    EmptyTrustPath::create(), Uuid::v4(), 'not-a-real-key', 'alice', 0);
                try { $repo->register($record, 200, 0); exit(0); }
                catch (RuntimeException $e) {
                    if ($e->getMessage() === 'WebAuthn registration generation changed') { exit(1); }
                    throw $e;
                }
            } catch (Throwable $e) {
                fwrite(STDERR, "Recovery race child failed: " . get_class($e) . "\n");
                exit(2);
            }
        }
        $children[$action] = $pid;
    }
    foreach ($children as $action => $pid) {
        pcntl_waitpid($pid, $status);
        if (!pcntl_wifexited($status)) { throw new RuntimeException('Recovery racer did not exit'); }
        $code = pcntl_wexitstatus($status);
        if (($action === 'recover' && $code !== 0) || ($action === 'register' && $code !== 0 && $code !== 1)) {
            throw new RuntimeException('Recovery racer failed');
        }
    }
    if ($parent->generation('alice') !== 1 || $parent->forUser('alice') !== []) {
        throw new RuntimeException('Stale registration survived account recovery');
    }
    echo "WebAuthn SQLite recovery race: no stale device survived\n";
} finally {
    @unlink($file);
}
