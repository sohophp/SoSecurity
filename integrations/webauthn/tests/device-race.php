<?php
declare(strict_types=1);

require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';

use SoSecurity\WebAuthn\SqlCredentialRepository;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

if (!extension_loaded('pcntl')) { fwrite(STDERR, "NOT RUN: pcntl required\n"); exit(2); }
$file = tempnam(sys_get_temp_dir(), 'sosecurity-webauthn-device-');
if ($file === false) { throw new RuntimeException('Cannot allocate local test database'); }
try {
    $connect = static function () use ($file): PDO {
        $pdo = new PDO('sqlite:' . $file, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $pdo->exec('PRAGMA busy_timeout=5000');
        return $pdo;
    };
    $pdo = $connect();
    $pdo->exec(file_get_contents(dirname(__DIR__) . '/schema.sqlite.sql'));
    $repository = new SqlCredentialRepository($pdo, 'race');
    foreach (['one', 'two'] as $id) {
        $record = CredentialRecord::create($id, 'public-key', [], 'none', EmptyTrustPath::create(),
            Uuid::v4(), 'not-a-real-key', 'alice', 0);
        $repository->register($record, 100, 0);
    }
    $children = [];
    foreach (['one', 'two'] as $id) {
        $pid = pcntl_fork();
        if ($pid === -1) { throw new RuntimeException('Cannot fork device remover'); }
        if ($pid === 0) {
            try {
                $other = new SqlCredentialRepository($connect(), 'race');
                $stored = $other->find($id, 'alice');
                exit($other->revokeKeepingOne($stored, 200) ? 0 : 1);
            } catch (Throwable $e) {
                fwrite(STDERR, "Device race child failed: " . get_class($e) . "\n");
                exit(2);
            }
        }
        $children[] = $pid;
    }
    $removed = 0;
    foreach ($children as $pid) {
        pcntl_waitpid($pid, $status);
        if (!pcntl_wifexited($status)) { throw new RuntimeException('Device remover did not exit'); }
        $code = pcntl_wexitstatus($status);
        if ($code !== 0 && $code !== 1) { throw new RuntimeException('Device remover failed'); }
        if ($code === 0) { ++$removed; }
    }
    if ($removed !== 1 || count($repository->forUser('alice')) !== 1) {
        throw new RuntimeException('Concurrent removals lost the last device');
    }
    echo "WebAuthn SQLite device race: one removal and one surviving device\n";
} finally {
    @unlink($file);
}
