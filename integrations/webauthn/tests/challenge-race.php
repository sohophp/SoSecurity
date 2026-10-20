<?php
declare(strict_types=1);

require $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';

use SoSecurity\Storage\FileStore;
use SoSecurity\WebAuthn\Ceremonies;
use SoSecurity\WebAuthn\ChallengeStore;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialUserEntity;

if (!extension_loaded('pcntl')) {
    fwrite(STDERR, "NOT RUN: pcntl required for challenge race\n");
    exit(2);
}
$directory = sys_get_temp_dir() . '/sosecurity-webauthn-' . bin2hex(random_bytes(8));
if (!mkdir($directory, 0700) || !chmod($directory, 0700)) {
    throw new RuntimeException('Cannot create private test directory');
}
try {
    $store = new ChallengeStore(new FileStore($directory, 'test'), 'site');
    $ceremonies = new Ceremonies('Test', 'example.test', 'https://example.test');
    $user = PublicKeyCredentialUserEntity::create('alice', 'alice-id', 'Alice');
    $handle = $store->issue($ceremonies->beginRegistration($user, []), 'alice-id', 'session-a');
    $children = [];
    for ($i = 0; $i < 4; ++$i) {
        $pid = pcntl_fork();
        if ($pid === -1) { throw new RuntimeException('Cannot fork challenge consumer'); }
        if ($pid === 0) {
            $independent = new ChallengeStore(new FileStore($directory, 'test'), 'site');
            $received = $independent->consume($handle, 'register', 'alice-id', 'session-a');
            exit($received instanceof PublicKeyCredentialCreationOptions ? 0 : 1);
        }
        $children[] = $pid;
    }
    $winners = 0;
    foreach ($children as $pid) {
        pcntl_waitpid($pid, $status);
        if (!pcntl_wifexited($status)) { throw new RuntimeException('Child did not exit'); }
        if (pcntl_wexitstatus($status) === 0) { ++$winners; }
    }
    if ($winners !== 1 || $store->consume($handle, 'register', 'alice-id', 'session-a') !== null) {
        throw new RuntimeException('Challenge was consumed more or fewer than once');
    }
    echo "WebAuthn file-store challenge race: one winner among four consumers\n";
} finally {
    foreach (glob($directory . '/*') ?: [] as $path) { unlink($path); }
    rmdir($directory);
}
