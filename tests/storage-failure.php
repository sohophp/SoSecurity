<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

use SoSecurity\Storage\Change;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;

if (!function_exists('posix_setrlimit') || !function_exists('pcntl_signal')) {
    echo "NOT RUN filesystem write failure: POSIX test process required\n";
    exit(getenv('SOSECURITY_REQUIRE_POSIX') === '1' ? 1 : 0);
}
$directory = privateDirectory();
try {
    $store = new FileStore($directory, 'write-failure');
    $store->transact('key', function () { return new Change(['original' => true], 0, null); });
    // Limits apply ONLY to this standalone test process. Simulate an actual partial OS write, not a fake store.
    pcntl_signal(SIGXFSZ, SIG_IGN);
    Check::same(true, posix_setrlimit(POSIX_RLIMIT_FSIZE, 16, 16));
    Check::throws(StorageException::class, function () use ($store) {
        $store->transact('key', function () { return new Change(['replacement' => str_repeat('x', 100)], 0, true); });
    });
    Check::same(['original' => true], $store->transact('key', function ($value) { return new Change(null, 0, $value); }));
    Check::same([], glob($directory . '/.write-*'));
} finally { cleanDirectory($directory); }
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " real partial-write failure assertions passed\n";
