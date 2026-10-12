<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Storage\Change;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;

$directory = getenv('SOSECURITY_TEST_FULL_DISK');
if (!$directory) { fwrite(STDERR, "Use bin/full-disk-check.sh to create an isolated tiny filesystem.\n"); exit(2); }
$store = new FileStore($directory, 'full-disk');
$store->transact('key', function () { return new Change(['original' => true], 0, null); });
$fill = fopen($directory . '/fill', 'wb');
if ($fill === false) { throw new RuntimeException('Cannot allocate isolated fill file.'); }
while (@fwrite($fill, str_repeat('x', 4096)) > 0) {}
fclose($fill);
Check::same(true, disk_free_space($directory) < 4096);
Check::throws(StorageException::class, function () use ($store) {
    $store->transact('key', function () { return new Change(['replacement' => true], 0, true); });
});
Check::same(['original' => true], $store->transact('key', function ($value) { return new Change(null, 0, $value); }));
Check::same([], glob($directory . '/.write-*'));
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " real ENOSPC assertions passed\n";
