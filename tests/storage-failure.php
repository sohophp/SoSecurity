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
// A child with pipe output avoids applying the size limit to a caller's redirected test log.
if (($argv[1] ?? '') !== '--isolated-write-child') {
    $pipes = [];
    $child = proc_open(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' --isolated-write-child',
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($child)) { throw new RuntimeException('Cannot start isolated write-failure test.'); }
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]); $errors = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]); $code = proc_close($child);
    if ($code !== 0 || $errors !== '') { throw new RuntimeException('Isolated write-failure test failed: ' . $errors); }
    echo $output;
    exit(0);
}
$directory = privateDirectory(); $web = privateDirectory();
try {
    $store = new FileStore($directory, 'write-failure');
    $store->transact('key', function () { return new Change(['original' => true], 0, null); });
    $uploader = null; $published = null;
    if (extension_loaded('gd') && extension_loaded('fileinfo')) {
        $image = imagecreatetruecolor(2, 2); imagepng($image, $directory . '/upload-source');
        if (is_resource($image)) { imagedestroy($image); } unset($image);
        $uploader = new SoSecurity\Upload\Saver(new SoSecurity\Upload\Validator(), $directory, $web);
        $published = $uploader->saveFile($directory . '/upload-source', 'normal.png');
    }
    // Limits apply ONLY to this standalone test process. Simulate an actual partial OS write, not a fake store.
    pcntl_signal(SIGXFSZ, SIG_IGN);
    Check::same(true, posix_setrlimit(POSIX_RLIMIT_FSIZE, 16, 16));
    Check::throws(StorageException::class, function () use ($store) {
        $store->transact('key', function () { return new Change(['replacement' => str_repeat('x', 100)], 0, true); });
    });
    Check::same(['original' => true], $store->transact('key', function ($value) { return new Change(null, 0, $value); }));
    Check::same([], glob($directory . '/.write-*'));
    if ($uploader !== null) {
        Check::throws(StorageException::class, function () use ($uploader, $directory) { $uploader->saveFile($directory . '/upload-source', 'normal.png'); });
        Check::same(1, count(glob($directory . '/*.png')));
        Check::same($published->metadata()['sha256'], hash_file('sha256', $published->path()));
    }
} finally { cleanDirectory($directory); cleanDirectory($web); }
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " real partial-write failure assertions passed\n";
