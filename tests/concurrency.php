<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\RedisStore;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Captcha\Captcha;

function parallelSuccesses(string $kind, string $target, string $operation, array $arguments = []): int
{
    $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/worker.php');
    foreach (array_merge([$kind, $target, $operation], $arguments) as $argument) { $command .= ' ' . escapeshellarg($argument); }
    $processes = [];
    for ($i = 0; $i < 24; ++$i) {
        $pipes = [];
        $workerCommand = $operation === 'reset' ? $command . ' ' . $i : $command;
        $process = proc_open($workerCommand, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) { throw new RuntimeException('Cannot start test worker.'); }
        fclose($pipes[0]); $processes[] = [$process, $pipes];
    }
    $successes = 0;
    foreach ($processes as list($process, $pipes)) {
        $stdout = stream_get_contents($pipes[1]); $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]); $code = proc_close($process);
        if ($code !== 0 || $stderr !== '' || !in_array($stdout, ['0', '1'], true)) {
            throw new RuntimeException('Worker failed: ' . $stderr . $stdout);
        }
        $successes += (int) $stdout;
    }
    return $successes;
}

$directory = privateDirectory();
try {
    $backends = ['file' => $directory];
    $socket = getenv('SOSECURITY_TEST_REDIS_SOCKET');
    if ($socket) { $backends['redis'] = $socket; }
    $mysql = getenv('SOSECURITY_TEST_MYSQL_SOCKET');
    if ($mysql) { $backends['mysql'] = $mysql; }
    foreach ($backends as $kind => $target) {
        if ($kind === 'redis') {
            $redis = new Redis(); $redis->connect($target, 0, 2.0);
            $store = new RedisStore($redis, 'concurrency'); $store->initialize();
            // Only dedicated test-instance keys; never FLUSHDB or touch unrelated namespaces.
            (new SoSecurity\RateLimit\RateLimiter($store))->reset('login', 'subject');
        } elseif ($kind === 'mysql') {
            $pdo = new PDO('mysql:unix_socket=' . $target . ';dbname=sosecurity_test;charset=utf8mb4', 'sosecurity_test', 'integration-only', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $store = new SoSecurity\Storage\MySqlStore($pdo, 'concurrency');
            (new SoSecurity\RateLimit\RateLimiter($store))->reset('login', 'subject');
        } else { $store = new FileStore($target, 'concurrency'); }
        Check::same(5, parallelSuccesses($kind, $target, 'rate'));
        $csrf = new CsrfTokens($store); $token = $csrf->issue('form', 'binding');
        Check::same(1, parallelSuccesses($kind, $target, 'csrf', [$token]));
        $captcha = new Captcha($store); $challenge = $captcha->arithmetic('form', 'binding');
        preg_match('/^(\d+) \+ (\d+)/', $challenge->prompt, $parts);
        Check::same(1, parallelSuccesses($kind, $target, 'captcha', [$challenge->id, (string) ($parts[1] + $parts[2])]));
        if ($kind === 'mysql') {
            $pdo->exec('DROP TABLE IF EXISTS accounts');
            $pdo->exec('CREATE TABLE accounts (id VARCHAR(128) PRIMARY KEY, version BIGINT NOT NULL, password_hash VARCHAR(255) NOT NULL) ENGINE=InnoDB');
            $pdo->exec("INSERT INTO accounts VALUES ('concurrency-demo',1,'OLD')");
            $reset = new SoSecurity\Password\ResetTokens($store); $tokens = [];
            for ($i = 0; $i < 4; ++$i) { $tokens[] = $reset->issue('concurrency-demo:1'); }
            Check::same(1, parallelSuccesses($kind, $target, 'reset', [implode(',', $tokens)]));
            Check::same(2, (int) $pdo->query("SELECT version FROM accounts WHERE id='concurrency-demo'")->fetchColumn());
            Check::same(true, (new SoSecurity\Password\PasswordHasher())->verify('Replacement-concurrent-password', $pdo->query("SELECT password_hash FROM accounts WHERE id='concurrency-demo'")->fetchColumn()));
            $pdo->exec('DROP TABLE accounts');
            echo "PASS MySQL password reset: 24 workers / 4 valid tokens; exactly one host version update\n";
        }
        echo "PASS $kind: 24 competing processes per scenario; exactly 5 requests, 1 CSRF consume, 1 CAPTCHA consume accepted\n";
    }
    if (extension_loaded('gd') && extension_loaded('fileinfo')) {
        $web = privateDirectory(); $source = $directory . '/upload-source';
        try {
            $image = imagecreatetruecolor(2, 2); imagepng($image, $source);
            if (is_resource($image)) { imagedestroy($image); } unset($image);
            Check::same(24, parallelSuccesses('file', $directory, 'upload', [$source, $web]));
            $files = glob($directory . '/*.png'); Check::same(24, count($files));
            foreach ($files as $file) {
                Check::same(0600, fileperms($file) & 0777);
                Check::same('image/png', (new finfo(FILEINFO_MIME_TYPE))->file($file));
            }
            echo "PASS uploads: 24 concurrent exclusive random files, no overwrite, private permissions\n";
        } finally { cleanDirectory($web); }
    } else { echo "NOT RUN concurrent uploads: fileinfo and GD required\n"; }
    if (!$socket) { echo "NOT RUN Redis: set SOSECURITY_TEST_REDIS_SOCKET for an isolated instance\n"; }
    echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " concurrency assertions passed\n";
} finally { cleanDirectory($directory); }
