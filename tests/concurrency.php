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
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
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
    foreach ($backends as $kind => $target) {
        if ($kind === 'redis') {
            $redis = new Redis(); $redis->connect($target, 0, 2.0);
            $store = new RedisStore($redis, 'concurrency');
            // Only dedicated test-instance keys; never FLUSHDB or touch unrelated namespaces.
            (new SoSecurity\RateLimit\RateLimiter($store))->reset('login', 'subject');
        } else { $store = new FileStore($target, 'concurrency'); }
        Check::same(5, parallelSuccesses($kind, $target, 'rate'));
        $csrf = new CsrfTokens($store); $token = $csrf->issue('form', 'binding');
        Check::same(1, parallelSuccesses($kind, $target, 'csrf', [$token]));
        $captcha = new Captcha($store); $challenge = $captcha->arithmetic('form', 'binding');
        preg_match('/^(\d+) \+ (\d+)/', $challenge->prompt, $parts);
        Check::same(1, parallelSuccesses($kind, $target, 'captcha', [$challenge->id, (string) ($parts[1] + $parts[2])]));
        echo "PASS $kind: 24 competing processes per scenario; exactly 5 requests, 1 CSRF consume, 1 CAPTCHA consume accepted\n";
    }
    if (!$socket) { echo "NOT RUN Redis: set SOSECURITY_TEST_REDIS_SOCKET for an isolated instance\n"; }
    echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " concurrency assertions passed\n";
} finally { cleanDirectory($directory); }
