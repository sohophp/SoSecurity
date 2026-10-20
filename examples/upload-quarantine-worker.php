<?php
declare(strict_types=1);
namespace SoSecurity\Examples\QuarantineHttp;

// Explicit CLI only. Requiring this file as a library does not execute work.
function worker(array $arguments): int
{
    try {
        if (PHP_SAPI !== 'cli' || count($arguments) !== 3 || !preg_match('/\A[1-9][0-9]?\z/D', $arguments[2]) || (int) $arguments[2] > 64) { return 2; }
        $config = configuration($arguments[1]); $services = services($config); $results = [];
        for ($index = 0; $index < (int) $arguments[2]; ++$index) {
            $status = $services['queue']->process(); if ($status === null) { break; } $results[] = ['id' => $status->id(), 'state' => $status->state()];
        }
        echo json_encode(['processed' => $results]) . "\n"; return 0;
    } catch (\Throwable $error) { fwrite(STDERR, "quarantine.worker_unavailable\n"); return 1; }
}
if (PHP_SAPI === 'cli' && isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    $autoload = dirname(__DIR__) . '/vendor/autoload.php'; if (!is_file($autoload)) { $autoload = dirname(__DIR__, 3) . '/autoload.php'; }
    require $autoload; require __DIR__ . '/upload-quarantine-business.php'; exit(worker($_SERVER['argv'] ?? []));
}
