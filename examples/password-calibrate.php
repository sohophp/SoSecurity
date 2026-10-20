<?php
declare(strict_types=1);
namespace SoSecurity\Examples\PasswordCalibration;

// Explicit CLI tool only; importing this example does not benchmark or start a subprocess.
if (PHP_SAPI !== 'cli' || realpath($_SERVER['SCRIPT_FILENAME'] ?? '') !== __FILE__) { return; }
ini_set('display_errors', '0');
$autoload = dirname(__DIR__) . '/vendor/autoload.php';
if (!is_file($autoload)) { $autoload = dirname(__DIR__, 3) . '/autoload.php'; }
require $autoload;

use SoSecurity\Password\PasswordHasher;

function now(): float { return function_exists('hrtime') ? hrtime(true) / 1000000000 : microtime(true); }

function worker(array $input): array
{
    if (array_keys($input) !== ['profile', 'options', 'samples'] || !is_array($input['options']) || !is_int($input['samples']) || $input['samples'] < 1 || $input['samples'] > 5) {
        throw new \RuntimeException('Invalid isolated probe.');
    }
    $hasher = new PasswordHasher($input['profile'], $input['options']); $candidate = bin2hex(random_bytes(32));
    $hasher->hash($candidate); $timings = []; // Warm up without exposing or persisting the probe password/hash.
    for ($i = 0; $i < $input['samples']; ++$i) {
        $before = now(); $hasher->hash($candidate); $elapsed = now() - $before;
        if ($elapsed <= 0) { throw new \RuntimeException('Probe clock invalid.'); }
        $timings[] = round($elapsed * 1000, 3);
    }
    sort($timings); return ['options' => $hasher->parameters(), 'median_ms' => $timings[intdiv(count($timings), 2)], 'samples_ms' => $timings];
}

function probe(array $input, float $deadline): ?array
{
    $command = 'exec ' . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__FILE__) . ' --worker=' . escapeshellarg(base64_encode(json_encode($input)));
    $pipes = []; $process = proc_open($command, [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
    if (!is_resource($process)) { throw new \RuntimeException('Cannot start isolated cost probe.'); }
    fclose($pipes[0]); stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false); $out = ''; $error = ''; $exit = null;
    try {
        while (true) {
            $out .= stream_get_contents($pipes[1]); $error .= stream_get_contents($pipes[2]);
            if (strlen($out) > 4096 || strlen($error) > 4096) { throw new \RuntimeException('Probe output budget exceeded.'); }
            $status = proc_get_status($process);
            if (!$status['running']) { $exit = $status['exitcode']; break; }
            if (now() >= $deadline) { return null; }
            usleep(5000);
        }
        $out .= stream_get_contents($pipes[1]); $error .= stream_get_contents($pipes[2]);
        $result = json_decode($out, true);
        if ($exit !== 0 || $error !== '' || !is_array($result) || !isset($result['median_ms'], $result['options'], $result['samples_ms'])) {
            throw new \RuntimeException('Isolated cost probe failed.');
        }
        return $result;
    } finally {
        $status = proc_get_status($process);
        if ($status['running']) {
            proc_terminate($process); $stop = now() + .1;
            do { usleep(5000); $status = proc_get_status($process); } while ($status['running'] && now() < $stop);
            if ($status['running']) { proc_terminate($process, 9); }
        }
        fclose($pipes[1]); fclose($pipes[2]); proc_close($process);
    }
}

try {
    if (count($argv) === 2 && strpos($argv[1], '--worker=') === 0) {
        $encoded = substr($argv[1], 9);
        if (strlen($encoded) > 1024) { throw new \RuntimeException('Probe input too large.'); }
        $input = json_decode(base64_decode($encoded, true) ?: '', true);
        if (!is_array($input)) { throw new \RuntimeException('Invalid probe input.'); }
        echo json_encode(worker($input)) . "\n"; exit;
    }
    $options = ['profile' => 'bcrypt', 'target-ms' => 250, 'budget-ms' => 3000, 'samples' => 3, 'max-memory-kib' => 65536]; $seen = [];
    foreach (array_slice($argv, 1) as $argument) {
        if ($argument === '--help') {
            echo "Usage: php examples/password-calibrate.php [--profile=bcrypt|argon2id] [--target-ms=250] [--budget-ms=3000] [--samples=3] [--max-memory-kib=65536]\nExplicit POSIX CLI probe; no real passwords, configuration writes or production auto-tuning.\n"; exit;
        }
        if (!preg_match('/\A--([a-z-]+)=([a-z0-9]+)\z/D', $argument, $parts) || !array_key_exists($parts[1], $options) || isset($seen[$parts[1]])) { throw new \RuntimeException('Invalid calibration option.'); }
        $seen[$parts[1]] = true;
        if ($parts[1] === 'profile') { $options[$parts[1]] = $parts[2]; }
        else {
            if (!preg_match('/\A[1-9][0-9]{0,5}\z/D', $parts[2])) { throw new \RuntimeException('Invalid calibration number.'); }
            $options[$parts[1]] = (int) $parts[2];
        }
    }
    if (DIRECTORY_SEPARATOR !== '/') { throw new \RuntimeException('Calibration requires explicit POSIX CLI process control.'); }
    foreach (['proc_open', 'proc_terminate', 'proc_get_status', 'proc_close'] as $function) {
        if (!function_exists($function)) { throw new \RuntimeException('Calibration requires explicit POSIX CLI process control.'); }
    }
    if ($options['target-ms'] < 10 || $options['target-ms'] > 2000 || $options['budget-ms'] < 100 || $options['budget-ms'] > 30000
        || $options['samples'] < 1 || $options['samples'] > 5 || $options['max-memory-kib'] < 19456 || $options['max-memory-kib'] > 262144) { throw new \RuntimeException('Calibration budget out of range.'); }
    $profile = $options['profile']; new PasswordHasher($profile); $candidates = [];
    if ($profile === 'bcrypt') { for ($cost = 10; $cost <= 16; ++$cost) { $candidates[] = ['cost' => $cost]; } }
    else {
        $memory = 19456;
        while (true) {
            $candidates[] = ['memory_cost' => $memory, 'time_cost' => 2, 'threads' => 1];
            if ($memory === $options['max-memory-kib']) { break; }
            $memory = min($options['max-memory-kib'], $memory === 19456 ? 32768 : $memory * 2);
        }
        for ($time = 3; $time <= 10; ++$time) { $candidates[] = ['memory_cost' => $memory, 'time_cost' => $time, 'threads' => 1]; }
    }
    $started = now(); $deadline = $started + $options['budget-ms'] / 1000; $measurements = []; $recommended = null; $reason = 'password.calibration_candidates_complete';
    foreach ($candidates as $candidate) {
        if (now() >= $deadline) { $reason = 'password.calibration_budget'; break; }
        $measurement = probe(['profile' => $profile, 'options' => $candidate, 'samples' => $options['samples']], $deadline);
        if ($measurement === null) { $reason = 'password.calibration_budget'; break; }
        $measurements[] = $measurement;
        if ($measurement['median_ms'] > $options['target-ms']) { $reason = 'password.calibration_target_exceeded'; break; }
        $recommended = $measurement['options'];
    }
    echo json_encode(['profile' => $profile, 'target_ms' => $options['target-ms'], 'budget_ms' => $options['budget-ms'], 'samples' => $options['samples'],
        'elapsed_ms' => round((now() - $started) * 1000, 3), 'measurements' => $measurements, 'recommended' => $recommended,
        'reason' => $reason, 'writes_configuration' => false], JSON_PRETTY_PRINT) . "\n";
} catch (\Throwable $e) { fwrite(STDERR, "Password calibration refused or failed; check options, profile availability and process control.\n"); exit(1); }
