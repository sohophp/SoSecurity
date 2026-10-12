<?php
declare(strict_types=1);
require dirname(__DIR__) . '/vendor/autoload.php';
error_reporting(E_ALL);
set_error_handler(function ($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    throw new ErrorException($message, 0, $severity, $file, $line);
});

final class TestClock implements SoSecurity\Support\Clock
{
    public $time = 100000;
    public function now(): int { return $this->time; }
}

final class Check
{
    public static $assertions = 0;
    public static function same($expected, $actual): void
    {
        ++self::$assertions;
        if ($expected !== $actual) {
            throw new RuntimeException('Expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
        }
    }
    public static function throws(string $type, callable $operation): void
    {
        ++self::$assertions;
        try { $operation(); } catch (Throwable $e) {
            if ($e instanceof $type) { return; }
            throw $e;
        }
        throw new RuntimeException('Expected exception ' . $type);
    }
}
function privateDirectory(): string
{
    $path = sys_get_temp_dir() . '/sosecurity-test-' . bin2hex(random_bytes(8));
    if (!mkdir($path, 0700)) { throw new RuntimeException('Cannot create test directory.'); }
    return $path;
}
function cleanDirectory(string $path): void
{
    foreach (new DirectoryIterator($path) as $entry) {
        if (!$entry->isDot()) { unlink($entry->getPathname()); }
    }
    rmdir($path);
}
