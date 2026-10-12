<?php
declare(strict_types=1);
namespace SoSecurity\Support;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;

/** Transport and lock budgets use real elapsed time, independently of injected token clocks. */
final class Deadline
{
    private $end;
    private $last;
    public function __construct(int $milliseconds)
    {
        if ($milliseconds < 1 || $milliseconds > 30000) {
            throw new ConfigurationException('Operation budget must be 1-30000 milliseconds.');
        }
        $this->last = self::now();
        $this->end = $this->last + $milliseconds / 1000;
    }
    public function remaining(): float
    {
        $now = self::now();
        // PHP 7.2 lacks hrtime(): a backward wall-clock adjustment must expire rather than extend the budget.
        if ($now < $this->last) { $this->end = $now; }
        $this->last = $now;
        return max(0.0, $this->end - $now);
    }
    public function check(string $reason = 'storage.timeout'): void
    {
        if ($this->remaining() <= 0) { throw new StorageException('Security operation exceeded its time budget.', $reason); }
    }
    private static function now(): float
    {
        return function_exists('hrtime') ? hrtime(true) / 1000000000 : microtime(true);
    }
}
