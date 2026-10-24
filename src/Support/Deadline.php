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
    private $backwards = false;
    public function __construct(int $milliseconds)
    {
        if ($milliseconds < 1 || $milliseconds > 30000) {
            throw new ConfigurationException('Operation budget must be 1-30000 milliseconds.');
        }
        $this->last = self::now();
        $this->end = $this->last + $milliseconds / 1000;
    }
    /** Intersect two already-started budgets; never restart or extend either deadline. */
    public function restrictTo(self $other):void
    {
        $this->end=min($this->end,$other->end);$this->last=max($this->last,$other->last);$this->backwards=$this->backwards||$other->backwards;
    }
    public function remaining(): float
    {
        $now = self::now();
        // PHP 7.2 lacks hrtime(): a backward wall-clock adjustment must expire rather than extend the budget.
        if ($now < $this->last) { $this->end = $now; $this->backwards = true; }
        $this->last = $now;
        return max(0.0, $this->end - $now);
    }
    public function check(string $reason = 'storage.timeout'): void
    {
        if ($this->remaining() <= 0) { throw new StorageException($this->backwards ? 'Security duration clock moved backwards; the operation budget is expired.' : 'Security operation exceeded its time budget.', $reason); }
    }
    private static function now(): float
    {
        $monotonic=function_exists('hrtime');
        try{$value=$monotonic?hrtime(true):microtime(true);}
        catch(\Throwable $error){throw new StorageException('Security duration clock unavailable.','storage.clock');}
        if((!is_int($value)&&!is_float($value))||!is_finite($value)||$value<0){throw new StorageException('Security duration clock returned invalid data.','storage.clock');}
        return $monotonic?$value/1000000000:$value;
    }
}
