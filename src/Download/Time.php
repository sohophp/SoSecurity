<?php
declare(strict_types=1);
namespace SoSecurity\Download;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;

final class Time
{
    public static function now(Clock $clock):int
    {
        $now=$clock->now();if($now<0||$now>PHP_INT_MAX-86400){throw new StorageException('Invalid download clock.','download.clock');}return $now;
    }
    public static function advance(Clock $clock,int &$seen):int
    {
        $now=self::now($clock);if($now<$seen){throw new StorageException('Download clock moved backwards.','download.clock');}$seen=$now;return $now;
    }
}
