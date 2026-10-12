<?php
declare(strict_types=1);

namespace SoSecurity\Support;

final class SystemClock implements Clock
{
    public function now(): int
    {
        return time();
    }
}
