<?php
declare(strict_types=1);

namespace SoSecurity\Support;

interface Clock
{
    public function now(): int;
}
