<?php
declare(strict_types=1);
namespace SoSecurity\Validation;

/** Trusted application rule. It must be bounded and have no mutation or remote I/O. */
interface Rule
{
    public function passes($value): bool;
    public function code(): string;
}
