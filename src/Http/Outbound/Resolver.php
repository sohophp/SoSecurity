<?php
declare(strict_types=1);
namespace SoSecurity\Http\Outbound;
use SoSecurity\Support\Deadline;
interface Resolver
{
    /** All final A/AAAA addresses. Trusted adapter MUST enforce the supplied deadline; no opaque native blocking lookup. */
    public function resolve(string $host, Deadline $deadline): array;
}
