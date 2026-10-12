<?php
declare(strict_types=1);
namespace SoSecurity\Http\Outbound;
use SoSecurity\Support\Deadline;
use SoSecurity\Http\Uri;
interface Transport
{
    /** Connect ONLY to pinnedIp, preserve Host/SNI/TLS verification, disable proxies/automatic redirects, enforce budgets. */
    public function send(Uri $uri, string $pinnedIp, string $method, array $headers, string $body, Deadline $deadline, int $maximumBody, int $maximumHeaders): Response;
}
