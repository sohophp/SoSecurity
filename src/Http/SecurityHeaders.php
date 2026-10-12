<?php
declare(strict_types=1);

namespace SoSecurity\Http;

final class SecurityHeaders
{
    /** CSP/HSTS are opt-in: start CSP in report-only and audit HTTPS before HSTS. */
    public static function build(?string $csp = null, bool $reportOnly = true, ?int $hstsAge = null, ?array $permissions = null): array
    {
        $headers = ['X-Content-Type-Options' => 'nosniff', 'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'X-Frame-Options' => 'SAMEORIGIN'];
        if ($csp !== null) {
            if ($csp === '' || strlen($csp) > 8192 || preg_match('/[\x00-\x1f\x7f]/', $csp)) {
                throw new \SoSecurity\Exception\ConfigurationException('Invalid CSP header value.');
            }
            $headers[$reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy'] = $csp;
        }
        if ($hstsAge !== null) {
            if ($hstsAge < 0 || $hstsAge > 63072000) {
                throw new \SoSecurity\Exception\ConfigurationException('Invalid HSTS max-age.');
            }
            $headers['Strict-Transport-Security'] = 'max-age=' . $hstsAge;
        }
        if ($permissions !== null) { $headers['Permissions-Policy'] = PermissionsPolicy::build($permissions); }
        return $headers;
    }
}
