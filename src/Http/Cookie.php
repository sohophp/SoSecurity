<?php
declare(strict_types=1);

namespace SoSecurity\Http;

final class Cookie
{
    /** Returns a header value, compatible with PHP 7.2. Host uses header(..., false). */
    public static function header(string $name, string $value, string $path = '/', bool $secure = true,
        bool $httpOnly = true, string $sameSite = 'Lax', ?int $maxAge = null, ?string $domain = null): string
    {
        if (!preg_match('/^[A-Za-z0-9_-]{1,128}$/D', $name)
            || !preg_match('#^/[A-Za-z0-9/_~.%-]*$#D', $path)
            || !in_array($sameSite, ['Lax', 'Strict', 'None'], true) || ($sameSite === 'None' && !$secure)
            || ($maxAge !== null && ($maxAge < 0 || $maxAge > 31536000))) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid cookie policy.');
        }
        if ($domain !== null) {
            $domain = strtolower(ltrim($domain, '.'));
            if (strlen($domain) > 253 || !preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/D', $domain)) {
                throw new \SoSecurity\Exception\ConfigurationException('Invalid cookie domain.');
            }
        }
        if ((strpos($name, '__Secure-') === 0 && !$secure)
            || (strpos($name, '__Host-') === 0 && (!$secure || $path !== '/' || $domain !== null))) {
            throw new \SoSecurity\Exception\ConfigurationException('Cookie prefix requirements are not met.');
        }
        $header = $name . '=' . rawurlencode($value) . '; Path=' . $path . '; SameSite=' . $sameSite;
        if ($domain !== null) { $header .= '; Domain=' . $domain; }
        if ($maxAge !== null) {
            $header .= '; Max-Age=' . $maxAge;
            if ($maxAge === 0) {
                $header .= '; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
            }
        }
        return $header . ($secure ? '; Secure' : '') . ($httpOnly ? '; HttpOnly' : '');
    }
}
