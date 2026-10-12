<?php
declare(strict_types=1);

namespace SoSecurity\Http;

final class Cookie
{
    /** Returns a header value, compatible with PHP 7.2. Host uses header(..., false). */
    public static function header(string $name, string $value, string $path = '/', bool $secure = true,
        bool $httpOnly = true, string $sameSite = 'Lax', ?int $maxAge = null): string
    {
        if (!preg_match('/^[A-Za-z0-9_-]{1,128}$/D', $name)
            || !preg_match('#^/[A-Za-z0-9/_~.%-]*$#D', $path)
            || !in_array($sameSite, ['Lax', 'Strict', 'None'], true) || ($sameSite === 'None' && !$secure)
            || ($maxAge !== null && ($maxAge < 0 || $maxAge > 31536000))) {
            throw new \InvalidArgumentException('Invalid cookie policy.');
        }
        if ((strpos($name, '__Secure-') === 0 && !$secure)
            || (strpos($name, '__Host-') === 0 && (!$secure || $path !== '/'))) {
            throw new \InvalidArgumentException('Cookie prefix requirements are not met.');
        }
        $header = $name . '=' . rawurlencode($value) . '; Path=' . $path . '; SameSite=' . $sameSite;
        if ($maxAge !== null) {
            $header .= '; Max-Age=' . $maxAge;
            if ($maxAge === 0) {
                $header .= '; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
            }
        }
        return $header . ($secure ? '; Secure' : '') . ($httpOnly ? '; HttpOnly' : '');
    }
}
