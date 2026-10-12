<?php
declare(strict_types=1);
namespace SoSecurity\Http\Outbound;
use SoSecurity\Exception\ValidationException;

final class RequestHeaders
{
    public static function normalize(array $headers): array
    {
        if (count($headers) > 32) { throw new ValidationException('Request header limit exceeded.', 'http.request_headers'); }
        $result = []; $bytes = 0;
        foreach ($headers as $name=>$value) {
            if (!is_string($name) || strlen($name) > 64 || !preg_match('/\A[a-zA-Z0-9!#$%&\x27*+.^_`|~-]+\z/D', $name) || !is_string($value)
                || preg_match('/[\x00-\x1f\x7f]/', $value)) { throw new ValidationException('Invalid request header.', 'http.request_headers'); }
            $name = strtolower($name); $bytes += strlen($name) + strlen($value) + 4;
            if (isset($result[$name]) || $bytes > 8192 || in_array($name, ['host','cookie','content-length','transfer-encoding','connection','expect','accept-encoding','forwarded','via','keep-alive','te','trailer','upgrade'], true)
                || strpos($name,'proxy-') === 0 || strpos($name,'x-forwarded-') === 0) { throw new ValidationException('Reserved, duplicated or excessive request header.', 'http.request_headers'); }
            $result[$name] = $value;
        }
        return $result;
    }
}
