<?php
declare(strict_types=1);
namespace SoSecurity\Http;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

final class PermissionsPolicy
{
    /** Opt-in browser feature policy only; no header emission or invented default restrictions. */
    public static function build(array $directives): string
    {
        if (!$directives || count($directives) > 32) { throw new ConfigurationException('Provide bounded Permissions-Policy directives.'); }
        $result = [];
        foreach ($directives as $feature => $origins) {
            if (!is_string($feature) || !preg_match('/\A[a-z][a-z0-9-]{0,63}\z/D', $feature) || !is_array($origins) || count($origins) > 32) { throw new ConfigurationException('Invalid Permissions-Policy directive.'); }
            if ($origins === ['*']) { $result[] = $feature . '=*'; continue; }
            $values = [];
            foreach ($origins as $origin) {
                if (!is_string($origin)) { throw new ConfigurationException('Feature origins must be strings.'); }
                if ($origin === 'self') { $values[] = 'self'; continue; }
                try { $values[] = '"' . Uri::originValue($origin) . '"'; }
                catch (ValidationException $e) { throw new ConfigurationException('Invalid feature origin.', 'configuration.permissions_policy', $e); }
            }
            $result[] = $feature . '=(' . implode(' ', array_unique($values)) . ')';
        }
        $value = implode(', ', $result);
        if (strlen($value) > 8192) { throw new ConfigurationException('Permissions-Policy header is too large.'); }
        return $value;
    }
}
