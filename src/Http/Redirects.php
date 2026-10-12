<?php
declare(strict_types=1);
namespace SoSecurity\Http;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

final class Redirects
{
    private $base;
    private $origins;
    public function __construct(string $trustedOrigin, array $additionalOrigins = [])
    {
        if (count($additionalOrigins) > 32) { throw new ConfigurationException('Redirect origin list is too large.'); }
        try {
            $this->base = Uri::parse(Uri::originValue($trustedOrigin)); $this->origins = [$this->base->origin()];
            foreach ($additionalOrigins as $origin) {
                if (!is_string($origin)) { throw new ConfigurationException('Redirect origins must be strings.'); }
                $this->origins[] = Uri::originValue($origin);
            }
        } catch (ValidationException $e) { throw new ConfigurationException('Configure fixed valid redirect origins.', 'configuration.redirect', $e); }
    }
    /** Returns canonical absolute Location; no header emission or status selection. */
    public function target(string $target): string
    {
        if (substr($target, 0, 2) === '//' || ($target !== '' && $target[0] !== '/' && !preg_match('/\Ahttps?:\/\//i', $target))) {
            throw new ValidationException('Use an absolute same-site path or approved HTTP origin.', 'url.redirect');
        }
        $uri = $this->base->resolve($target);
        if (!in_array($uri->origin(), $this->origins, true)) { throw new ValidationException('Redirect origin is not approved.', 'url.redirect'); }
        return $uri->url();
    }
    public function allows(string $target): bool { try { $this->target($target); return true; } catch (ValidationException $e) { return false; } }
}
