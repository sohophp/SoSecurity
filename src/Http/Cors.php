<?php
declare(strict_types=1);
namespace SoSecurity\Http;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

/** Exact origins and bounded browser preflight; host still owns authentication, CSRF and business permissions. */
final class Cors
{
    private $origins;
    private $methods;
    private $requestHeaders;
    private $exposed;
    private $credentials;
    private $maxAge;
    public function __construct(array $origins, array $methods = ['GET', 'POST'], array $requestHeaders = ['content-type'], bool $credentials = false, int $maxAge = 600, array $exposed = [])
    {
        if (count($origins) > 64 || !$methods || count($methods) > 8 || $maxAge < 0 || $maxAge > 86400 || ($credentials && in_array('*', $origins, true))) { throw new ConfigurationException('Invalid CORS policy.'); }
        $this->origins = []; $this->methods = [];
        foreach ($origins as $origin) {
            if (!is_string($origin)) { throw new ConfigurationException('CORS origins must be strings.'); }
            try { $this->origins[] = $origin === '*' ? '*' : Uri::originValue($origin); }
            catch (ValidationException $e) { throw new ConfigurationException('Invalid configured CORS origin.', 'configuration.cors', $e); }
        }
        if (in_array('*', $this->origins, true) && count($this->origins) !== 1) { throw new ConfigurationException('Wildcard origin cannot be combined with others.'); }
        foreach ($methods as $method) {
            if (!in_array($method, ['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'], true)) { throw new ConfigurationException('Unsupported CORS method.'); }
            $this->methods[] = $method;
        }
        $this->requestHeaders = $this->names($requestHeaders, true); $this->exposed = $this->names($exposed, true);
        $this->credentials = $credentials; $this->maxAge = $maxAge;
    }
    public function evaluate(string $method, ?string $origin, ?string $requestedMethod = null, ?string $requestedHeaders = null, string $existingVary = ''): CorsDecision
    {
        $preflight = $method === 'OPTIONS' && $requestedMethod !== null;
        $vary = $this->vary($existingVary, $preflight); $headers = ['Vary' => $vary];
        if ($origin === null) { return new CorsDecision(!$preflight, $preflight ? 403 : 200, $headers, $preflight ? 'cors.origin' : 'cors.not_cross_origin'); }
        try { $canonical = Uri::originValue($origin); } catch (ValidationException $e) { return new CorsDecision(false, 403, $headers, 'cors.origin'); }
        if ($canonical !== $origin || (!in_array('*', $this->origins, true) && !in_array($canonical, $this->origins, true))) { return new CorsDecision(false, 403, $headers, 'cors.origin'); }
        $wanted = $preflight ? $requestedMethod : $method;
        if (!in_array($wanted, $this->methods, true)) { return new CorsDecision(false, 403, $headers, 'cors.method'); }
        if ($preflight) {
            if ($requestedHeaders !== null) {
                if (strlen($requestedHeaders) > 2048) { return new CorsDecision(false, 403, $headers, 'cors.headers'); }
                try { $requested = $this->names(array_map('trim', explode(',', $requestedHeaders)), false); }
                catch (ValidationException $e) { return new CorsDecision(false, 403, $headers, 'cors.headers'); }
                if (array_diff($requested, $this->requestHeaders)) { return new CorsDecision(false, 403, $headers, 'cors.headers'); }
            }
            $headers['Access-Control-Allow-Methods'] = implode(', ', $this->methods);
            if ($this->requestHeaders) { $headers['Access-Control-Allow-Headers'] = implode(', ', $this->requestHeaders); }
            $headers['Access-Control-Max-Age'] = (string) $this->maxAge;
        }
        $headers['Access-Control-Allow-Origin'] = in_array('*', $this->origins, true) ? '*' : $canonical;
        if ($this->credentials) { $headers['Access-Control-Allow-Credentials'] = 'true'; }
        if (!$preflight && $this->exposed) { $headers['Access-Control-Expose-Headers'] = implode(', ', $this->exposed); }
        return new CorsDecision(true, $preflight ? 204 : 200, $headers, $preflight ? 'cors.preflight' : 'cors.allowed');
    }
    private function names(array $names, bool $configuration): array
    {
        if (count($names) > 32) { if ($configuration) { throw new ConfigurationException('Too many CORS header names.'); } throw new ValidationException('Too many requested headers.'); }
        $result = [];
        foreach ($names as $name) {
            if (!is_string($name) || strlen($name) > 64 || !preg_match('/\A[a-zA-Z0-9!#$%&\x27*+.^_`|~-]+\z/D', $name) || in_array(strtolower($name), ['set-cookie', '*'], true)) {
                if ($configuration) { throw new ConfigurationException('Invalid configured CORS header name.'); } throw new ValidationException('Invalid requested header name.');
            }
            $result[] = strtolower($name);
        }
        return array_values(array_unique($result));
    }
    private function vary(string $existing, bool $preflight): string
    {
        if (strlen($existing) > 2048) { throw new ConfigurationException('Vary value is too large.'); }
        $tokens = $existing === '' ? [] : array_map('trim', explode(',', $existing));
        if (in_array('*', $tokens, true)) {
            $this->names(array_values(array_diff($tokens, ['*'])), true);
            return '*';
        }
        $names = $this->names($tokens, true);
        $names = array_merge($names, ['origin'], $preflight ? ['access-control-request-method', 'access-control-request-headers'] : []);
        return implode(', ', array_unique($names));
    }
}
