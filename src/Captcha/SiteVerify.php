<?php
declare(strict_types=1);

namespace SoSecurity\Captcha;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;

/** @internal Fixed provider endpoints and bounded, authenticated TLS transport. */
final class SiteVerify
{
    public static function secret(string $secret): void
    {
        if (strlen($secret) < 16 || strlen($secret) > 256 || preg_match('/[\x00-\x20\x7f]/', $secret)) {
            throw new ConfigurationException('Invalid CAPTCHA provider secret.');
        }
    }

    public static function token($token): bool
    {
        return is_string($token) && $token !== '' && strlen($token) <= 8192 && !preg_match('/[\x00-\x20\x7f]/', $token);
    }

    public static function verify(string $provider, array $payload, ?string $clientIp, ?callable $transport): array
    {
        if ($clientIp !== null) {
            if (filter_var($clientIp, FILTER_VALIDATE_IP) === false) { throw new ConfigurationException('Invalid client IP.'); }
            $payload['remoteip'] = $clientIp;
        }
        try { $body = $transport === null ? self::request($provider, $payload) : $transport($payload); }
        catch (DependencyException $e) { throw $e; }
        // Do not chain arbitrary adapter exceptions: their messages may contain tokens or secrets.
        catch (\Throwable $e) { throw new DependencyException('CAPTCHA provider transport failed.', 'dependency.transport'); }
        if (!is_string($body) || strlen($body) > 16384) { throw new DependencyException('Invalid CAPTCHA provider response.'); }
        $data = json_decode($body, true, 16);
        if (!is_array($data) || !isset($data['success']) || !is_bool($data['success'])) {
            throw new DependencyException('Malformed CAPTCHA provider response.');
        }
        return $data;
    }

    private static function request(string $provider, array $payload): string
    {
        $endpoints = ['turnstile' => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            'hcaptcha' => 'https://api.hcaptcha.com/siteverify', 'recaptcha' => 'https://www.google.com/recaptcha/api/siteverify'];
        if (!isset($endpoints[$provider])) { throw new ConfigurationException('Unknown CAPTCHA provider.'); }
        if (!extension_loaded('curl')) { throw new DependencyException('CAPTCHA provider requires ext-curl or a trusted transport adapter.'); }
        $handle = curl_init($endpoints[$provider]);
        if ($handle === false) { throw new DependencyException('Cannot initialize CAPTCHA provider transport.'); }
        $body = ''; $headerBytes = 0;
        try {
            if (!curl_setopt_array($handle, [CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => http_build_query($payload, '', '&', PHP_QUERY_RFC1738),
                CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
                CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_TIMEOUT => 8, CURLOPT_PROXY => '', CURLOPT_NETRC => false,
                CURLOPT_FOLLOWLOCATION => false, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_HEADERFUNCTION => function ($handle, string $chunk) use (&$headerBytes): int {
                    $headerBytes += strlen($chunk); return $headerBytes <= 16384 ? strlen($chunk) : 0;
                },
                CURLOPT_WRITEFUNCTION => function ($handle, string $chunk) use (&$body): int {
                    if (strlen($body) + strlen($chunk) > 16384) { return 0; }
                    $body .= $chunk; return strlen($chunk);
                }])) { throw new DependencyException('Cannot enforce CAPTCHA transport restrictions.'); }
            if (curl_exec($handle) === false || curl_getinfo($handle, CURLINFO_HTTP_CODE) !== 200) {
                throw new DependencyException('CAPTCHA verification service unavailable.', 'dependency.transport');
            }
            return $body;
        } finally { if (PHP_VERSION_ID < 80000) { curl_close($handle); } }
    }
}
