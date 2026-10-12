<?php
declare(strict_types=1);

namespace SoSecurity\Captcha;

/** Cloudflare validates expiry/single use. Host and action are additionally bound here. */
final class Turnstile
{
    private $secret;
    private $hostname;
    private $action;
    private $transport;

    public function __construct(string $secret, string $hostname, string $action, ?callable $transport = null)
    {
        if (strlen($secret) < 16 || strlen($secret) > 256 || preg_match('/[\x00-\x20\x7f]/', $secret)
            || !preg_match('/^[a-z0-9.-]{1,253}$/D', $hostname)
            || !preg_match('/^[A-Za-z0-9_-]{1,32}$/D', $action)) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid Turnstile secret, expected hostname or action.');
        }
        $this->secret = $secret;
        $this->hostname = $hostname;
        $this->action = $action;
        $this->transport = $transport;
    }

    /** Transport failures throw, invalid challenges return false. Never log the request payload. */
    public function verify($token, ?string $clientIp = null): bool
    {
        if (!is_string($token) || $token === '' || strlen($token) > 2048 || preg_match('/[\x00-\x20\x7f]/', $token)) {
            return false;
        }
        if ($clientIp !== null && filter_var($clientIp, FILTER_VALIDATE_IP) === false) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid client IP.');
        }
        $payload = ['secret' => $this->secret, 'response' => $token];
        if ($clientIp !== null) {
            $payload['remoteip'] = $clientIp;
        }
        try { $body = $this->transport === null ? $this->request($payload) : ($this->transport)($payload); }
        catch (\SoSecurity\Exception\DependencyException $e) { throw $e; }
        catch (\Throwable $e) { throw new \SoSecurity\Exception\DependencyException('Turnstile transport failed.', 'dependency.transport', $e); }
        if (!is_string($body) || strlen($body) > 16384) {
            throw new \SoSecurity\Exception\DependencyException('Invalid Turnstile response.');
        }
        $data = json_decode($body, true, 16);
        if (!is_array($data) || !isset($data['success']) || !is_bool($data['success'])) {
            throw new \SoSecurity\Exception\DependencyException('Malformed Turnstile response.');
        }
        return $data['success'] && ($data['hostname'] ?? null) === $this->hostname
            && ($data['action'] ?? null) === $this->action;
    }

    private function request(array $payload): string
    {
        if (!extension_loaded('curl')) {
            throw new \SoSecurity\Exception\DependencyException('Turnstile requires ext-curl or a trusted transport adapter.');
        }
        $handle = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
        if ($handle === false) {
            throw new \SoSecurity\Exception\DependencyException('Cannot initialize Turnstile transport.');
        }
        $body = '';
        try {
            curl_setopt_array($handle, [CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => http_build_query($payload, '', '&', PHP_QUERY_RFC3986),
                CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
                CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_TIMEOUT => 8,
                CURLOPT_FOLLOWLOCATION => false, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_WRITEFUNCTION => function ($handle, string $chunk) use (&$body): int {
                    if (strlen($body) + strlen($chunk) > 16384) {
                        return 0;
                    }
                    $body .= $chunk;
                    return strlen($chunk);
                }]);
            if (curl_exec($handle) === false || curl_getinfo($handle, CURLINFO_HTTP_CODE) !== 200) {
                throw new \SoSecurity\Exception\DependencyException('Turnstile verification service unavailable.');
            }
            return $body;
        } finally {
            if (PHP_VERSION_ID < 80000) {
                curl_close($handle);
            }
        }
    }
}
