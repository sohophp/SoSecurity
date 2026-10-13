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
        $data = SiteVerify::verify('turnstile', ['secret' => $this->secret, 'response' => $token], $clientIp, $this->transport);
        return $data['success'] && ($data['hostname'] ?? null) === $this->hostname
            && ($data['action'] ?? null) === $this->action;
    }

}
