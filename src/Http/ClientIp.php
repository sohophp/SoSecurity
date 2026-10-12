<?php
declare(strict_types=1);

namespace SoSecurity\Http;

/** X-Forwarded-For only. Trusted edge must append actual peer IP or overwrite incoming header. */
final class ClientIp
{
    private $trusted;

    public function __construct(?IpRules $trustedProxies = null)
    {
        $this->trusted = $trustedProxies ?? new IpRules();
    }

    public function resolve(array $server): string
    {
        $remote = $server['REMOTE_ADDR'] ?? '';
        if (!is_string($remote) || filter_var($remote, FILTER_VALIDATE_IP) === false) {
            throw new \SoSecurity\Exception\ValidationException('Missing or invalid REMOTE_ADDR.');
        }
        $remote = inet_ntop(inet_pton($remote));
        if (!$this->trusted->contains($remote)) {
            return $remote;
        }
        $header = $server['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($header === '') {
            return $remote;
        }
        if (!is_string($header) || strlen($header) > 2048) {
            throw new \SoSecurity\Exception\ValidationException('Invalid proxy chain.');
        }
        $chain = array_map('trim', explode(',', $header));
        if (count($chain) > 32) {
            throw new \SoSecurity\Exception\ValidationException('Proxy chain is too long.');
        }
        foreach ($chain as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
                throw new \SoSecurity\Exception\ValidationException('Invalid forwarded IP.');
            }
        }
        // Walk from nearest hop; attacker-controlled leftmost entries are never blindly trusted.
        $candidate = $remote;
        for ($i = count($chain) - 1; $i >= 0 && $this->trusted->contains($candidate); --$i) {
            $candidate = inet_ntop(inet_pton($chain[$i]));
        }
        return $candidate;
    }
}
