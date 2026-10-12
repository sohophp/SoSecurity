<?php
declare(strict_types=1);

namespace SoSecurity\Http;

final class IpRules
{
    private $networks = [];

    public function __construct(array $rules = [])
    {
        foreach ($rules as $rule) {
            if (!is_string($rule)) {
                throw new \SoSecurity\Exception\ConfigurationException('IP rules must be strings.');
            }
            $parts = explode('/', $rule);
            $bytes = @inet_pton($parts[0]);
            $bits = $bytes === false ? 0 : strlen($bytes) * 8;
            if (count($parts) > 2 || $bytes === false || (isset($parts[1])
                && (!preg_match('/^(0|[1-9][0-9]*)$/D', $parts[1]) || (int) $parts[1] > $bits))) {
                throw new \SoSecurity\Exception\ConfigurationException('Invalid IP/CIDR rule.');
            }
            $this->networks[] = [$bytes, isset($parts[1]) ? (int) $parts[1] : $bits];
        }
    }

    public function contains(string $ip): bool
    {
        $address = @inet_pton($ip);
        if ($address === false) {
            return false;
        }
        foreach ($this->networks as list($network, $bits)) {
            if (strlen($address) !== strlen($network)) {
                continue;
            }
            $whole = intdiv($bits, 8);
            $rest = $bits % 8;
            if (substr($address, 0, $whole) === substr($network, 0, $whole)
                && ($rest === 0 || ((ord($address[$whole]) ^ ord($network[$whole])) & (255 << (8 - $rest))) === 0)) {
                return true;
            }
        }
        return false;
    }
}
