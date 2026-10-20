<?php
declare(strict_types=1);

namespace SoSecurity\Mfa;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;

/** RFC 6238 calculation only. Use TotpFactors for enrollment, throttling and atomic replay protection. */
final class Totp
{
    private $algorithm;
    private $digits;
    private $period;
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public function __construct(string $algorithm = 'sha1', int $digits = 6, int $period = 30)
    {
        if (PHP_INT_SIZE < 8 || !in_array($algorithm, ['sha1', 'sha256', 'sha512'], true)
            || !in_array($digits, [6, 8], true) || $period < 15 || $period > 120) {
            throw new ConfigurationException('TOTP requires 64-bit integers, SHA-1/256/512, 6/8 digits and a 15-120 second period.', 'configuration.totp');
        }
        $this->algorithm = $algorithm; $this->digits = $digits; $this->period = $period;
    }

    public function generateSecret(): string
    {
        return self::encodeSecret(random_bytes(['sha1' => 20, 'sha256' => 32, 'sha512' => 64][$this->algorithm]));
    }

    public static function encodeSecret(string $binary): string
    {
        if (strlen($binary) < 20 || strlen($binary) > 128) { throw new ConfigurationException('TOTP secrets require 20-128 bytes.', 'configuration.totp_secret'); }
        $buffer = 0; $bits = 0; $encoded = '';
        for ($i = 0; $i < strlen($binary); ++$i) {
            $buffer = ($buffer << 8) | ord($binary[$i]); $bits += 8;
            while ($bits >= 5) { $bits -= 5; $encoded .= self::ALPHABET[($buffer >> $bits) & 31]; }
            $buffer &= (1 << $bits) - 1;
        }
        if ($bits > 0) { $encoded .= self::ALPHABET[($buffer << (5 - $bits)) & 31]; }
        return $encoded;
    }

    public function provisioningUri(string $secret, string $issuer, string $account): string
    {
        $this->decode($secret); Guard::label($issuer); Guard::label($account);
        if (strpos($issuer, ':') !== false || strpos($account, ':') !== false) {
            throw new ConfigurationException('Authenticator labels must not contain colons.', 'configuration.totp_label');
        }
        return 'otpauth://totp/' . rawurlencode($issuer . ':' . $account) . '?' . http_build_query([
            'secret' => $secret, 'issuer' => $issuer, 'algorithm' => strtoupper($this->algorithm), 'digits' => $this->digits, 'period' => $this->period,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    public function codeAt(string $secret, int $unixTime): string
    {
        if ($unixTime < 0) { throw new ConfigurationException('TOTP time must not be negative.', 'configuration.clock'); }
        return $this->atStep($this->decode($secret), intdiv($unixTime, $this->period));
    }

    /** Highest matching step wins if a short code collides within the bounded drift window. */
    public function matchingStep(string $secret, $code, int $unixTime, int $window = 1): ?int
    {
        if ($unixTime < 0 || $window < 0 || $window > 2) { throw new ConfigurationException('Invalid TOTP time or drift window.', 'configuration.totp'); }
        $binary = $this->decode($secret);
        if (!is_string($code) || strlen($code) !== $this->digits || !preg_match('/\A[0-9]+\z/D', $code)) { return null; }
        $current = intdiv($unixTime, $this->period); $matched = null;
        for ($step = max(0, $current - $window); $step <= $current + $window; ++$step) {
            if (hash_equals($this->atStep($binary, $step), $code)) { $matched = $step; }
        }
        return $matched;
    }

    public function profile(): array { return ['algorithm' => $this->algorithm, 'digits' => $this->digits, 'period' => $this->period]; }

    private function atStep(string $binary, int $step): string
    {
        $counter = pack('N2', intdiv($step, 4294967296), $step & 0xffffffff);
        $mac = hash_hmac($this->algorithm, $counter, $binary, true); $offset = ord($mac[strlen($mac) - 1]) & 15;
        $number = unpack('Nvalue', substr($mac, $offset, 4))['value'] & 0x7fffffff;
        return str_pad((string) ($number % ($this->digits === 6 ? 1000000 : 100000000)), $this->digits, '0', STR_PAD_LEFT);
    }

    private function decode(string $secret): string
    {
        if (strlen($secret) < 32 || strlen($secret) > 205 || !preg_match('/\A[A-Z2-7]+\z/D', $secret)) {
            throw new ConfigurationException('TOTP secret must be canonical unpadded Base32.', 'configuration.totp_secret');
        }
        $buffer = 0; $bits = 0; $binary = '';
        for ($i = 0; $i < strlen($secret); ++$i) {
            $buffer = ($buffer << 5) | strpos(self::ALPHABET, $secret[$i]); $bits += 5;
            if ($bits >= 8) { $bits -= 8; $binary .= chr(($buffer >> $bits) & 255); }
            $buffer &= (1 << $bits) - 1;
        }
        if (strlen($binary) < 20 || strlen($binary) > 128 || self::encodeSecret($binary) !== $secret) {
            throw new ConfigurationException('TOTP secret encoding is invalid.', 'configuration.totp_secret');
        }
        return $binary;
    }
}
