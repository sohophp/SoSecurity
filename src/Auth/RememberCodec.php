<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\Guard;

/** Internal opaque-token framing. MAC authenticates old generations without storing every historical secret. */
final class RememberCodec
{
    private $keys;
    public function __construct(HmacKeys $keys) { $this->keys = $keys; }
    public function issue(string $scope, string $selector, int $generation, string $secret): string
    {
        if ($generation < 0 || $generation > 2147483647 || !preg_match('/\A[a-f0-9]{32}\z/D', $selector) || !preg_match('/\A[a-f0-9]{64}\z/D', $secret)) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid persistent credential material.', 'configuration.remember');
        }
        $id = $this->keys->currentId(); $counter = sprintf('%08x', $generation);
        return 'sorp1.' . $id . '.' . $selector . '.' . $counter . '.' . $secret . '.' . bin2hex($this->keys->sign($this->message($scope, $id, $selector, $counter, $secret)));
    }
    public function parse(string $scope, $token): ?array
    {
        Guard::label($scope);
        if (!is_string($token) || strlen($token) > 210 || !preg_match('/\Asorp1\.([A-Za-z][A-Za-z0-9_-]{0,31})\.([a-f0-9]{32})\.([0-7][a-f0-9]{7})\.([a-f0-9]{64})\.([a-f0-9]{64})\z/D', $token, $parts)) { return null; }
        if (!$this->keys->verify($parts[1], $this->message($scope, $parts[1], $parts[2], $parts[3], $parts[4]), hex2bin($parts[5]))) { return null; }
        return ['id' => $parts[2], 'generation' => hexdec($parts[3]), 'digest' => hash('sha256', $token)];
    }
    private function message(string $scope, string $id, string $selector, string $counter, string $secret): string
    {
        Guard::label($scope);
        return 'SoSecurity.Remember.1.' . strlen($scope) . ':' . $scope . strlen($id) . ':' . $id . ':' . $selector . ':' . $counter . ':' . $secret;
    }
    public function __debugInfo(): array { return ['keys' => '[redacted]']; }
    public function __sleep(): array { throw new \SoSecurity\Exception\ConfigurationException('Do not serialize private token codecs.', 'configuration.keys_serialization'); }
}
