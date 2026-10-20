<?php
declare(strict_types=1);
namespace SoSecurity\Operation;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Auth\VerifiedSession;
use SoSecurity\Exception\ConfigurationException;

final class Policy
{
    private $ttl;
    private $capacity;
    private $age;
    private $strength;
    private $methods = [];
    public function __construct(int $ttl = 120, int $capacity = 8, int $maximumAge = 300, int $minimumStrength = 2, array $methods = ['totp','webauthn'])
    {
        if ($ttl < 1 || $ttl > 300 || $capacity < 1 || $capacity > 16 || $maximumAge < 1 || $maximumAge > 900 || $minimumStrength < 1 || $minimumStrength > 2
            || !$methods || count($methods) > 4 || array_values($methods) !== $methods) { throw new ConfigurationException('Invalid bounded operation policy.', 'configuration.operation'); }
        foreach ($methods as $method) {
            if (!is_string($method) || !in_array($method,['password','totp','recovery','webauthn'],true) || in_array($method,$this->methods,true)
                || SessionRegistry::strength($method) < $minimumStrength) { throw new ConfigurationException('Invalid operation authentication method.', 'configuration.operation'); }
            $this->methods[] = $method;
        }
        sort($this->methods); $this->ttl = $ttl; $this->capacity = $capacity; $this->age = $maximumAge; $this->strength = $minimumStrength;
    }
    public function ttl(): int { return $this->ttl; }
    public function capacity(): int { return $this->capacity; }
    public function maximumAge(): int { return $this->age; }
    public function minimumStrength(): int { return $this->strength; }
    public function methods(): array { return $this->methods; }
    public function accepts(VerifiedSession $session, int $now): bool { return in_array($session->method(),$this->methods,true) && $session->recent($this->age,$now,$this->strength); }
    public function fingerprint(): string { return hash('sha256',json_encode([$this->ttl,$this->capacity,$this->age,$this->strength,$this->methods])); }
    public function __set(string $name,$value): void { throw new ConfigurationException('Operation policies are immutable.','configuration.immutable'); }
}
