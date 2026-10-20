<?php
declare(strict_types=1);

namespace SoSecurity\Mfa;

/** Sensitive provisioning result. Deliver only to the authorized account over TLS, without caching/logging. */
final class Enrollment
{
    private $read;

    public function __construct(string $id, string $uri, int $expiresAt)
    {
        $this->read=static function()use($id,$uri,$expiresAt):array{return [$id,$uri,$expiresAt];};
    }
    public function id(): string { return ($this->read)()[0]; }
    public function provisioningUri(): string { return ($this->read)()[1]; }
    public function expiresAt(): int { return ($this->read)()[2]; }
    public function __debugInfo(): array { return ['id' => $this->id(), 'expires' => $this->expiresAt(), 'provisioning_uri' => '[redacted]']; }
    public function __sleep(): array { throw new \SoSecurity\Exception\ConfigurationException('Do not serialize MFA enrollment secrets.', 'configuration.mfa_serialization'); }
    public function __wakeup():void {throw new \SoSecurity\Exception\ConfigurationException('Reload current authorized MFA enrollment data.','configuration.mfa_serialization');}
    public function __set(string $name, $value): void { throw new \SoSecurity\Exception\ConfigurationException('Enrollment is immutable.', 'configuration.immutable'); }
}
