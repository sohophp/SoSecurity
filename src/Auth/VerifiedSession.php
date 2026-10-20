<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

final class VerifiedSession
{
    private $account;
    private $id;
    private $method;
    private $created;
    private $authenticated;
    private $expires;
    private $resumed;
    public function __construct(Account $account, string $id, string $method, int $createdAt, int $authenticatedAt, int $expiresAt, bool $resumed = false)
    {
        SessionRegistry::strength($method);
        $this->account = $account; $this->id = $id; $this->method = $method; $this->created = $createdAt;
        $this->authenticated = $authenticatedAt; $this->expires = $expiresAt; $this->resumed = $resumed;
    }
    public function account(): Account { return $this->account; }
    public function id(): string { return $this->id; }
    public function method(): string { return $this->method; }
    public function createdAt(): int { return $this->created; }
    public function authenticatedAt(): int { return $this->authenticated; }
    public function expiresAt(): int { return $this->expires; }
    public function resumed(): bool { return $this->resumed; }
    public function strength(): int { return SessionRegistry::strength($this->method); }
    public function recent(int $maximumAge, int $now, int $minimumStrength = 2): bool
    {
        \SoSecurity\Support\Guard::duration($maximumAge);
        if ($minimumStrength < 0 || $minimumStrength > 2) { throw new \SoSecurity\Exception\ConfigurationException('Invalid authentication strength.', 'configuration.authentication'); }
        return !$this->resumed && $this->authenticated > 0 && $now >= $this->authenticated && $now < $this->expires
            && $now - $this->authenticated < $maximumAge && $this->strength() >= $minimumStrength;
    }
    public function __set(string $name, $value): void { throw new \SoSecurity\Exception\ConfigurationException('Verified sessions are immutable.', 'configuration.immutable'); }
    public function __sleep(): array { throw new \SoSecurity\Exception\ConfigurationException('Revalidate the registry on every request instead of serializing verified authority.', 'configuration.identity_serialization'); }
}
