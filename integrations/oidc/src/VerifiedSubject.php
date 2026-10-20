<?php
declare(strict_types=1);

namespace SoSecurity\Oidc;

use RuntimeException;

/** The client has completed its authorization-code callback before this object is created. */
final class VerifiedSubject
{
    private $read;

    private function __construct(string $issuer, string $subject, int $issuedAt, ?string $providerSessionId)
    {
        $this->read = static function () use ($issuer, $subject, $issuedAt, $providerSessionId): array {
            return [$issuer, $subject, $issuedAt, $providerSessionId];
        };
    }

    public static function fromClient(StrictClient $client): ?self
    {
        if (get_class($client) !== StrictClient::class) {
            throw new RuntimeException('Only the strict OIDC client may create an external identity proof.');
        }
        $pair = $client->authenticateSubject();
        if ($pair === null) { return null; }
        if (array_keys($pair) !== ['issuer', 'subject', 'issued_at', 'sid']
            || !is_string($pair['issuer']) || !is_string($pair['subject'])
            || strlen($pair['issuer']) > 2048 || preg_match('/\Ahttps:\/\/[^\x00-\x20\x7f]+\z/D', $pair['issuer']) !== 1
            || strlen($pair['subject']) > 255 || preg_match('/\A[\x21-\x7e]+\z/D', $pair['subject']) !== 1
            || !is_int($pair['issued_at']) || $pair['issued_at'] < 0
            || ($pair['sid'] !== null && (!is_string($pair['sid']) || strlen($pair['sid']) > 255
                || preg_match('/\A[\x21-\x7e]+\z/D', $pair['sid']) !== 1))) {
            throw new RuntimeException('OIDC client did not return a verified subject.');
        }
        return new self($pair['issuer'], $pair['subject'], $pair['issued_at'], $pair['sid']);
    }

    private function data(): array
    {
        if (!$this->read instanceof \Closure) { throw new RuntimeException('Reload external identity proof from current verification.'); }
        return ($this->read)();
    }
    public function issuer(): string { return $this->data()[0]; }
    public function subject(): string { return $this->data()[1]; }
    public function issuedAt(): int { return $this->data()[2]; }
    public function providerSessionId(): ?string { return $this->data()[3]; }
    public function __debugInfo(): array { return ['issuer' => $this->issuer(), 'subject' => '[redacted]', 'sid' => '[redacted]']; }
    public function __sleep(): array { throw new RuntimeException('Do not serialize external identity proofs.'); }
    public function __wakeup(): void { throw new RuntimeException('Reload external identity proof from current verification.'); }
    public function __set(string $name, $value): void { throw new RuntimeException('Verified external identity proofs are immutable.'); }
}
