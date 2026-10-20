<?php
declare(strict_types=1);

namespace SoSecurity\Oidc;

use RuntimeException;

/** A signed back-channel Logout Token; hosts must durably revoke matching federated sessions. */
final class VerifiedLogout
{
    private $read;

    private function __construct(string $issuer, ?string $subject, ?string $sessionId, string $tokenId, int $issuedAt)
    {
        $this->read = static function () use ($issuer, $subject, $sessionId, $tokenId, $issuedAt): array {
            return [$issuer, $subject, $sessionId, $tokenId, $issuedAt];
        };
    }

    public static function fromToken(StrictClient $client, $jwt): self
    {
        if (get_class($client) !== StrictClient::class || !is_string($jwt) || strlen($jwt) > 16384
            || !preg_match('/\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z/D', $jwt)) {
            throw new RuntimeException('Invalid OIDC logout token.');
        }
        $parts = explode('.', $jwt);
        $header = json_decode(self::decode($parts[0]));
        $claims = json_decode(self::decode($parts[1]));
        if (!is_object($header) || !is_object($claims) || !isset($header->alg)
            || !in_array($header->alg, ['RS256', 'PS256'], true)
            || (property_exists($header, 'typ') && $header->typ !== 'logout+jwt')
            || property_exists($header, 'crit') || property_exists($header, 'jku')
            || property_exists($header, 'x5u') || property_exists($header, 'jwk')
            || property_exists($header, 'x5c') || property_exists($header, 'b64')
            || (property_exists($header, 'kid') && !self::label($header->kid, 128))
            || !isset($claims->iss, $claims->aud, $claims->iat, $claims->jti, $claims->events)
            || $claims->iss !== $client->getIssuer() || !self::audience($claims->aud, $client->getClientID(), $claims->azp ?? null)
            || (property_exists($claims, 'azp') && (!is_string($claims->azp) || $claims->azp !== $client->getClientID()))
            || !is_int($claims->iat) || $claims->iat < time() - 86400 || $claims->iat > time() + 60
            || !self::label($claims->jti, 128) || !is_object($claims->events)
            || !property_exists($claims->events, 'http://schemas.openid.net/event/backchannel-logout')
            || !is_object($claims->events->{'http://schemas.openid.net/event/backchannel-logout'})
            || property_exists($claims, 'nonce')
            || (property_exists($claims, 'exp') && (!is_int($claims->exp) || $claims->exp <= time() || $claims->exp > $claims->iat + 86400))
            || (property_exists($claims, 'nbf') && (!is_int($claims->nbf) || $claims->nbf > time() + 60))) {
            throw new RuntimeException('Invalid OIDC logout token claims.');
        }
        $hasSubject = property_exists($claims, 'sub');
        $hasSessionId = property_exists($claims, 'sid');
        $subject = $hasSubject ? $claims->sub : null;
        $sessionId = $hasSessionId ? $claims->sid : null;
        if ((!$hasSubject && !$hasSessionId)
            || ($hasSubject && !self::label($subject, 255))
            || ($hasSessionId && !self::label($sessionId, 255))) {
            throw new RuntimeException('Invalid OIDC logout target.');
        }
        $client->verifySignatures($jwt);
        return new self($claims->iss, $subject, $sessionId, $claims->jti, $claims->iat);
    }

    private function data(): array
    {
        if (!$this->read instanceof \Closure) { throw new RuntimeException('Reload logout proof from current signature verification.'); }
        return ($this->read)();
    }
    public function issuer(): string { return $this->data()[0]; }
    public function subject(): ?string { return $this->data()[1]; }
    public function sessionId(): ?string { return $this->data()[2]; }
    public function tokenId(): string { return $this->data()[3]; }
    public function issuedAt(): int { return $this->data()[4]; }
    public function __debugInfo(): array { return ['issuer' => $this->issuer(), 'subject' => '[redacted]', 'sid' => '[redacted]', 'jti' => '[redacted]']; }
    public function __sleep(): array { throw new RuntimeException('Do not serialize logout proofs.'); }
    public function __wakeup(): void { throw new RuntimeException('Reload logout proof from current signature verification.'); }
    public function __set(string $name, $value): void { throw new RuntimeException('Verified logout proofs are immutable.'); }

    private static function decode(string $part): string
    {
        $raw = base64_decode(strtr($part, '-_', '+/') . str_repeat('=', (4 - strlen($part) % 4) % 4), true);
        if ($raw === false || rtrim(strtr(base64_encode($raw), '+/', '-_'), '=') !== $part) {
            throw new RuntimeException('Invalid OIDC logout token encoding.');
        }
        return $raw;
    }

    private static function label($value, int $maximum): bool
    {
        return is_string($value) && $value !== '' && strlen($value) <= $maximum
            && preg_match('/\A[\x21-\x7e]+\z/D', $value) === 1;
    }

    private static function audience($value, $expected, $authorizedParty): bool
    {
        if (!is_string($expected) || $expected === '') { return false; }
        if ($authorizedParty !== null && $authorizedParty !== $expected) { return false; }
        if (is_string($value)) { return hash_equals($expected, $value); }
        if (!is_array($value) || count($value) < 1 || count($value) > 8) { return false; }
        $seen = [];
        foreach ($value as $audience) {
            if (!self::label($audience, 256) || isset($seen[$audience])) { return false; }
            $seen[$audience] = true;
        }
        return isset($seen[$expected]) && (count($value) === 1 || $authorizedParty === $expected);
    }
}
