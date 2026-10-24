<?php
declare(strict_types=1);

namespace SoSecurity\WebAuthn;

use InvalidArgumentException;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Optional host adapter; the callback must read a fresh, protected server-side session each time. */
final class SessionDeviceAuthority implements DeviceAuthority
{
    private $scope;
    private $sessions;
    private $csrf;
    private $currentSession;
    private $clock;
    private $recentSeconds;
    private $before;

    /** $currentSession returns subject, opaque registry token and host session binding from trusted state. */
    public function __construct(string $scope, SessionRegistry $sessions, CsrfTokens $csrf,
        callable $currentSession, ?Clock $clock = null, int $recentSeconds = 300)
    {
        $this->scope = Guard::label($scope);
        if ($recentSeconds < 1 || $recentSeconds > 600) {
            throw new InvalidArgumentException('Invalid WebAuthn recent authentication age');
        }
        $this->sessions = $sessions;
        $this->csrf = $csrf;
        $this->currentSession = $currentSession;
        $this->clock = $clock ?? new SystemClock();
        $this->recentSeconds = $recentSeconds;
    }

    /** Issue only while this exact account has a current, strong and recent host session. */
    public function issueRemovalProof(string $userHandle, string $credentialId): string
    {
        $this->identity($userHandle, $credentialId);
        $current = $this->current($userHandle, $this->now());
        if ($current === null) {
            throw new SecurityException('Recent WebAuthn device authority required', 'webauthn.denied');
        }
        $proof = $this->requestProof(function()use($credentialId,$current):string{return $this->csrf->issue($this->proofScope($credentialId), $current['binding']);});
        if (!$this->live($current)) {
            throw new SecurityException('Recent WebAuthn device authority expired', 'webauthn.denied');
        }
        return $proof;
    }

    public function allow(string $phase, string $scope, string $userHandle, string $credentialId,
        $proof, int $now): bool
    {
        $before = $this->before;
        $this->before = null;
        if (($phase !== 'before' && $phase !== 'current' && $phase !== 'return') || $scope !== $this->scope ||
            !is_string($proof) || $proof === '' || $userHandle === '' || strlen($userHandle) > 256 ||
            $credentialId === '' || strlen($credentialId) > 1024) {
            return false;
        }
        $current = $this->current($userHandle, $now);
        if ($current === null) { return false; }
        if ($phase === 'before') {
            if (!$this->requestProof(function()use($credentialId,$current,$proof):bool{return $this->csrf->verify($this->proofScope($credentialId), $current['binding'], $proof, true);}) || !$this->live($current)) {
                return false;
            }
            $this->before = [$userHandle, $credentialId, $current['session'], $current['binding'], hash('sha256', $proof)];
            return true;
        }
        $accepted = $before !== null && $before ===
            [$userHandle, $credentialId, $current['session'], $current['binding'], hash('sha256', $proof)];
        if ($accepted && $phase === 'current') { $this->before = $before; }
        return $accepted;
    }

    private function identity(string $userHandle, string $credentialId): void
    {
        if ($userHandle === '' || strlen($userHandle) > 256 ||
            $credentialId === '' || strlen($credentialId) > 1024) {
            throw new InvalidArgumentException('Invalid WebAuthn device identity');
        }
    }

    private function proofScope(string $credentialId): string
    {
        return 'webauthn.remove:' . hash('sha256', strlen($this->scope) . ':' . $this->scope . $credentialId);
    }

    private function current(string $userHandle, int $now): ?array
    {
        try { $reference = ($this->currentSession)(); }
        catch (\Throwable $error) { throw new DependencyException('WebAuthn session authority unavailable', 'webauthn.authority_unavailable'); }
        if (!is_array($reference) || !isset($reference['subject'], $reference['token'], $reference['binding']) ||
            !is_string($reference['subject']) || !hash_equals($userHandle, $reference['subject']) ||
            !is_string($reference['token']) || !is_string($reference['binding']) ||
            $reference['binding'] === '' || strlen($reference['binding']) > 256) {
            return null;
        }
        try { $verified = $this->sessions->verify($this->scope, $userHandle, $reference['token'], 2); }
        catch (\Throwable $error) { throw new DependencyException('WebAuthn session authority unavailable', 'webauthn.authority_unavailable'); }
        $checkedAt = $this->now();
        if ($checkedAt < $now || $verified === null || !$verified->recent($this->recentSeconds, $checkedAt, 2)) {
            return null;
        }
        $binding = hash('sha256', strlen($reference['binding']) . ':' . $reference['binding'] . $verified->id());
        return ['session' => $verified->id(), 'binding' => $binding, 'checked_at' => $checkedAt,
            'until' => min($verified->expiresAt(), $verified->authenticatedAt() + $this->recentSeconds)];
    }

    private function requestProof(callable $operation)
    {
        try { return $operation(); }
        catch (\Throwable $error) {
            if ($error instanceof StorageException && $error->reason() === 'csrf.clock') {
                throw new StorageException('WebAuthn request proof clock unavailable', 'csrf.clock');
            }
            throw new DependencyException('WebAuthn request proof unavailable', 'webauthn.request_unavailable');
        }
    }

    private function now(): int
    {
        try { $now = $this->clock->now(); }
        catch (\Throwable $error) { throw new DependencyException('WebAuthn authority clock unavailable', 'webauthn.clock'); }
        if ($now < 0 || $now > PHP_INT_MAX - 86400) {
            throw new SecurityException('Invalid WebAuthn authority clock', 'webauthn.clock');
        }
        return $now;
    }

    private function live(array $current): bool
    {
        $now = $this->now();
        return $now >= $current['checked_at'] && $now < $current['until'];
    }
}
