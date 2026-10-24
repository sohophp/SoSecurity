<?php
declare(strict_types=1);

namespace SoSecurity\WebAuthn;

use InvalidArgumentException;
use RuntimeException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;

/** Authorized single-device removal; last-device recovery is a separate workflow. */
final class DeviceManager
{
    private $repository;
    private $authority;
    private $notice;
    private $clock;

    public function __construct(SqlCredentialRepository $repository, DeviceAuthority $authority,
        callable $onRemoved, ?Clock $clock = null)
    {
        $this->repository = $repository;
        $this->authority = $authority;
        $this->notice = $onRemoved;
        $this->clock = $clock ?? new SystemClock();
    }

    /** $proof is host-defined and must be consumed by DeviceAuthority before changing SQL state. */
    public function remove(string $userHandle, string $credentialId, $proof): bool
    {
        if ($userHandle === '' || strlen($userHandle) > 256 ||
            $credentialId === '' || strlen($credentialId) > 1024) {
            throw new InvalidArgumentException('Invalid WebAuthn device identity');
        }
        $now = $this->now();
        try {
            $allowed = $this->authority->allow('before', $this->repository->scope(),
                $userHandle, $credentialId, $proof, $now);
        } catch (\Throwable $e) {
            throw new RuntimeException('WebAuthn removal authority unavailable');
        }
        if ($allowed !== true) { return false; }
        $stored = $this->repository->find($credentialId, $userHandle);
        if ($stored === null) { return false; }
        try {
            $now = $this->now($now);
            $allowed = $this->authority->allow('current', $this->repository->scope(),
                $userHandle, $credentialId, $proof, $now);
            $now = $this->now($now);
        } catch (\Throwable $e) {
            throw new RuntimeException('WebAuthn removal authority unavailable');
        }
        if ($allowed !== true || !$this->repository->revokeKeepingOne($stored, $now)) { return false; }
        try {
            if ($this->authority->allow('return', $this->repository->scope(),
                $userHandle, $credentialId, $proof, $this->now($now)) !== true) {
                throw new RuntimeException('WebAuthn removal authority changed');
            }
            ($this->notice)($userHandle, $credentialId, $now);
        } catch (\Throwable $e) {
            throw new RuntimeException('WebAuthn removal outcome requires reconciliation');
        }
        return true;
    }
    private function now(?int $seen = null): int
    {
        try { $now = $this->clock->now(); }
        catch (\Throwable $error) { throw new RuntimeException('WebAuthn removal clock unavailable'); }
        if ($now < 0 || ($seen !== null && $now < $seen)) {
            throw new RuntimeException('Invalid WebAuthn removal clock');
        }
        return $now;
    }

}
