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
        $now = $this->clock->now();
        try {
            $allowed = $this->authority->allow('before', $this->repository->scope(),
                $userHandle, $credentialId, $proof, $now);
        } catch (\Throwable $e) {
            throw new RuntimeException('WebAuthn removal authority unavailable', 0, $e);
        }
        if ($allowed !== true) { return false; }
        $stored = $this->repository->find($credentialId, $userHandle);
        if ($stored === null || !$this->repository->revokeKeepingOne($stored, $now)) { return false; }
        try {
            if ($this->authority->allow('return', $this->repository->scope(),
                $userHandle, $credentialId, $proof, $this->clock->now()) !== true) {
                throw new RuntimeException('WebAuthn removal authority changed');
            }
            ($this->notice)($userHandle, $credentialId, $now);
        } catch (\Throwable $e) {
            throw new RuntimeException('WebAuthn removal outcome requires reconciliation', 0, $e);
        }
        return true;
    }
}
