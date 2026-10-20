<?php
declare(strict_types=1);

namespace SoSecurity\WebAuthn;

use InvalidArgumentException;
use RuntimeException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;

/** Strongly approved account-wide credential revocation; enrollment uses a new generation. */
final class RecoveryManager
{
    private $repository;
    private $authority;
    private $clock;

    public function __construct(SqlCredentialRepository $repository, RecoveryAuthority $authority, ?Clock $clock = null)
    {
        $this->repository = $repository;
        $this->authority = $authority;
        $this->clock = $clock ?? new SystemClock();
    }

    /** Return new generation only after host completion; failure after begin requires reconciliation. */
    public function recover(string $userHandle, $proof): ?int
    {
        if ($userHandle === '' || strlen($userHandle) > 256) {
            throw new InvalidArgumentException('Invalid WebAuthn recovery account');
        }
        $now = $this->clock->now();
        try {
            $allowed = $this->authority->begin($this->repository->scope(), $userHandle, $proof, $now);
        } catch (\Throwable $e) {
            throw new RuntimeException('WebAuthn recovery authority unavailable', 0, $e);
        }
        if ($allowed !== true) { return null; }
        try {
            $generation = $this->repository->revokeAllForRecovery($userHandle, $now);
            if ($this->authority->complete($this->repository->scope(), $userHandle,
                $generation, $this->clock->now()) !== true) {
                throw new RuntimeException('WebAuthn recovery completion denied');
            }
            return $generation;
        } catch (\Throwable $e) {
            throw new RuntimeException('WebAuthn recovery outcome requires reconciliation', 0, $e);
        }
    }
}
