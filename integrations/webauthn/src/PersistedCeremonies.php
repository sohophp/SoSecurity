<?php
declare(strict_types=1);

namespace SoSecurity\WebAuthn;

use InvalidArgumentException;
use RuntimeException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialUserEntity;

/** Registered-user WebAuthn flow with required credential persistence. */
final class PersistedCeremonies
{
    private $bound;
    private $repository;
    private $clock;

    public function __construct(BoundCeremonies $bound, SqlCredentialRepository $repository, ?Clock $clock = null)
    {
        $this->bound = $bound;
        $this->repository = $repository;
        $this->clock = $clock ?? new SystemClock();
    }

    public function beginRegistration(PublicKeyCredentialUserEntity $user, string $session): array
    {
        $generation = $this->repository->generation($user->id);
        $records = array_map(static function (StoredCredential $stored): CredentialRecord {
            return $stored->record();
        }, $this->repository->forUser($user->id));
        return $this->bound->beginRegistration($user, $records, $this->session($session, $generation));
    }

    public function finishRegistration(string $handle, string $userHandle, string $session, string $response): CredentialRecord
    {
        $generation = $this->repository->generation($userHandle);
        $verified = $this->bound->finishRegistration($handle, $userHandle,
            $this->session($session, $generation), $response);
        $this->repository->register($verified, $this->clock->now(), $generation);
        return $verified;
    }

    public function beginAuthentication(string $userHandle, string $session): array
    {
        $generation = $this->repository->generation($userHandle);
        $records = array_map(static function (StoredCredential $stored): CredentialRecord {
            return $stored->record();
        }, $this->repository->forUser($userHandle));
        return $this->bound->beginAuthentication($userHandle, $records, $this->session($session, $generation));
    }

    /** Grant a login session only after this method has returned successfully. */
    public function finishAuthentication(string $handle, string $userHandle, string $session,
        string $response, string $credentialId): CredentialRecord
    {
        $generation = $this->repository->generation($userHandle);
        try {
            $stored = $this->repository->find($credentialId, $userHandle);
        } catch (InvalidArgumentException $e) {
            $stored = null;
        }
        $verified = $this->bound->finishAuthentication($handle, $userHandle,
            $this->session($session, $generation),
            $response, $stored === null ? null : $stored->record());
        if ($stored === null || !$this->repository->commitAssertion($stored, $verified, $this->clock->now())) {
            throw new RuntimeException('WebAuthn credential changed before login commit');
        }
        return $verified;
    }

    private function session(string $session, int $generation): string
    {
        if ($session === '' || strlen($session) > 256 || $generation < 0) {
            throw new InvalidArgumentException('Invalid WebAuthn session or generation');
        }
        return hash('sha256', strlen($session) . ':' . $session . ':' . $generation);
    }
}
