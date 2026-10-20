<?php
declare(strict_types=1);

namespace SoSecurity\WebAuthn;

use InvalidArgumentException;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/** Binds WebAuthn verification to a one-use account/session challenge. */
final class BoundCeremonies
{
    private $ceremonies;
    private $challenges;

    public function __construct(Ceremonies $ceremonies, ChallengeStore $challenges)
    {
        $this->ceremonies = $ceremonies;
        $this->challenges = $challenges;
    }

    /** @param CredentialRecord[] $existing @return array{handle:string,options:PublicKeyCredentialCreationOptions} */
    public function beginRegistration(PublicKeyCredentialUserEntity $user, array $existing, string $session): array
    {
        $options = $this->ceremonies->beginRegistration($user, $existing);
        return ['handle' => $this->challenges->issue($options, $user->id, $session), 'options' => $options];
    }

    public function finishRegistration(string $handle, string $userHandle, string $session, string $response): CredentialRecord
    {
        $options = $this->challenges->consume($handle, 'register', $userHandle, $session);
        if (!$options instanceof PublicKeyCredentialCreationOptions || $options->user->id !== $userHandle) {
            throw new InvalidArgumentException('WebAuthn registration challenge is unavailable');
        }
        return $this->ceremonies->finishRegistration($options, $response);
    }

    /** @param CredentialRecord[] $registered @return array{handle:string,options:PublicKeyCredentialRequestOptions} */
    public function beginAuthentication(string $userHandle, array $registered, string $session): array
    {
        $options = $this->ceremonies->beginAuthentication($userHandle, $registered);
        return ['handle' => $this->challenges->issue($options, $userHandle, $session), 'options' => $options];
    }

    public function finishAuthentication(string $handle, string $userHandle, string $session,
        string $response, ?CredentialRecord $record): CredentialRecord
    {
        $options = $this->challenges->consume($handle, 'authenticate', $userHandle, $session);
        if (!$options instanceof PublicKeyCredentialRequestOptions || $record === null) {
            throw new InvalidArgumentException('WebAuthn authentication challenge is unavailable');
        }
        return $this->ceremonies->finishAuthentication($options, $response, $record, $userHandle);
    }
}
