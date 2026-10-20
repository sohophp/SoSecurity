<?php
declare(strict_types=1);

namespace SoSecurity\WebAuthn;

use Cose\Algorithms;
use InvalidArgumentException;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Signal\AllAcceptedCredentials;

/** Stateless verifier. The host must persist and consume options exactly once. */
final class Ceremonies
{
    private $rp;
    private $host;
    private $serializer;
    private $attestation;
    private $assertion;

    public function __construct(string $rpName, string $rpId, string $origin)
    {
        if ($rpName === '' || $rpId === '' || strpos($rpId, '://') !== false ||
            !preg_match('~^https://[^/?#]+$~D', $origin) ||
            parse_url($origin, PHP_URL_HOST) !== $rpId ||
            parse_url($origin, PHP_URL_USER) !== null ||
            parse_url($origin, PHP_URL_PASS) !== null) {
            throw new InvalidArgumentException('An HTTPS origin with the exact RP ID host is required');
        }
        $this->rp = PublicKeyCredentialRpEntity::create($rpName, $rpId);
        $this->host = $rpId;
        $support = AttestationStatementSupportManager::create();
        $support->add(NoneAttestationStatementSupport::create());
        $this->serializer = (new WebauthnSerializerFactory($support))->create();
        $factory = new CeremonyStepManagerFactory();
        $factory->setAllowedOrigins([$origin]);
        $this->attestation = AuthenticatorAttestationResponseValidator::create($factory->creationCeremony());
        $this->assertion = AuthenticatorAssertionResponseValidator::create($factory->requestCeremony());
    }

    /** @param array<mixed> $existing */
    public function beginRegistration(PublicKeyCredentialUserEntity $user, array $existing): PublicKeyCredentialCreationOptions
    {
        $exclude = [];
        foreach ($existing as $record) {
            if (!$record instanceof CredentialRecord || $record->userHandle !== $user->id) {
                throw new InvalidArgumentException('Invalid existing credential');
            }
            $exclude[] = $record->getPublicKeyCredentialDescriptor();
        }
        return PublicKeyCredentialCreationOptions::create($this->rp, $user, random_bytes(32),
            pubKeyCredParams: [
                PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_ES256),
                PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_RS256),
            ],
            authenticatorSelection: AuthenticatorSelectionCriteria::create(
                userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED),
            attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            excludeCredentials: $exclude);
    }

    public function finishRegistration(PublicKeyCredentialCreationOptions $options, string $response): CredentialRecord
    {
        if ($options->rp->id !== $this->host) {
            throw new InvalidArgumentException('RP ID mismatch');
        }
        $credential = $this->load($response);
        if (!$credential->response instanceof AuthenticatorAttestationResponse) {
            throw new InvalidArgumentException('Expected attestation response');
        }
        $record = $this->attestation->check($credential->response, $options, $this->host);
        if (!hash_equals($record->publicKeyCredentialId, $credential->rawId)) {
            throw new InvalidArgumentException('Credential ID mismatch');
        }
        return $record;
    }

    /** @param array<mixed> $registered */
    public function beginAuthentication(string $userHandle, array $registered): PublicKeyCredentialRequestOptions
    {
        if ($userHandle === '' || $registered === []) {
            throw new InvalidArgumentException('At least one credential is required');
        }
        $allow = [];
        foreach ($registered as $record) {
            if (!$record instanceof CredentialRecord || $record->userHandle !== $userHandle) {
                throw new InvalidArgumentException('Invalid registered credential');
            }
            $allow[] = $record->getPublicKeyCredentialDescriptor();
        }
        return PublicKeyCredentialRequestOptions::create(random_bytes(32), $this->host, $allow,
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED);
    }

    public function finishAuthentication(PublicKeyCredentialRequestOptions $options, string $response,
        CredentialRecord $record, string $userHandle): CredentialRecord
    {
        if ($options->rpId !== $this->host || $record->userHandle !== $userHandle) {
            throw new InvalidArgumentException('Credential owner or RP ID mismatch');
        }
        $credential = $this->load($response);
        if (!$credential->response instanceof AuthenticatorAssertionResponse ||
            !hash_equals($record->publicKeyCredentialId, $credential->rawId)) {
            throw new InvalidArgumentException('Credential ID or response type mismatch');
        }
        $allowed = false;
        foreach ($options->allowCredentials as $descriptor) {
            $allowed = $allowed || hash_equals($descriptor->id, $credential->rawId);
        }
        if (!$allowed) {
            throw new InvalidArgumentException('Credential not allowed by challenge');
        }
        return $this->assertion->check($record, $credential->response, $options, $this->host, $userHandle);
    }

    /** @param array<mixed> $remaining Browser signal after an authorized server-side deletion. */
    public function acceptedCredentialsSignal(PublicKeyCredentialUserEntity $user, array $remaining): string
    {
        if (count($remaining) > 32) { throw new InvalidArgumentException('Too many credentials for signal'); }
        $descriptors = [];
        foreach ($remaining as $record) {
            if (!$record instanceof CredentialRecord || $record->userHandle !== $user->id) {
                throw new InvalidArgumentException('Invalid signal credential owner');
            }
            $descriptors[] = $record->getPublicKeyCredentialDescriptor();
        }
        return $this->serializer->serialize(new AllAcceptedCredentials($this->rp, $user, $descriptors), 'json');
    }

    private function load(string $response): PublicKeyCredential
    {
        if ($response === '' || strlen($response) > 65536) {
            throw new InvalidArgumentException('WebAuthn response size is invalid');
        }
        $credential = $this->serializer->deserialize($response, PublicKeyCredential::class, 'json');
        if (!$credential instanceof PublicKeyCredential) {
            throw new InvalidArgumentException('Invalid WebAuthn response');
        }
        return $credential;
    }
}
