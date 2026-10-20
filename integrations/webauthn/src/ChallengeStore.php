<?php
declare(strict_types=1);

namespace SoSecurity\WebAuthn;

use InvalidArgumentException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\NamespacedStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

/** One-use, short-lived challenge options backed by a shared atomic store. */
final class ChallengeStore
{
    private $store;
    private $clock;
    private $serializer;
    private $ttl;

    public function __construct(AtomicStore $store, string $scope, ?Clock $clock = null, int $ttl = 300)
    {
        if ($scope === '' || strlen($scope) > 128 || $ttl < 30 || $ttl > 600) {
            throw new InvalidArgumentException('Invalid challenge scope or TTL');
        }
        $this->store = new NamespacedStore($store, 'webauthn:' . $scope);
        $this->clock = $clock ?? new SystemClock();
        $this->ttl = $ttl;
        $support = AttestationStatementSupportManager::create();
        $support->add(NoneAttestationStatementSupport::create());
        $this->serializer = (new WebauthnSerializerFactory($support))->create();
    }

    /** @param PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions $options */
    public function issue($options, string $subject, string $session): string
    {
        $type = $this->type($options);
        $binding = $this->binding($subject, $session);
        $json = $this->serializer->serialize($options, 'json');
        if (strlen($json) > 32768 || strlen($options->challenge) !== 32) {
            throw new InvalidArgumentException('WebAuthn options exceed challenge budget');
        }
        $expires = $this->clock->now() + $this->ttl;
        $value = ['v' => 1, 'type' => $type, 'binding' => $binding, 'options' => $json, 'expires' => $expires];
        for ($attempt = 0; $attempt < 3; ++$attempt) {
            $handle = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
            $created = $this->store->transact('challenge:' . $handle, static function ($current) use ($value, $expires): Change {
                if ($current !== null) {
                    if (!isset($current['expires']) || !is_int($current['expires']) || $current['expires'] < 1) {
                        throw new StorageException('Corrupt WebAuthn challenge state');
                    }
                    return new Change($current, $current['expires'], false);
                }
                return new Change($value, $expires, true);
            });
            if ($created === true) {
                return $handle;
            }
        }
        throw new StorageException('Unable to allocate unique WebAuthn challenge');
    }

    /** @return PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions|null */
    public function consume(string $handle, string $type, string $subject, string $session)
    {
        if (!preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $handle) ||
            ($type !== 'register' && $type !== 'authenticate')) {
            throw new InvalidArgumentException('Invalid challenge handle or type');
        }
        $binding = $this->binding($subject, $session);
        $now = $this->clock->now();
        $json = $this->store->transact('challenge:' . $handle, static function ($current) use ($type, $binding, $now): Change {
            if ($current === null) {
                return new Change(null, 0, null);
            }
            if (count($current) !== 5 || ($current['v'] ?? null) !== 1 ||
                !isset($current['type'], $current['binding'], $current['options'], $current['expires']) ||
                !is_string($current['type']) || !is_string($current['binding']) ||
                !is_string($current['options']) || !is_int($current['expires']) ||
                strlen($current['options']) > 32768 || $current['expires'] < 1) {
                throw new StorageException('Corrupt WebAuthn challenge state');
            }
            if ($current['expires'] <= $now) {
                return new Change(null, 0, null);
            }
            if ($current['type'] !== $type || !hash_equals($current['binding'], $binding)) {
                return new Change($current, $current['expires'], null);
            }
            return new Change(null, 0, $current['options']);
        });
        if ($json === null) {
            return null;
        }
        $class = $type === 'register' ? PublicKeyCredentialCreationOptions::class : PublicKeyCredentialRequestOptions::class;
        $options = $this->serializer->deserialize($json, $class, 'json');
        if (!$options instanceof $class || strlen($options->challenge) !== 32) {
            throw new StorageException('Corrupt WebAuthn challenge options');
        }
        return $options;
    }

    private function type($options): string
    {
        if ($options instanceof PublicKeyCredentialCreationOptions) {
            return 'register';
        }
        if ($options instanceof PublicKeyCredentialRequestOptions) {
            return 'authenticate';
        }
        throw new InvalidArgumentException('Unsupported WebAuthn options');
    }

    private function binding(string $subject, string $session): string
    {
        if ($subject === '' || $session === '' || strlen($subject) > 256 || strlen($session) > 256) {
            throw new InvalidArgumentException('Invalid challenge subject or session');
        }
        return hash('sha256', strlen($subject) . ':' . $subject . ':' . $session);
    }
}
