<?php
declare(strict_types=1);

namespace SoSecurity\Oidc;

use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Durable at-least-once logout delivery; the host callback must revoke federated sessions idempotently. */
final class LogoutProcessor
{
    private $store;
    private $client;
    private $clock;

    public function __construct(AtomicStore $store, StrictClient $client, ?Clock $clock = null)
    {
        if (get_class($client) !== StrictClient::class) {
            throw new SecurityException('Use the exact strict OIDC client.', 'federation.client');
        }
        $this->store = $store;
        $this->client = $client;
        $this->clock = $clock ?? new SystemClock();
    }

    /** Return success only after a durable host revocation; retries may invoke the callback again. */
    public function process(string $scope, $jwt, callable $revoke): bool
    {
        Guard::label($scope);
        $proof = VerifiedLogout::fromToken($this->client, $jwt);
        $digest = hash('sha256', $jwt);
        $key = Guard::key('oidc-logout', $scope, hash('sha256', strlen($proof->issuer()) . ':' . $proof->issuer()
            . strlen($proof->tokenId()) . ':' . $proof->tokenId()));
        $now = $this->clock->now();
        if ($now < 0 || $now > PHP_INT_MAX - 172800) {
            throw new SecurityException('Logout clock out of range.', 'federation.clock');
        }
        $expires = $now + 172800;
        $done = $this->store->transact($key, function ($old) use ($digest, $now, $expires) {
            $row = $this->read($old);
            if ($row !== null && !hash_equals($row['digest'], $digest)) {
                throw new SecurityException('Logout token ID collision.', 'federation.logout_conflict');
            }
            if ($row === null) { $row = ['v' => 1, 'digest' => $digest, 'status' => 'pending', 'created' => $now]; }
            return new Change($row, $expires, $row['status'] === 'done');
        });
        if ($done) { return true; }
        if ($revoke($proof, $scope) !== true) {
            throw new SecurityException('Federated session revocation is incomplete.', 'federation.logout_incomplete');
        }
        return $this->store->transact($key, function ($old) use ($digest, $expires) {
            $row = $this->read($old);
            if ($row === null || !hash_equals($row['digest'], $digest)) {
                throw new StorageException('Logout receipt disappeared or changed.', 'storage.corrupt');
            }
            $row['status'] = 'done';
            return new Change($row, $expires, true);
        });
    }

    private function read($value): ?array
    {
        if ($value === null) { return null; }
        if (!is_array($value)) { throw new StorageException('Corrupt logout receipt.', 'storage.corrupt'); }
        $keys = array_keys($value); sort($keys);
        if ($keys !== ['created', 'digest', 'status', 'v'] || $value['v'] !== 1
            || !is_string($value['digest']) || preg_match('/\A[a-f0-9]{64}\z/D', $value['digest']) !== 1
            || !in_array($value['status'], ['pending', 'done'], true)
            || !is_int($value['created']) || $value['created'] < 0) {
            throw new StorageException('Corrupt logout receipt.', 'storage.corrupt');
        }
        return $value;
    }
}
