<?php
declare(strict_types=1);

namespace SoSecurity\Csrf;

use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

final class CsrfTokens
{
    private $store;
    private $clock;
    private $ttl;
    private $capacity;

    public function __construct(AtomicStore $store, int $ttl = 7200, int $capacity = 16, ?Clock $clock = null)
    {
        Guard::duration($ttl);
        if ($capacity < 1 || $capacity > 64) {
            throw new \SoSecurity\Exception\ConfigurationException('Token capacity must be between 1 and 64.');
        }
        $this->store = $store;
        $this->ttl = $ttl;
        $this->capacity = $capacity;
        $this->clock = $clock ?? new SystemClock();
    }

    public function issue(string $scope, string $binding): string
    {
        $key = Guard::key('csrf', $scope, $binding);
        $token = bin2hex(random_bytes(32));
        $digest = hash('sha256', $token);
        $now = $this->clock->now();
        return $this->store->transact($key, function (?array $state) use ($token, $digest, $now) {
            $this->validateState($state);
            $tokens = array_filter($state ?? [], function ($expires) use ($now) { return $expires > $now; });
            while (count($tokens) >= $this->capacity) {
                array_shift($tokens);
            }
            $tokens[$digest] = $now + $this->ttl;
            return new Change($tokens, max($tokens), $token);
        });
    }

    /** Single-use is optional: ordinary forms remain valid across tabs and resubmissions. */
    public function verify(string $scope, string $binding, $token, bool $singleUse = false): bool
    {
        $key = Guard::key('csrf', $scope, $binding);
        if (!is_string($token) || !preg_match('/^[a-f0-9]{64}$/D', $token)) {
            return false;
        }
        $digest = hash('sha256', $token);
        $now = $this->clock->now();
        return $this->store->transact($key, function (?array $tokens) use ($digest, $now, $singleUse) {
            $this->validateState($tokens);
            $tokens = $tokens ?? [];
            $valid = false;
            foreach ($tokens as $stored => $expires) {
                if ($expires <= $now) {
                    unset($tokens[$stored]);
                } elseif (hash_equals($stored, $digest)) {
                    $valid = true;
                    if ($singleUse) {
                        unset($tokens[$stored]);
                    }
                }
            }
            return new Change($tokens ?: null, $tokens ? max($tokens) : 0, $valid);
        });
    }

    public function revoke(string $scope, string $binding): void
    {
        $this->store->transact(Guard::key('csrf', $scope, $binding), function () {
            return new Change(null, 0, null);
        });
    }

    private function validateState(?array $state): void
    {
        if ($state === null) {
            return;
        }
        if (count($state) > 64) {
            throw new StorageException('Corrupt CSRF state.', 'storage.corrupt');
        }
        foreach ($state as $digest => $expires) {
            if (!is_string($digest) || !preg_match('/^[a-f0-9]{64}$/D', $digest)
                || !is_int($expires) || $expires <= 0) {
                throw new StorageException('Corrupt CSRF state.', 'storage.corrupt');
            }
        }
    }
}
