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

/** Rejects an ID Token issued before a durable provider logout. This does not revoke host sessions. */
final class LogoutFence
{
    private $store;
    private $clock;

    public function __construct(AtomicStore $store, ?Clock $clock = null)
    {
        $this->store = $store;
        $this->clock = $clock ?? new SystemClock();
    }

    public function record(string $scope, VerifiedLogout $logout): void
    {
        Guard::label($scope);
        $now = $this->now();
        if ($logout->issuedAt() < max(0, $now - 86400) || $logout->issuedAt() > $now + 60) {
            throw new SecurityException('Logout proof is outside its lifetime.', 'federation.logout_time');
        }
        $subject = $logout->subject();
        $sid = $logout->sessionId();
        if ($subject === null && $sid === null) {
            throw new SecurityException('Logout proof has no target.', 'federation.logout_target');
        }
        $key = $subject !== null && $sid !== null
            ? $this->key($scope, $logout->issuer(), 'pair', $subject, $sid)
            : ($subject !== null ? $this->key($scope, $logout->issuer(), 'sub', $subject)
                : $this->key($scope, $logout->issuer(), 'sid', $sid));
        $issuedAt = $logout->issuedAt();
        $expires = $now + 172800;
        $this->store->transact($key, function ($old) use ($issuedAt, $expires, $now) {
            $row = $this->read($old);
            $newer = $row === null || $issuedAt > $row['iat'];
            $row = ['v' => 2, 'iat' => max($issuedAt, $row === null ? 0 : $row['iat']),
                'recorded' => $newer ? $now : $row['recorded'],
                'expires' => max($expires, $row === null ? 0 : $row['expires'])];
            return new Change($row, $row['expires'], null);
        });
    }

    public function allows(string $scope, VerifiedSubject $subject): bool
    {
        Guard::label($scope);
        $now = $this->now();
        if ($subject->issuedAt() < max(0, $now - 86400) || $subject->issuedAt() > $now + 60) { return false; }
        return $this->allowed($scope, $subject->issuer(), $subject->subject(), $subject->providerSessionId(),
            $subject->issuedAt(), null);
    }

    /** A live federated session also predates a logout if it existed before the notification was recorded. */
    public function allowsSession(string $scope, string $issuer, string $subject, ?string $sid,
        int $issuedAt, int $createdAt): bool
    {
        Guard::label($scope);
        $now = $this->now();
        if ($createdAt < 0 || $createdAt > $now || $issuedAt < 0 || $issuedAt > $now + 60
            || $issuer === '' || strlen($issuer) > 2048 || $subject === '' || strlen($subject) > 255
            || ($sid !== null && ($sid === '' || strlen($sid) > 255))) { return false; }
        return $this->allowed($scope, $issuer, $subject, $sid, $issuedAt, $createdAt);
    }

    private function allowed(string $scope, string $issuer, string $subject, ?string $sid,
        int $issuedAt, ?int $createdAt): bool
    {
        $targets = [$this->key($scope, $issuer, 'sub', $subject)];
        if ($sid !== null) {
            $targets[] = $this->key($scope, $issuer, 'sid', $sid);
            $targets[] = $this->key($scope, $issuer, 'pair', $subject, $sid);
        }
        foreach ($targets as $key) {
            $row = $this->store->transact($key, function ($old) {
                $row = $this->read($old);
                return new Change($row, $row === null ? 0 : $row['expires'], $row);
            });
            if ($row !== null && ($issuedAt <= $row['iat']
                || ($createdAt !== null && $createdAt <= $row['recorded']))) { return false; }
        }
        return true;
    }

    private function key(string $scope, string $issuer, string $kind, string $first, string $second = ''): string
    {
        $value = static function (string $part): string { return strlen($part) . ':' . $part; };
        return Guard::key('oidc-logout-fence-' . $kind, $scope,
            hash('sha256', $value($issuer) . $value($first) . $value($second)));
    }

    private function read($old): ?array
    {
        if ($old === null) { return null; }
        if (!is_array($old)) { throw new StorageException('Corrupt logout fence.', 'storage.corrupt'); }
        $keys = array_keys($old); sort($keys);
        if ($keys !== ['expires', 'iat', 'recorded', 'v'] || $old['v'] !== 2
            || !is_int($old['iat']) || $old['iat'] < 0
            || !is_int($old['recorded']) || $old['recorded'] < 0
            || !is_int($old['expires']) || $old['expires'] <= $old['iat'] || $old['expires'] <= $old['recorded']) {
            throw new StorageException('Corrupt logout fence.', 'storage.corrupt');
        }
        return $old;
    }

    private function now(): int
    {
        $now = $this->clock->now();
        if ($now < 0 || $now > PHP_INT_MAX - 172800) {
            throw new SecurityException('Logout clock out of range.', 'federation.clock');
        }
        return $now;
    }
}
