<?php
declare(strict_types=1);

namespace SoSecurity\Oidc;

use SoSecurity\Auth\Account;
use SoSecurity\Auth\IdentityProvider;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** One external issuer/subject maps to at most one current local account. No email auto-linking. */
final class LinkRegistry
{
    private $store;
    private $identities;
    private $sessions;
    private $guard;
    private $clock;
    private $logoutFence;

    public function __construct(AtomicStore $store, IdentityProvider $identities, SessionRegistry $sessions,
        callable $requestGuard, ?Clock $clock = null, ?LogoutFence $logoutFence = null)
    {
        $this->store = $store; $this->identities = $identities; $this->sessions = $sessions;
        $this->guard = $requestGuard; $this->clock = $clock ?? new SystemClock(); $this->logoutFence = $logoutFence;
    }

    /** Requires both a verified OIDC subject and recent, non-restored local authentication. */
    public function link(string $scope, string $subject, $localSessionToken, VerifiedSubject $remote): bool
    {
        $this->guard('federation_link', $scope);
        if ($this->logoutFence !== null && !$this->logoutFence->allows($scope, $remote)) {
            throw new SecurityException('External identity predates provider logout.', 'federation.logged_out');
        }
        $account = $this->current($scope, $subject);
        $verified = $this->sessions->verify($scope, $subject, $localSessionToken);
        $now = $this->clock->now();
        if ($account === null || $verified === null || !$verified->recent(300, $now, $account->mfaRequired() ? 2 : 1)
            || !hash_equals($account->fingerprint(), $verified->account()->fingerprint())) {
            throw new SecurityException('Recent local authentication is required for federation linking.', 'federation.local_proof');
        }
        $row = ['v' => 2, 'scope' => $scope, 'subject' => $subject, 'fingerprint' => $account->fingerprint(),
            'issuer' => $remote->issuer(), 'remote' => $remote->subject(), 'created' => $now,
            'binding' => bin2hex(random_bytes(16))];
        return $this->store->transact($this->key($scope, $remote), function ($old) use ($row) {
            $old = $this->read($old);
            if ($old !== null) {
                $existingBinding = $old;
                $proposedBinding = $row;
                unset($existingBinding['created'], $existingBinding['binding'], $existingBinding['v'],
                    $proposedBinding['created'], $proposedBinding['binding'], $proposedBinding['v']);
                if ($existingBinding !== $proposedBinding) {
                    throw new SecurityException('External identity is already linked.', 'federation.link_conflict');
                }
            }
            return new Change($old === null ? $row : $old, 0, true);
        });
    }

    /** A verified external subject never becomes authority unless its exact local binding is still current. */
    public function resolve(string $scope, VerifiedSubject $remote): ?Account
    {
        $this->guard('federation_resolve', $scope);
        if ($this->logoutFence !== null && !$this->logoutFence->allows($scope, $remote)) { return null; }
        $row = $this->store->transact($this->key($scope, $remote), function ($old) {
            return new Change($old, 0, $this->read($old));
        });
        if ($row === null || $row['scope'] !== $scope || $row['issuer'] !== $remote->issuer()
            || $row['remote'] !== $remote->subject()) { return null; }
        $account = $this->current($scope, $row['subject']);
        if ($account === null || !hash_equals($row['fingerprint'], $account->fingerprint())) { return null; }
        return $this->logoutFence === null || $this->logoutFence->allows($scope, $remote) ? $account : null;
    }

    /** Metadata check for an already authenticated federated session; never use this as login proof. */
    public function matchesCurrentLink(string $scope, string $issuer, string $remote, Account $account): bool
    {
        Guard::label($scope);
        if ($account->scope() !== $scope || !$account->enabled() || $issuer === '' || strlen($issuer) > 2048
            || $remote === '' || strlen($remote) > 255) { return false; }
        $row = $this->store->transact($this->pairKey($scope, $issuer, $remote), function ($old) {
            return new Change($old, 0, $this->read($old));
        });
        if ($row === null || $row['scope'] !== $scope || $row['issuer'] !== $issuer || $row['remote'] !== $remote
            || $row['subject'] !== $account->subject() || !hash_equals($row['fingerprint'], $account->fingerprint())) {
            return false;
        }
        $current = $this->current($scope, $account->subject());
        return $current !== null && hash_equals($current->fingerprint(), $account->fingerprint());
    }

    /** Exact unlink still requires fresh local proof; recovery without the provider needs separate strong approval. */
    public function unlink(string $scope, string $subject, $localSessionToken, VerifiedSubject $remote): bool
    {
        $this->guard('federation_unlink', $scope);
        $account = $this->current($scope, $subject);
        $verified = $this->sessions->verify($scope, $subject, $localSessionToken);
        $now = $this->clock->now();
        if ($account === null || $verified === null || !$verified->recent(300, $now, $account->mfaRequired() ? 2 : 1)
            || !hash_equals($account->fingerprint(), $verified->account()->fingerprint())) {
            throw new SecurityException('Recent local authentication is required for federation unlinking.', 'federation.local_proof');
        }
        return $this->store->transact($this->key($scope, $remote), function ($old) use ($scope, $subject, $account, $remote) {
            $row = $this->read($old);
            if ($row === null) { return new Change(null, 0, false); }
            if ($row['scope'] !== $scope || $row['subject'] !== $subject || $row['issuer'] !== $remote->issuer()
                || $row['remote'] !== $remote->subject() || !hash_equals($row['fingerprint'], $account->fingerprint())) {
                throw new SecurityException('External identity belongs to another local account or version.', 'federation.link_conflict');
            }
            return new Change(null, 0, true);
        });
    }

    /** Provider-outage unlink: the host must independently approve and audit this exact old binding. */
    public function recoverUnlink(string $scope, string $subject, $localSessionToken, string $issuer,
        string $remoteSubject, callable $approveRecovery): bool
    {
        $this->guard('federation_recovery_unlink', $scope);
        Guard::label($subject);
        if (strlen($issuer) > 2048 || preg_match('/\Ahttps:\/\/[^\x00-\x20\x7f]+\z/D', $issuer) !== 1
            || strlen($remoteSubject) > 255 || preg_match('/\A[\x21-\x7e]+\z/D', $remoteSubject) !== 1) {
            throw new SecurityException('Invalid external identity target.', 'federation.recovery_target');
        }
        $account = $this->localProof($scope, $subject, $localSessionToken);
        $key = $this->pairKey($scope, $issuer, $remoteSubject);
        $original = $this->store->transact($key, function ($old) {
            return new Change($old, 0, $this->read($old));
        });
        if ($original === null) { return false; }
        if ($original['scope'] !== $scope || $original['subject'] !== $subject
            || $original['issuer'] !== $issuer || $original['remote'] !== $remoteSubject) {
            throw new SecurityException('External identity belongs to another local account.', 'federation.link_conflict');
        }
        // Approval is deliberately outside AtomicStore::transact(), whose callback may be retried.
        if ($approveRecovery($scope, $subject, $issuer, $remoteSubject,
            ['linked_at' => $original['created'], 'linked_fingerprint' => $original['fingerprint'],
                'current_fingerprint' => $account->fingerprint(),
                'binding_id' => $original['binding'] ?? null]) !== true) {
            throw new SecurityException('Independent federation recovery approval is required.', 'federation.recovery_denied');
        }
        $current = $this->localProof($scope, $subject, $localSessionToken);
        if (!hash_equals($account->fingerprint(), $current->fingerprint())) {
            throw new SecurityException('Local identity changed during federation recovery.', 'federation.local_proof');
        }
        return $this->store->transact($key, function ($old) use ($original) {
            $row = $this->read($old);
            if ($row !== $original) {
                throw new SecurityException('Federation binding changed during recovery.', 'federation.link_conflict');
            }
            return new Change(null, 0, true);
        });
    }

    private function localProof(string $scope, string $subject, $token): Account
    {
        $account = $this->current($scope, $subject);
        $verified = $this->sessions->verify($scope, $subject, $token);
        $now = $this->clock->now();
        if ($account === null || $verified === null || !$verified->recent(300, $now, $account->mfaRequired() ? 2 : 1)
            || !hash_equals($account->fingerprint(), $verified->account()->fingerprint())) {
            throw new SecurityException('Recent local authentication is required for federation recovery.', 'federation.local_proof');
        }
        return $account;
    }

    private function current(string $scope, string $subject): ?Account
    {
        Guard::label($scope); Guard::label($subject);
        $account = $this->identities->find($scope, $subject);
        if ($account === null) { return null; }
        if (!$account instanceof Account || !$account->enabled() || $account->scope() !== $scope || $account->subject() !== $subject) {
            throw new SecurityException('Invalid current local identity.', 'federation.local_identity');
        }
        return $account;
    }

    private function guard(string $phase, string $scope): void
    {
        Guard::label($scope);
        if (($this->guard)($phase, $scope) !== true) {
            throw new SecurityException('Federation request protection was not confirmed.', 'federation.request_denied');
        }
    }

    private function key(string $scope, VerifiedSubject $remote): string
    {
        return $this->pairKey($scope, $remote->issuer(), $remote->subject());
    }

    private function pairKey(string $scope, string $issuer, string $remote): string
    {
        return Guard::key('federation-link', $scope, hash('sha256', strlen($scope) . ':' . $scope
            . strlen($issuer) . ':' . $issuer . strlen($remote) . ':' . $remote));
    }

    private function read($value): ?array
    {
        if ($value === null) { return null; }
        if (!is_array($value)) { throw new StorageException('Corrupt federation link.', 'storage.corrupt'); }
        $keys = array_keys($value); sort($keys);
        $legacy = $value['v'] ?? null;
        if (($legacy === 1 && $keys !== ['created', 'fingerprint', 'issuer', 'remote', 'scope', 'subject', 'v'])
            || ($legacy === 2 && $keys !== ['binding', 'created', 'fingerprint', 'issuer', 'remote', 'scope', 'subject', 'v'])
            || !in_array($legacy, [1, 2], true)
            || ($legacy === 2 && (!is_string($value['binding']) || preg_match('/\A[a-f0-9]{32}\z/D', $value['binding']) !== 1))
            || !is_int($value['created']) || $value['created'] < 0
            || !is_string($value['fingerprint']) || preg_match('/\A[a-f0-9]{64}\z/D', $value['fingerprint']) !== 1
            || !is_string($value['scope']) || !is_string($value['subject'])
            || !is_string($value['issuer']) || !is_string($value['remote'])
            || strlen($value['issuer']) > 2048 || strlen($value['remote']) > 255) {
            throw new StorageException('Corrupt federation link.', 'storage.corrupt');
        }
        Guard::label($value['scope']); Guard::label($value['subject']);
        return $value;
    }
}
