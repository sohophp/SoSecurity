<?php
declare(strict_types=1);
namespace SoSecurity\Examples\Leases;
use PDO;
use SoSecurity\Concurrency\Lease;
use SoSecurity\Concurrency\LeaseManager;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;

/** Host-owned jobs: tenant,id,lease_epoch,fence,lease_digest,lease_until,revision,output.
 * Provision/pin epoch separately; caller authenticates/authorizes and owns SQL begin/commit/rollback.
 * Exclusive (maximum=1) example. No auto schema, transactions, HTTP output, network or job execution on import.
 */
function databaseNow(PDO $pdo): string
{
    if (!$pdo->inTransaction()) { throw new ConfigurationException('Host transaction required.', 'lease.transaction'); }
    $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
    if ($driver === 'sqlite') { return "CAST(strftime('%s','now') AS INTEGER)"; }
    if ($driver === 'mysql') { return 'UNIX_TIMESTAMP()'; }
    throw new ConfigurationException('Example supports explicit SQLite/MySQL database clocks.', 'lease.database');
}
function binding(Lease $lease, string $scope, string $resource): array
{
    \SoSecurity\Support\Guard::key('leased-work', $scope, $resource);
    return ['tenant' => $scope, 'id' => $resource, 'epoch' => $lease->epoch(), 'fence' => $lease->fence(), 'digest' => hash('sha256', $lease->token())];
}
function current(LeaseManager $manager, string $scope, string $resource, string $owner, string $token, bool $renew = false): Lease
{
    if ($manager->policy()->maximum() !== 1) { throw new ConfigurationException('Exclusive business fence requires one holder.', 'lease.exclusive'); }
    $lease = $renew ? $manager->renew($scope, $resource, $owner, $token) : $manager->verify($scope, $resource, $owner, $token);
    if ($lease === null) { throw new SecurityException('Lease no longer held.', 'lease.lost'); }
    return $lease;
}
/** Fresh statement after possible lock/trigger latency; caller rolls back on rejection. Not a COMMIT-time hook. */
function finish(PDO $pdo, Lease $lease, int $started): void
{
    $raw = $pdo->query('SELECT ' . databaseNow($pdo))->fetchColumn(); $now = time();
    if ((!is_int($raw) && !is_string($raw)) || !preg_match('/\A[0-9]{1,19}\z/D', (string) $raw) || (string) (int) $raw !== (string) $raw || (int) $raw < 0 || $now < $started) {
        throw new SecurityException('Database/worker clock is unavailable or moved backwards.', 'lease.clock');
    }
    if ($now >= $lease->expiresAt() || (int) $raw >= $lease->expiresAt()) { throw new SecurityException('Lease expired during business SQL; roll back.', 'lease.expired'); }
}
function claim(PDO $pdo, LeaseManager $manager, string $scope, string $resource, string $owner, string $token): Lease
{
    $started = time(); $now = databaseNow($pdo); $lease = current($manager, $scope, $resource, $owner, $token); $parameters = binding($lease, $scope, $resource);
    $parameters['deadline'] = $lease->expiresAt(); $parameters['new_fence'] = $lease->fence(); $parameters['future_deadline'] = $lease->expiresAt();
    $sql = 'UPDATE jobs SET fence=:new_fence,lease_digest=:digest,lease_until=:deadline WHERE tenant=:tenant AND id=:id AND lease_epoch=:epoch AND fence<:fence AND CAST(:future_deadline AS DECIMAL(20,0))>' . $now;
    $statement = $pdo->prepare($sql); $statement->execute($parameters);
    if ($statement->rowCount() !== 1) { throw new SecurityException('Business fence not acquired.', 'lease.fence_denied'); }
    finish($pdo, $lease, $started);
    return $lease;
}
/** Call with a freshly verified lease for every step. SQL rejects snapshots superseded after that verification. */
function write(PDO $pdo, Lease $lease, string $scope, string $resource, int $expectedRevision, string $output): void
{
    $started = time(); $now = databaseNow($pdo);
    if ($expectedRevision < 1 || $expectedRevision === PHP_INT_MAX || strlen($output) > 65536) { throw new ValidationException('Invalid bounded job update.', 'lease.payload'); }
    $parameters = binding($lease, $scope, $resource) + ['revision' => $expectedRevision, 'output' => $output];
    $statement = $pdo->prepare('UPDATE jobs SET output=:output,revision=revision+1 WHERE tenant=:tenant AND id=:id AND lease_epoch=:epoch AND fence=:fence AND lease_digest=:digest AND revision=:revision AND lease_until>' . $now);
    $statement->execute($parameters);
    if ($statement->rowCount() !== 1) { throw new SecurityException('Business fence, revision or database deadline changed.', 'lease.fence_denied'); }
    finish($pdo, $lease, $started);
}
/** Renew both boundaries; if SQL rejects, do not continue even though the shared lease may already be renewed. */
function renew(PDO $pdo, LeaseManager $manager, string $scope, string $resource, string $owner, string $token): Lease
{
    $started = time(); $now = databaseNow($pdo); $lease = current($manager, $scope, $resource, $owner, $token, true); $parameters = binding($lease, $scope, $resource) + ['deadline' => $lease->expiresAt()];
    $statement = $pdo->prepare('UPDATE jobs SET lease_until=:deadline WHERE tenant=:tenant AND id=:id AND lease_epoch=:epoch AND fence=:fence AND lease_digest=:digest AND lease_until>' . $now);
    $statement->execute($parameters);
    // MySQL may report changed rows rather than matched rows for same-second renewals.
    $check = $pdo->prepare('SELECT lease_until FROM jobs WHERE tenant=:tenant AND id=:id AND lease_epoch=:epoch AND fence=:fence AND lease_digest=:digest AND lease_until>' . $now);
    unset($parameters['deadline']); $check->execute($parameters);
    if ((int) $check->fetchColumn() !== $lease->expiresAt()) { throw new SecurityException('Business fence renewal refused.', 'lease.fence_denied'); }
    finish($pdo, $lease, $started);
    return $lease;
}
/** Retire SQL authority, COMMIT the host transaction, then release the shared lease. SQL rollback preserves the old boundary. */
function retire(PDO $pdo, Lease $lease, string $scope, string $resource): void
{
    databaseNow($pdo); $statement = $pdo->prepare('UPDATE jobs SET lease_until=0 WHERE tenant=:tenant AND id=:id AND lease_epoch=:epoch AND fence=:fence AND lease_digest=:digest');
    $statement->execute(binding($lease, $scope, $resource));
}
