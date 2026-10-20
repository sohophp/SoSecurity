<?php
declare(strict_types=1);

namespace SoSecurity\Audit;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Outbox\Claim;
use SoSecurity\Outbox\Message;
use SoSecurity\Outbox\SqlOutbox;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;

/** Claims one authenticated alert, calls a host-supplied idempotent transport, then settles its lease. */
final class AlertOutboxWorker
{
    private const CLASSES = ['authentication', 'authorization', 'abuse', 'availability'];
    private $queue;
    private $scope;
    private $worker;
    private $siteBinding;
    private $deliver;

    public function __construct(MetricsSink $metrics, SqlOutbox $queue, string $scope, string $worker, callable $deliver)
    {
        Guard::label($scope);
        Guard::label($worker);
        $this->queue = $queue;
        $this->scope = $scope;
        $this->worker = $worker;
        $this->siteBinding = $metrics->siteBinding();
        $this->deliver = static function (string $id, array $alert) use ($deliver) { return $deliver($id, $alert); };
    }

    /** Returns false only when no alert was claimable in this bounded page. Failure always throws. */
    public function runOne(int $afterOrder = 0): bool
    {
        $producer = AlertOutboxPublisher::producer();
        $claim = $this->queue->claim($this->scope, $producer, $this->worker, $afterOrder);
        if ($claim === null) { return false; }
        $fresh = $this->queue->currentClaim($this->scope, $producer, $this->worker, $claim->token());
        if ($fresh === null || $fresh->message()->fingerprint() !== $claim->message()->fingerprint()) {
            throw new StorageException('Current alert delivery lease is unavailable.', 'audit.alert_lease');
        }
        try { $alert = $this->alert($fresh); }
        catch (StorageException $error) {
            $this->settleFailure($claim, 'audit.alert_message', false);
            throw $error;
        }
        try { $accepted = ($this->deliver)($fresh->status()->deliveryId(), $alert); }
        catch (\Throwable $error) {
            $this->settleFailure($claim, 'audit.alert_delivery', true);
            throw new DependencyException('Alert transport did not confirm durable acceptance.', 'audit.alert_delivery', $error);
        }
        if ($accepted !== true) {
            $this->settleFailure($claim, 'audit.alert_delivery', true);
            throw new DependencyException('Alert transport did not confirm durable acceptance.', 'audit.alert_delivery');
        }
        if (!$this->queue->acknowledge($this->scope, $producer, $this->worker, $claim->token())) {
            throw new StorageException('Alert acknowledgement result is unknown.', 'audit.alert_ack_unknown');
        }
        return true;
    }

    private function settleFailure(Claim $claim, string $code, bool $retryable): void
    {
        if (!$this->queue->fail($this->scope, AlertOutboxPublisher::producer(), $this->worker,
            $claim->token(), $code, $retryable)) {
            throw new StorageException('Alert failure settlement is unknown.', 'audit.alert_settlement');
        }
    }

    private function alert(Claim $claim): array
    {
        $message = $claim->message();
        $body = $message->body();
        if ($message->scope() !== $this->scope || $message->producer() !== AlertOutboxPublisher::producer()
            || $message->destination() !== 'security-alert' || $message->topic() !== 'audit.threshold'
            || strlen($body) > 512) { $this->invalid(); }
        $alert = json_decode($body, true);
        if (!is_array($alert) || array_keys($alert) !== ['v', 'site_binding', 'class', 'window_start', 'expires_at']
            || $alert['v'] !== 1 || !is_string($alert['site_binding'])
            || !hash_equals($this->siteBinding, $alert['site_binding'])
            || !in_array($alert['class'], self::CLASSES, true)
            || !is_int($alert['window_start']) || $alert['window_start'] < 0
            || $alert['window_start'] > PHP_INT_MAX - 31536001
            || !is_int($alert['expires_at']) || $alert['expires_at'] <= $alert['window_start']
            || $alert['expires_at'] - $alert['window_start'] > 86400
            || json_encode($alert, JSON_UNESCAPED_SLASHES) !== $body
            || $message->createdAt() !== $alert['window_start']
            || $message->aggregate() !== $alert['class'] . ':' . $alert['window_start']
            || $message->id() !== Message::identifier('audit-alert:' . $this->siteBinding . ':'
                . $alert['class'] . ':' . $alert['window_start'], $alert['window_start'])) {
            $this->invalid();
        }
        return $alert;
    }

    private function invalid(): void
    {
        throw new StorageException('Alert message differs from the fixed protocol.', 'audit.alert_message');
    }

    public function __debugInfo(): array { return ['alert_outbox_worker' => '[redacted]']; }
    public function __sleep(): array
    {
        throw new ConfigurationException('Rebuild alert worker from trusted configuration.', 'configuration.audit_serialization');
    }
    public function __wakeup(): void
    {
        throw new ConfigurationException('Rebuild alert worker from trusted configuration.', 'configuration.audit_serialization');
    }
    public function __set(string $name, $value): void
    {
        throw new ConfigurationException('Alert worker configuration is immutable.', 'configuration.immutable');
    }
}
