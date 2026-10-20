<?php
declare(strict_types=1);

namespace SoSecurity\Audit;

use SoSecurity\Outbox\Message;
use SoSecurity\Outbox\SqlOutbox;
use SoSecurity\Support\Guard;

/** Persists observed fixed-category alerts; host owns the SQL transaction and delivery worker. */
final class AlertOutboxPublisher
{
    private const PRODUCER = 'security-audit';
    private $metrics;
    private $queue;
    private $scope;
    private $actor;

    public function __construct(MetricsSink $metrics, SqlOutbox $queue, string $scope, string $actor)
    {
        Guard::label($scope);
        Guard::label($actor);
        $this->metrics = $metrics;
        $this->queue = $queue;
        $this->scope = $scope;
        $this->actor = $actor;
    }

    public static function producer(): string { return self::PRODUCER; }

    /** Call inside a host-owned SQL transaction; repeated polling uses the same immutable IDs. */
    public function publish(): array
    {
        $binding = $this->metrics->siteBinding();
        $statuses = [];
        foreach ($this->metrics->inspectRetained() as $snapshot) {
            foreach ($snapshot['alerts'] as $class) {
                $start = $snapshot['window_start'];
                $identity = 'audit-alert:' . $binding . ':' . $class . ':' . $start;
                $body = json_encode(['v' => 1, 'site_binding' => $binding, 'class' => $class,
                    'window_start' => $start, 'expires_at' => $snapshot['expires_at']], JSON_UNESCAPED_SLASHES);
                $message = new Message($this->scope, self::PRODUCER,
                    Message::identifier($identity, $start), 'security-alert', 'audit.threshold',
                    $class . ':' . $start, $body);
                $statuses[] = $this->queue->enqueue($message, $this->actor);
            }
        }
        return $statuses;
    }

    public function __debugInfo(): array { return ['alert_outbox_publisher' => '[redacted]']; }
    public function __sleep(): array
    {
        throw new \SoSecurity\Exception\ConfigurationException('Rebuild alert publisher from trusted configuration.', 'configuration.audit_serialization');
    }
    public function __wakeup(): void
    {
        throw new \SoSecurity\Exception\ConfigurationException('Rebuild alert publisher from trusted configuration.', 'configuration.audit_serialization');
    }
    public function __set(string $name, $value): void
    {
        throw new \SoSecurity\Exception\ConfigurationException('Alert publisher configuration is immutable.', 'configuration.immutable');
    }
}
