<?php
declare(strict_types=1);

namespace SoSecurity\Audit;

use SoSecurity\Outbox\Message;
use SoSecurity\Outbox\SqlOutbox;
use SoSecurity\Support\Guard;
use SoSecurity\Support\Deadline;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;

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
                $statuses[] = $this->queue->enqueue($this->message($binding, $snapshot, $class), $this->actor);
            }
        }
        return $statuses;
    }

    /** Host-owned transaction: roll back on any failure, including final archive authorization. */
    public function publishArchived(WindowArchive $archive, int $windowStart, int $timeoutMilliseconds = 1000): array
    {
        $budget = new Deadline($timeoutMilliseconds);
        if (!$archive->matches($this->metrics)) {
            throw new ConfigurationException('Use the exact metrics source for archived alerts.', 'configuration.audit_archive');
        }
        $snapshot = $archive->window($windowStart, $budget);
        $binding = $this->metrics->siteBinding();
        $statuses = [];
        foreach ($snapshot['alerts'] as $class) {
            // Every opaque enqueue may change current archive permission or the stored source.
            if ($archive->window($windowStart, $budget) !== $snapshot) {
                throw new StorageException('Archived audit window changed during publication.', 'audit.window_changed');
            }
            $statuses[] = $this->queue->enqueue($this->message($binding, $snapshot, $class), $this->actor);
            $budget->check('audit.window_timeout');
        }
        if ($archive->window($windowStart, $budget) !== $snapshot) {
            throw new StorageException('Archived audit window changed during publication.', 'audit.window_changed');
        }
        $budget->check('audit.window_timeout');
        return $statuses;
    }

    private function message(string $binding, array $snapshot, string $class): Message
    {
        $start = $snapshot['window_start'];
        $identity = 'audit-alert:' . $binding . ':' . $class . ':' . $start;
        $body = json_encode(['v' => 1, 'site_binding' => $binding, 'class' => $class,
            'window_start' => $start, 'expires_at' => $snapshot['expires_at']], JSON_UNESCAPED_SLASHES);
        return new Message($this->scope, self::PRODUCER,
            Message::identifier($identity, $start), 'security-alert', 'audit.threshold',
            $class . ':' . $start, $body);
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
