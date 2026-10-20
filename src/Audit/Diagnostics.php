<?php
declare(strict_types=1);

namespace SoSecurity\Audit;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;

/** Fixed-shape operator snapshot; the host must authorize every read. */
final class Diagnostics
{
    private $metrics;
    private $budget;
    private $authorize;

    public function __construct(MetricsSink $metrics, BudgetedSink $budget, callable $authorize)
    {
        $this->metrics = $metrics;
        $this->budget = $budget;
        $this->authorize = static function () use ($authorize): bool { return $authorize() === true; };
    }

    public function inspect(): array
    {
        try { $authorized = ($this->authorize)(); }
        catch (\Throwable $error) { $authorized = false; }
        if (!$authorized) {
            throw new SecurityException('Audit diagnostics access denied.', 'audit.diagnostics_forbidden');
        }
        $metrics = $this->metrics->inspect();
        $budget = $this->budget->inspect();
        return ['window_start' => $metrics['window_start'], 'expires_at' => $metrics['expires_at'],
            'counts' => $metrics['counts'], 'total' => $metrics['total'], 'alerts' => $metrics['alerts'],
            'budget' => ['allowed' => $budget->allowed(), 'remaining' => $budget->remaining(),
                'retry_after' => $budget->retryAfter()]];
    }

    public function __debugInfo(): array { return ['audit_diagnostics' => '[redacted]']; }
    public function __sleep(): array
    {
        throw new ConfigurationException('Rebuild audit diagnostics from trusted configuration.', 'configuration.audit_serialization');
    }
    public function __wakeup(): void
    {
        throw new ConfigurationException('Rebuild audit diagnostics from trusted configuration.', 'configuration.audit_serialization');
    }
    public function __set(string $name, $value): void
    {
        throw new ConfigurationException('Audit diagnostics configuration is immutable.', 'configuration.immutable');
    }
}
