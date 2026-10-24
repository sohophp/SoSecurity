<?php
declare(strict_types=1);

namespace SoSecurity\Audit;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\RateLimit\BudgetDecision;
use SoSecurity\RateLimit\BudgetLimiter;
use SoSecurity\RateLimit\BudgetPolicy;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\NamespacedStore;
use SoSecurity\Storage\SessionStore;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;

/** Explicit shared, per-site audit event cap. Exhaustion fails closed; it never silently drops events. */
final class BudgetedSink
{
    private $admit;
    private $inspect;
    private $sink;

    public function __construct(AtomicStore $store, string $site, int $maximumEvents, int $windowSeconds, callable $sink, ?Clock $clock = null)
    {
        Guard::label($site);
        $base = $store;
        while ($base instanceof NamespacedStore) { $base = $base->underlying(); }
        if ($base instanceof MemoryStore || $base instanceof SessionStore || $maximumEvents < 1 || $maximumEvents > 100000
            || $windowSeconds < 1 || $windowSeconds > 86400) {
            throw new ConfigurationException('Use shared atomic storage and a bounded audit event policy.', 'configuration.audit_budget');
        }
        $budget = new BudgetLimiter($store, new BudgetPolicy('fixed_window', $maximumEvents, $windowSeconds), $clock);
        $this->admit = static function () use ($budget, $site): bool {
            return $budget->consume('audit-events', $site)->allowed();
        };
        $this->inspect = static function () use ($budget, $site): BudgetDecision {
            return $budget->inspect('audit-events', $site);
        };
        $this->sink = static function (array $record) use ($sink): void { $sink($record); };
    }

    /** Current shared capacity decision for a trusted operator; no audit event is consumed. */
    public function inspect(): BudgetDecision
    {
        if (!$this->inspect instanceof \Closure) {
            throw new ConfigurationException('Rebuild audit budget adapters from trusted configuration.', 'configuration.audit_serialization');
        }
        return ($this->inspect)();
    }

    public function __invoke(array $record): void
    {
        if (count($record) !== 5 || array_keys($record) !== ['time', 'event', 'scope', 'subject', 'context']
            || !is_int($record['time']) || $record['time'] < 0
            || !is_string($record['event']) || !preg_match('/\A[a-z][a-z0-9_.]{0,63}\z/D', $record['event'])
            || !is_string($record['scope']) || $record['scope'] === '' || strlen($record['scope']) > 256
            || preg_match('/[\x00-\x1f\x7f]/', $record['scope'])
            || ($record['subject'] !== null && (!is_string($record['subject']) || !preg_match('/\A[a-f0-9]{64}\z/D', $record['subject'])))
            || !is_array($record['context']) || count($record['context']) > 3) {
            throw new ConfigurationException('Invalid bounded audit record.', 'configuration.audit_record');
        }
        foreach ($record['context'] as $name => $value) {
            if (($name === 'allowed' && !is_bool($value))
                || ($name === 'retry_after' && (!is_int($value) || $value < 0))
                || ($name === 'status' && (!is_int($value) || $value < 0))
                || !in_array($name, ['allowed', 'retry_after', 'status'], true)) {
                throw new ConfigurationException('Invalid bounded audit context.', 'configuration.audit_record');
            }
        }
        if (!($this->admit)()) { throw new SecurityException('Audit event budget exhausted.', 'audit.capacity'); }
        ($this->sink)($record);
    }

    public function __debugInfo(): array { return ['audit_budget' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Rebuild audit budget adapters from trusted configuration.', 'configuration.audit_serialization'); }
}
