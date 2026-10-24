<?php
declare(strict_types=1);

namespace SoSecurity\Audit;

use SoSecurity\Support\Guard;

/** Allow-listed structured fields: no arbitrary payload, headers, credentials or exception text. */
final class AuditLogger
{
    private $sink;
    private $key;
    private $stateContext;
    private $statePrepare;

    public function __construct(callable $sink, string $pseudonymKey)
    {
        if (strlen($pseudonymKey) < 32) {
            throw new \SoSecurity\Exception\ConfigurationException('Use an independent audit pseudonym key of at least 32 bytes.');
        }
        $this->sink = static function(array $record)use($sink):void{$sink($record);};
        $this->stateContext = static function(\PDO $pdo, string $site, \SoSecurity\Support\Clock $clock)use($sink):?array{
            return $sink instanceof SqlSink ? $sink->stateContext($pdo, $site, $clock) : null;
        };
        $this->statePrepare = static function(array $record, int $maximumRows, \SoSecurity\Support\Deadline $deadline)use($sink):\Closure{
            if (!$sink instanceof SqlSink) { throw new \SoSecurity\Exception\ConfigurationException('Use the exact concrete SQL audit sink.', 'configuration.audit_state'); }
            return $sink->prepareState($record, $maximumRows, $deadline);
        };
        $this->key = static function()use($pseudonymKey):string{return $pseudonymKey;};
    }

    public function record(string $event, string $scope, ?string $subject = null, array $context = []): void
    {
        $record = $this->format($event, $scope, $subject, $context);
        if(!$this->sink instanceof \Closure){throw new \SoSecurity\Exception\ConfigurationException('Rebuild audit callbacks from trusted configuration.','configuration.audit_serialization');}
        ($this->sink)($record);
    }

    private function format(string $event, string $scope, ?string $subject, array $context): array
    {
        if (!preg_match('/^[a-z][a-z0-9_.]{0,63}$/D', $event)) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid event code.');
        }
        Guard::label($scope);
        if ($subject !== null && strlen($subject) > 1024) {
            throw new \SoSecurity\Exception\ConfigurationException('Audit subject exceeds 1024 bytes.', 'configuration.audit_subject');
        }
        $safe = [];
        foreach (['allowed', 'retry_after', 'status'] as $field) {
            if (isset($context[$field])) {
                if (($field === 'allowed' && !is_bool($context[$field]))
                    || ($field !== 'allowed' && (!is_int($context[$field]) || $context[$field] < 0))) {
                    throw new \SoSecurity\Exception\ConfigurationException('Invalid audit field: ' . $field);
                }
                $safe[$field] = $context[$field];
            }
        }
        return ['time' => time(), 'event' => $event, 'scope' => $scope,
            'subject' => $subject === null ? null : hash_hmac('sha256', $subject, $this->pseudonymKey()), 'context' => $safe];
    }

    /** Only a directly configured concrete SQL sink can declare a native audit source. */
    public function stateContext(\PDO $pdo, string $site, \SoSecurity\Support\Clock $clock): ?array
    {
        if (!$this->stateContext instanceof \Closure) { return null; }
        $context = ($this->stateContext)($pdo, $site, $clock);
        if ($context === null) { return null; }
        $context['fingerprint'] = hash('sha256', 'SoSecurity.AuditLogger.State.1.' . $context['fingerprint']
            . '.' . hash_hmac('sha256', 'SoSecurity.AuditLogger.PseudonymBinding.1', $this->pseudonymKey()));
        return $context;
    }

    /** Trusted native wiring only: exact source and a single fixed authorization event. */
    public function prepareState(\PDO $pdo, string $site, \SoSecurity\Support\Clock $clock, int $maximumRows,
        \SoSecurity\Support\Deadline $deadline, string $scope, string $subject, bool $allowed): \Closure
    {
        if ($this->stateContext($pdo, $site, $clock) === null || !$this->statePrepare instanceof \Closure) {
            throw new \SoSecurity\Exception\ConfigurationException('Use the declared concrete audit source.', 'configuration.audit_state');
        }
        return ($this->statePrepare)($this->format($allowed ? 'authorization.allowed' : 'authorization.denied', $scope, $subject, ['allowed'=>$allowed]), $maximumRows, $deadline);
    }

    private function pseudonymKey():string
    {
        if(!$this->key instanceof \Closure){throw new \SoSecurity\Exception\ConfigurationException('Rebuild private audit configuration.','configuration.audit_serialization');}
        return ($this->key)();
    }

    public function __debugInfo(): array { return ['audit' => '[redacted]']; }
    public function __sleep(): array
    {
        throw new \SoSecurity\Exception\ConfigurationException('Rebuild audit loggers from trusted configuration.', 'configuration.audit_serialization');
    }
}
