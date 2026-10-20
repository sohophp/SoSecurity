<?php
declare(strict_types=1);

namespace SoSecurity\Audit;

use SoSecurity\Support\Guard;

/** Allow-listed structured fields: no arbitrary payload, headers, credentials or exception text. */
final class AuditLogger
{
    private $sink;
    private $key;

    public function __construct(callable $sink, string $pseudonymKey)
    {
        if (strlen($pseudonymKey) < 32) {
            throw new \SoSecurity\Exception\ConfigurationException('Use an independent audit pseudonym key of at least 32 bytes.');
        }
        $this->sink = static function(array $record)use($sink):void{$sink($record);};
        $this->key = static function()use($pseudonymKey):string{return $pseudonymKey;};
    }

    public function record(string $event, string $scope, ?string $subject = null, array $context = []): void
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
        if(!$this->sink instanceof \Closure){throw new \SoSecurity\Exception\ConfigurationException('Rebuild audit callbacks from trusted configuration.','configuration.audit_serialization');}
        ($this->sink)(['time' => time(), 'event' => $event, 'scope' => $scope,
            'subject' => $subject === null ? null : hash_hmac('sha256', $subject, $this->pseudonymKey()), 'context' => $safe]);
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
