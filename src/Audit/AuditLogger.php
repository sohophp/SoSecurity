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
        $this->sink = $sink;
        $this->key = $pseudonymKey;
    }

    public function record(string $event, string $scope, ?string $subject = null, array $context = []): void
    {
        if (!preg_match('/^[a-z][a-z0-9_.]{0,63}$/D', $event)) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid event code.');
        }
        Guard::label($scope);
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
        ($this->sink)(['time' => time(), 'event' => $event, 'scope' => $scope,
            'subject' => $subject === null ? null : hash_hmac('sha256', $subject, $this->key), 'context' => $safe]);
    }
}
