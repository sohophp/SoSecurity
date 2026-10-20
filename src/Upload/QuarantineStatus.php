<?php
declare(strict_types=1);
namespace SoSecurity\Upload;

use SoSecurity\Exception\ConfigurationException;

/** Descriptive metadata, never a file access capability. Recheck Quarantine before reading bytes. */
final class QuarantineStatus
{
    private $values;
    public function __construct(array $values)
    {
        $fields = ['id', 'state', 'attempts', 'generation', 'retry_at', 'expires_at', 'error'];
        if (count($values) !== count($fields) || array_diff(array_keys($values), $fields)
            || !is_string($values['id']) || !preg_match('/\A[a-f0-9]{32}\z/D', $values['id'])
            || !in_array($values['state'], ['staging', 'pending', 'scanning', 'retry', 'available', 'rejected', 'failed', 'deleting', 'expired'], true)
            || !is_int($values['attempts']) || $values['attempts'] < 0 || $values['attempts'] > 10
            || !is_int($values['generation']) || $values['generation'] < 1
            || !is_int($values['retry_at']) || $values['retry_at'] < 0
            || !is_int($values['expires_at']) || $values['expires_at'] < 0
            || !in_array($values['error'], [null, 'scan.failed', 'scan.timeout', 'content.invalid', 'attempts.exhausted', 'admin.rejected'], true)) {
            throw new ConfigurationException('Invalid quarantine status.', 'configuration.quarantine');
        }
        // Reconstruct scalars so caller-owned array references cannot change this view.
        $this->values = [];
        foreach ($fields as $field) { $this->values[$field] = $values[$field]; }
    }
    public function id(): string { return $this->values['id']; }
    public function state(): string { return $this->values['state']; }
    public function attempts(): int { return $this->values['attempts']; }
    public function generation(): int { return $this->values['generation']; }
    public function retryAt(): int { return $this->values['retry_at']; }
    public function expiresAt(): int { return $this->values['expires_at']; }
    public function error(): ?string { return $this->values['error']; }
    public function metadata(): array { return $this->values; }
    public function __sleep(): array { throw new ConfigurationException('Reload current quarantine status.', 'configuration.upload_serialization'); }
    public function __wakeup(): void { throw new ConfigurationException('Reload current quarantine status.', 'configuration.upload_serialization'); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Quarantine status is immutable.', 'configuration.immutable'); }
}
