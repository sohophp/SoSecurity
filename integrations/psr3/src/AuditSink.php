<?php
declare(strict_types=1);

namespace SoSecurity\Psr3;

use Psr\Log\LogLevel;
use Psr\Log\LoggerInterface;
use SoSecurity\Exception\ConfigurationException;

/** Maps a validated structured audit record to a fixed PSR-3 message. */
final class AuditSink
{
    private $write;

    public function __construct(LoggerInterface $logger, string $level = LogLevel::NOTICE)
    {
        if (!in_array($level, [
            LogLevel::EMERGENCY, LogLevel::ALERT, LogLevel::CRITICAL, LogLevel::ERROR,
            LogLevel::WARNING, LogLevel::NOTICE, LogLevel::INFO, LogLevel::DEBUG
        ], true)) {
            throw new ConfigurationException('Invalid audit log level.', 'configuration.audit_log_level');
        }
        $this->write = static function (array $record) use ($logger, $level): void {
            $logger->log($level, 'security.audit', $record);
        };
    }

    public function __invoke(array $record): void
    {
        if (array_keys($record) !== ['time', 'event', 'scope', 'subject', 'context']
            || !is_int($record['time']) || $record['time'] < 0
            || !is_string($record['event']) || !preg_match('/\A[a-z][a-z0-9_.]{0,63}\z/D', $record['event'])
            || !is_string($record['scope']) || $record['scope'] === '' || strlen($record['scope']) > 256
            || preg_match('/[\x00-\x1f\x7f]/', $record['scope'])
            || ($record['subject'] !== null && (!is_string($record['subject']) || !preg_match('/\A[a-f0-9]{64}\z/D', $record['subject'])))
            || !is_array($record['context']) || count($record['context']) > 3) {
            throw new ConfigurationException('Invalid PSR-3 audit record.', 'configuration.audit_record');
        }
        foreach ($record['context'] as $name => $value) {
            if (($name === 'allowed' && !is_bool($value))
                || ($name === 'retry_after' && (!is_int($value) || $value < 0))
                || ($name === 'status' && (!is_int($value) || $value < 0))
                || !in_array($name, ['allowed', 'retry_after', 'status'], true)) {
                throw new ConfigurationException('Invalid PSR-3 audit context.', 'configuration.audit_record');
            }
        }
        ($this->write)($record);
    }

    public function __debugInfo(): array { return ['audit_sink' => '[redacted]']; }
    public function __sleep(): array
    {
        throw new ConfigurationException('Rebuild PSR-3 audit sinks from trusted configuration.', 'configuration.audit_serialization');
    }
}
