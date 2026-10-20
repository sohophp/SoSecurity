# SoSecurity PSR-3 audit adapter

This optional Composer package connects SoSecurity's structured `AuditLogger` records to a host `Psr\Log\LoggerInterface`. The core package has no PSR-3 dependency.

```php
$sink = new SoSecurity\Psr3\AuditSink($hostLogger, \Psr\Log\LogLevel::WARNING);
$audit = new SoSecurity\Audit\AuditLogger($sink, $independentAuditPseudonymKey);
$audit->record('login.failed', 'login', $serverSideAccountId, ['allowed' => false]);
```

For a shared event cap, pass `$sink` to `SoSecurity\Audit\BudgetedSink` before constructing `AuditLogger`. The adapter emits the fixed message `security.audit` with a bounded, structured context. Invalid records and levels are rejected before the host logger is called; host logger exceptions propagate.

The host must configure a real logger, its persistence and retention, access controls, and independent failure alerting. A successful PSR-3 method call does not prove durable storage; a null or silently dropping logger cannot provide mandatory audit. This adapter does not enroll business operations in a transaction. The package is currently a local candidate, not a published release.
