<?php
declare(strict_types=1);

// Requiring this file performs no IO. The host supplies a trusted, independent audit PDO and key.
// Install resources/sql/audit-{sqlite,mysql}.sql and call sink->initialize() in a private CLI bootstrap.
// Do not initialize schemas or choose connections/site/limits from an HTTP request.
return static function (PDO $auditConnection, string $site, string $pseudonymKey,
    callable $authorizeMaintenance, ?callable $authorizeRead = null): array {
    $sink = new SoSecurity\Audit\SqlSink($auditConnection, $site, 10000, 604800, null, 1000, $authorizeMaintenance, $authorizeRead);
    return ['logger' => new SoSecurity\Audit\AuditLogger($sink, $pseudonymKey), 'sink' => $sink];
};
