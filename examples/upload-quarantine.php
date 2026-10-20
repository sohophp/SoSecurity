<?php
declare(strict_types=1);

// Load the host's Composer autoloader first. Importing this file performs no initialization.
return static function (
    \SoSecurity\Storage\AtomicStore $state,
    \SoSecurity\Upload\Scanner $scanner,
    string $privateSpool,
    string $documentRoot,
    string $serverScope
): \SoSecurity\Upload\Quarantine {
    return new \SoSecurity\Upload\Quarantine($state,
        new \SoSecurity\Upload\Policy(['extensions' => ['jpg', 'jpeg', 'png'], 'maximum_bytes' => 5242880]),
        $scanner, $privateSpool, $documentRoot, $serverScope,
        ['maximum_entries' => 64, 'maximum_total_bytes' => 67108864, 'maximum_attempts' => 3,
            'lease_seconds' => 60, 'scan_milliseconds' => 30000, 'retry_seconds' => 60, 'lifetime_seconds' => 86400]);
};

// Authorized upload POST, after authentication/object permission/CSRF/quotas:
// $pending = $queue->enqueueUpload($_FILES['file']); persist $pending->id() in the host's resource record.
// Bounded trusted worker invocation: $status = $queue->process(); null means no due job.
// Authorized read: $snapshot = $queue->readAvailable($hostResource->quarantineId());
// Privileged POST: $queue->rescan($id) or $queue->reject($id); no manual "mark clean" operation.
// Maintenance: $queue->remove($id) for staging, rejected, failed, deleting or expired entries.
