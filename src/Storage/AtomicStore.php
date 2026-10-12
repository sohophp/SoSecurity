<?php
declare(strict_types=1);

namespace SoSecurity\Storage;

interface AtomicStore
{
    /**
     * Callback receives live state (array|null) and returns Change. Commit before returning result.
     * The entire read/modify/write must be atomic. Callbacks may be retried: no I/O or side effects.
     * Failure MUST throw StorageException; never substitute an empty store.
     */
    public function transact(string $key, callable $callback);
}
