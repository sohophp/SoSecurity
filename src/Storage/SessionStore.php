<?php
declare(strict_types=1);

namespace SoSecurity\Storage;

use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

/** Host must hold the native session lock throughout each operation. Not global rate limiting. */
final class SessionStore implements AtomicStore
{
    private $namespace;
    private $clock;

    public function __construct(string $namespace, ?Clock $clock = null)
    {
        if (!extension_loaded('session')) {
            throw new StorageException('Native SessionStore requires ext-session.');
        }
        $this->namespace = '_sosecurity_' . Guard::label($namespace);
        $this->clock = $clock ?? new SystemClock();
    }

    public function transact(string $key, callable $callback)
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new StorageException('The host must start and hold a locked session.');
        }
        Guard::label($key);
        $key = hash('sha256', $key);
        $bucket = $_SESSION[$this->namespace] ?? [];
        if (!is_array($bucket)) {
            throw new StorageException('Corrupt session security state.');
        }
        // Bound expired-state growth without touching unrelated host session data.
        foreach ($bucket as $id => $raw) {
            if (!is_string($raw)) {
                throw new StorageException('Corrupt session security state.');
            }
            if (Codec::decode($raw, $this->clock->now()) === null) {
                unset($bucket[$id]);
            }
        }
        $value = isset($bucket[$key]) ? Codec::decode($bucket[$key], $this->clock->now()) : null;
        $change = $callback($value);
        if (!$change instanceof Change) {
            throw new StorageException('Callback must return Change.');
        }
        if ($change->value === null) {
            unset($bucket[$key]);
        } else {
            if (!isset($bucket[$key]) && count($bucket) >= 128) {
                throw new StorageException('Session security state capacity exceeded.');
            }
            $bucket[$key] = Codec::encode($change);
        }
        $_SESSION[$this->namespace] = $bucket;
        return $change->result;
    }
}
