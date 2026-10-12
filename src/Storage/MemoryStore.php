<?php
declare(strict_types=1);

namespace SoSecurity\Storage;

use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;

/** Tests and single-process demonstrations only. Never production request limiting. */
final class MemoryStore implements AtomicStore
{
    private $states = [];
    private $clock;

    public function __construct(?Clock $clock = null)
    {
        $this->clock = $clock ?? new SystemClock();
    }

    public function transact(string $key, callable $callback)
    {
        $value = isset($this->states[$key]) ? Codec::decode($this->states[$key], $this->clock->now()) : null;
        $change = $callback($value);
        if (!$change instanceof Change) {
            throw new StorageException('Callback must return Change.');
        }
        if ($change->value() === null) {
            unset($this->states[$key]);
        } else {
            $this->states[$key] = Codec::encode($change);
        }
        return $change->result();
    }
}
