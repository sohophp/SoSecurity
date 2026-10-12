<?php
declare(strict_types=1);
namespace SoSecurity\Storage;

final class PruneResult
{
    private $removed;
    private $scanned;
    private $complete;
    public function __construct(int $removed, int $scanned, bool $complete)
    {
        $this->removed = $removed; $this->scanned = $scanned; $this->complete = $complete;
    }
    public function removed(): int { return $this->removed; }
    public function scanned(): int { return $this->scanned; }
    public function complete(): bool { return $this->complete; }
}
