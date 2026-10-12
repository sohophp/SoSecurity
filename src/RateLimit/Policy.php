<?php
declare(strict_types=1);

namespace SoSecurity\RateLimit;

use SoSecurity\Support\Guard;

final class Policy
{
    public $limit;
    public $window;
    public $bans;
    public $historyTtl;

    public function __construct(int $limit = 5, int $window = 300, array $bans = [60, 300, 900], int $historyTtl = 86400)
    {
        if ($limit < 1 || $limit > 1000000 || !$bans || count($bans) > 16) {
            throw new \InvalidArgumentException('Invalid request limit or ban ladder.');
        }
        Guard::duration($window);
        Guard::duration($historyTtl);
        foreach ($bans as $seconds) {
            if (!is_int($seconds)) {
                throw new \InvalidArgumentException('Ban durations must be integers.');
            }
            Guard::duration($seconds);
        }
        if ($historyTtl < max($window, max($bans))) {
            throw new \InvalidArgumentException('History TTL must cover the window and longest ban.');
        }
        $this->limit = $limit;
        $this->window = $window;
        $this->bans = array_values($bans);
        $this->historyTtl = $historyTtl;
    }
}
