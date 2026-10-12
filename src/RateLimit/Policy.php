<?php
declare(strict_types=1);

namespace SoSecurity\RateLimit;

use SoSecurity\Support\Guard;

final class Policy
{
    private $limit;
    private $window;
    private $bans;
    private $historyTtl;

    public function __construct(int $limit = 5, int $window = 300, array $bans = [60, 300, 900], int $historyTtl = 86400)
    {
        if ($limit < 1 || $limit > 1000000 || !$bans || count($bans) > 16) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid request limit or ban ladder.');
        }
        Guard::duration($window);
        Guard::duration($historyTtl);
        foreach ($bans as $seconds) {
            if (!is_int($seconds)) {
                throw new \SoSecurity\Exception\ConfigurationException('Ban durations must be integers.');
            }
            Guard::duration($seconds);
        }
        if ($historyTtl < max($window, max($bans))) {
            throw new \SoSecurity\Exception\ConfigurationException('History TTL must cover the window and longest ban.');
        }
        $this->limit = $limit;
        $this->window = $window;
        $this->bans = [];
        foreach ($bans as $seconds) { $this->bans[] = $seconds; }
        $this->historyTtl = $historyTtl;
    }
    public function limit(): int { return $this->limit; }
    public function window(): int { return $this->window; }
    public function banDurations(): array { return $this->bans; }
    public function historyTtl(): int { return $this->historyTtl; }
    public function __set(string $name, $value): void
    {
        throw new \SoSecurity\Exception\ConfigurationException('Rate limit policies are immutable.', 'configuration.immutable');
    }
}
