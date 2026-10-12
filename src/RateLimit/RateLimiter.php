<?php
declare(strict_types=1);

namespace SoSecurity\RateLimit;

use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

final class RateLimiter
{
    private $store;
    private $policy;
    private $clock;

    public function __construct(AtomicStore $store, ?Policy $policy = null, ?Clock $clock = null)
    {
        $this->store = $store;
        $this->policy = $policy ?? new Policy();
        $this->clock = $clock ?? new SystemClock();
    }

    /** Reserve BEFORE password/provider work: post-failure counting alone races under concurrency. */
    public function consume(string $scope, string $subject): Decision
    {
        return $this->evaluate($scope, $subject, true);
    }

    public function inspect(string $scope, string $subject): Decision
    {
        return $this->evaluate($scope, $subject, false);
    }

    private function evaluate(string $scope, string $subject, bool $consume): Decision
    {
        $key = Guard::key('rate', $scope, $subject);
        $now = $this->clock->now();
        $policy = $this->policy;
        return $this->store->transact($key, function (?array $state) use ($now, $consume, $policy) {
            $this->validateState($state);
            $state = $state ?? ['start' => $now, 'count' => 0, 'strikes' => 0, 'until' => 0, 'permanent' => false];
            if ($state['permanent'] || $state['until'] > $now) {
                return new Change($state, $state['permanent'] ? 0 : $state['expires'],
                    new Decision(false, 0, max(0, $state['until'] - $now), $state['permanent']));
            }
            if ($state['until'] > 0 || $state['start'] + $policy->window <= $now) {
                $state['start'] = $now;
                $state['count'] = 0;
                $state['until'] = 0;
            }
            $allowed = $state['count'] < $policy->limit;
            if ($consume) {
                if ($allowed) {
                    ++$state['count'];
                } else {
                    $duration = $policy->bans[min($state['strikes'], count($policy->bans) - 1)];
                    $state['strikes'] = min($state['strikes'] + 1, count($policy->bans));
                    $state['until'] = $now + $duration;
                }
                $state['expires'] = $now + $policy->historyTtl;
            }
            // An unused inspection must not create a record or extend the history retention.
            $expiry = $state['expires'] ?? 0;
            $retry = $allowed ? 0 : ($state['until'] > $now ? $state['until'] - $now
                : max(0, $state['start'] + $policy->window - $now));
            return new Change($expiry > 0 ? $state : null, $expiry,
                new Decision($allowed, max(0, $policy->limit - $state['count']), $retry));
        });
    }

    /** Null duration means a manually managed permanent ban. Authorization belongs to the host. */
    public function ban(string $scope, string $subject, ?int $duration = null): void
    {
        if ($duration !== null) {
            Guard::duration($duration);
        }
        $now = $this->clock->now();
        $this->store->transact(Guard::key('rate', $scope, $subject), function () use ($now, $duration) {
            $until = $duration === null ? 0 : $now + $duration;
            $state = ['start' => $now, 'count' => 0, 'strikes' => 0, 'until' => $until,
                'permanent' => $duration === null, 'expires' => $until];
            return new Change($state, $until, null);
        });
    }

    /** Explicit operator action; avoid resetting a broad IP bucket after every successful login. */
    public function reset(string $scope, string $subject): void
    {
        $this->store->transact(Guard::key('rate', $scope, $subject), function () { return new Change(null, 0, null); });
    }

    private function validateState(?array $state): void
    {
        if ($state === null) {
            return;
        }
        foreach (['start', 'count', 'strikes', 'until', 'expires'] as $field) {
            if (!isset($state[$field]) || !is_int($state[$field]) || $state[$field] < 0) {
                throw new StorageException('Corrupt rate-limit state.');
            }
        }
        if (!isset($state['permanent']) || !is_bool($state['permanent'])) {
            throw new StorageException('Corrupt rate-limit state.');
        }
    }
}
