<?php
declare(strict_types=1);
namespace SoSecurity\RateLimit;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Guard;

/** Internal pure state machine. Time is supplied once outside every retryable transaction. */
final class BudgetState
{
    public static function ceil(int $numerator, int $denominator): int
    {
        if ($numerator < 0 || $denominator < 1) { throw new ConfigurationException('Invalid integer budget division.', 'configuration.budget'); }
        return intdiv($numerator, $denominator) + ($numerator % $denominator === 0 ? 0 : 1);
    }
    public static function input(string $scope, string $subject, int $cost, int $now): void
    {
        Guard::key('budget', $scope, $subject);
        if (!preg_match('//u', $scope) || $now < 0 || $now > PHP_INT_MAX - 31536000) { throw new ConfigurationException('Invalid budget scope/clock.', 'configuration.budget'); }
        if ($cost < 1 || $cost > 1000000) { throw new ValidationException('Budget cost must be 1-1000000.', 'rate.cost'); }
    }
    public static function fields(array $value, array $expected): bool { $keys = array_keys($value); sort($keys); sort($expected); return $keys === $expected; }
    public static function read($state, BudgetPolicy $policy, int $now): ?array
    {
        if ($state === null) { return null; }
        if (!is_array($state) || !self::fields($state, ['v','policy','seen','expires','data']) || $state['v'] !== 1
            || !is_string($state['policy']) || !preg_match('/\A[a-f0-9]{64}\z/D', $state['policy']) || !is_int($state['seen']) || $state['seen'] < 0
            || !is_int($state['expires']) || $state['expires'] <= $state['seen'] || !is_array($state['data'])) { throw new StorageException('Corrupt request budget.', 'storage.corrupt'); }
        if (!hash_equals($policy->fingerprint(), $state['policy'])) { throw new StorageException('Active request-budget policy changed; migrate the scope explicitly.', 'rate.policy_changed'); }
        if ($state['seen'] > $now) { throw new StorageException('Request-budget clock moved backwards.', 'rate.clock'); }
        $data = $state['data']; $window = $policy->window();
        if ($policy->algorithm() === 'token_bucket') {
            if (!self::fields($data, ['at','credit']) || !is_int($data['at']) || $data['at'] !== $state['seen'] || !is_int($data['credit'])
                || $data['credit'] < 0 || $data['credit'] >= $policy->capacity() * $window
                || $state['expires'] !== $data['at'] + self::ceil($policy->capacity() * $window - $data['credit'], $policy->limit())) { throw new StorageException('Corrupt token credits.', 'storage.corrupt'); }
        } elseif ($policy->algorithm() === 'fixed_window') {
            if (!self::fields($data, ['start','used']) || !is_int($data['start']) || $data['start'] < 0 || $data['start'] > $state['seen']
                || !is_int($data['used']) || $data['used'] < 1 || $data['used'] > $policy->limit() || $state['expires'] !== $data['start'] + $window) { throw new StorageException('Corrupt fixed-window budget.', 'storage.corrupt'); }
        } else {
            if (!self::fields($data, ['events']) || !is_array($data['events']) || !$data['events'] || count($data['events']) > $policy->maximumEntries()
                || array_values($data['events']) !== $data['events']) { throw new StorageException('Corrupt sliding-window budget.', 'storage.corrupt'); }
            $last = -1; $sum = 0;
            foreach ($data['events'] as $event) {
                if (!is_array($event) || array_keys($event) !== [0,1] || !is_int($event[0]) || $event[0] < 0 || $event[0] <= $last || $event[0] > $state['seen']
                    || !is_int($event[1]) || $event[1] < 1 || $event[1] > $policy->limit() - $sum) { throw new StorageException('Corrupt sliding-window event.', 'storage.corrupt'); }
                $last = $event[0]; $sum += $event[1];
            }
            if ($state['expires'] !== $last + $window) { throw new StorageException('Corrupt sliding-window expiry.', 'storage.corrupt'); }
        }
        return $state['expires'] <= $now ? null : $state;
    }
    public static function evaluate(?array $state, BudgetPolicy $policy, int $now, int $cost, bool $consume): Change
    {
        $original = $state; $state = self::read($state, $policy, $now);
        if ($cost > $policy->capacity()) {
            return new Change($original, $original['expires'] ?? 0, new BudgetDecision(false, 0, 0, 'rate.cost_exceeds_limit'));
        }
        $window = $policy->window(); $retry = 0; $reason = 'rate.allowed';
        if ($policy->algorithm() === 'token_bucket') {
            $maximum = $policy->capacity() * $window; $credit = $maximum;
            if ($state !== null) {
                $credit = $state['data']['credit']; $elapsed = $now - $state['data']['at'];
                $credit = $elapsed >= self::ceil($maximum - $credit, $policy->limit()) ? $maximum : $credit + $elapsed * $policy->limit();
            }
            $allowed = $credit >= $cost * $window;
            if ($allowed && $consume) { $credit -= $cost * $window; }
            if (!$allowed) { $retry = self::ceil($cost * $window - $credit, $policy->limit()); }
            $remaining = intdiv($credit, $window); $data = ['at' => $now, 'credit' => $credit];
            $expires = $now + self::ceil($maximum - $credit, $policy->limit());
        } elseif ($policy->algorithm() === 'fixed_window') {
            $data = $state === null ? ['start' => $now, 'used' => 0] : $state['data'];
            $allowed = $cost <= $policy->limit() - $data['used'];
            if ($allowed && $consume) { $data['used'] += $cost; }
            $remaining = $policy->limit() - $data['used']; $expires = $data['start'] + $window;
            if (!$allowed) { $retry = $expires - $now; }
        } else {
            $events = $state['data']['events'] ?? []; $live = []; $used = 0;
            foreach ($events as $event) { if ($event[0] > $now - $window) { $live[] = $event; $used += $event[1]; } }
            $sameSecond = $live && $live[count($live)-1][0] === $now;
            $capacity = !$sameSecond && count($live) >= $policy->maximumEntries();
            $allowed = !$capacity && $cost <= $policy->limit() - $used;
            if (!$allowed) {
                $released = 0;
                foreach ($live as $event) {
                    $released += $event[1]; $retry = $event[0] + $window - $now;
                    if ($cost <= $policy->limit() - $used + $released) { break; }
                }
                if ($capacity) { $retry = max($retry, $live[0][0] + $window - $now); $reason = 'rate.capacity'; }
            } elseif ($consume) {
                if ($sameSecond) { $live[count($live)-1][1] += $cost; } else { $live[] = [$now, $cost]; }
                $used += $cost;
            }
            $remaining = $policy->limit() - $used; $data = ['events' => $live]; $expires = $live ? $live[count($live)-1][0] + $window : $now + $window;
        }
        $decision = new BudgetDecision($allowed, $remaining, $retry, $allowed ? 'rate.allowed' : ($reason === 'rate.capacity' ? $reason : 'rate.exhausted'), $consume && $allowed ? $expires : 0);
        if (!$consume) { return new Change($original, $original['expires'] ?? 0, $decision); }
        return new Change(['v' => 1, 'policy' => $policy->fingerprint(), 'seen' => $now, 'expires' => $expires, 'data' => $data], $expires, $decision);
    }
    public static function finish(int $started, int $now, bool $admitted, int $until): void
    {
        if ($now < $started) { throw new StorageException('Budget clock moved backwards during storage I/O.', 'rate.clock'); }
        if ($admitted && ($until === 0 || $until <= $now)) { throw new StorageException('Budget reservation expired during storage I/O; no operation may start.', 'rate.expired'); }
    }
}
