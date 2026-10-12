<?php
declare(strict_types=1);

namespace SoSecurity\Captcha;

use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

final class Captcha
{
    private $store;
    private $clock;
    private $ttl;
    private $attempts;
    private $capacity;

    public function __construct(AtomicStore $store, int $ttl = 300, int $attempts = 3,
        int $capacity = 4, ?Clock $clock = null)
    {
        Guard::duration($ttl);
        if ($attempts < 1 || $attempts > 10 || $capacity < 1 || $capacity > 16) {
            throw new \InvalidArgumentException('Invalid CAPTCHA attempt limit or capacity.');
        }
        $this->store = $store;
        $this->ttl = $ttl;
        $this->attempts = $attempts;
        $this->capacity = $capacity;
        $this->clock = $clock ?? new SystemClock();
    }

    public function arithmetic(string $scope, string $binding): Challenge
    {
        $left = random_int(1, 20);
        $right = random_int(1, 20);
        return $this->issue($scope, $binding, (string) ($left + $right), "$left + $right = ?", null);
    }

    public function image(string $scope, string $binding, ?ImageRenderer $renderer = null,
        int $length = 5, string $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'): Challenge
    {
        if ($length < 4 || $length > 8 || !preg_match('/^[A-Z2-9]{8,32}$/D', $alphabet)
            || count(array_unique(str_split($alphabet))) !== strlen($alphabet)) {
            throw new \InvalidArgumentException('Use 4-8 characters and 8-32 distinct ASCII alphabet symbols.');
        }
        $answer = '';
        for ($i = 0; $i < $length; ++$i) {
            $answer .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }
        $png = ($renderer ?? new ImageRenderer())->render($answer);
        return $this->issue($scope, $binding, $answer, '', $png);
    }

    private function issue(string $scope, string $binding, string $answer, string $prompt, ?string $image): Challenge
    {
        $key = Guard::key('captcha', $scope, $binding);
        $id = bin2hex(random_bytes(16));
        $now = $this->clock->now();
        $record = ['digest' => hash('sha256', $id . ':' . $answer),
            'expires' => $now + $this->ttl, 'remaining' => $this->attempts];
        $this->store->transact($key, function (?array $state) use ($id, $record, $now) {
            $this->validateState($state);
            $state = array_filter($state ?? [], function ($item) use ($now) { return $item['expires'] > $now; });
            while (count($state) >= $this->capacity) {
                array_shift($state);
            }
            $state[$id] = $record;
            return new Change($state, max(array_column($state, 'expires')), null);
        });
        return new Challenge($id, $prompt, $image, $record['expires']);
    }

    public function verify(string $scope, string $binding, $id, $answer): bool
    {
        $key = Guard::key('captcha', $scope, $binding);
        if (!is_string($id) || !preg_match('/^[a-f0-9]{32}$/D', $id)) {
            return false;
        }
        $answer = is_string($answer) && strlen($answer) <= 32 ? strtoupper(trim($answer)) : '';
        $now = $this->clock->now();
        return $this->store->transact($key, function (?array $state) use ($id, $answer, $now) {
            $this->validateState($state);
            $state = array_filter($state ?? [], function ($item) use ($now) { return $item['expires'] > $now; });
            $valid = false;
            if (isset($state[$id])) {
                $valid = hash_equals($state[$id]['digest'], hash('sha256', $id . ':' . $answer));
                if ($valid || --$state[$id]['remaining'] <= 0) {
                    unset($state[$id]);
                }
            }
            return new Change($state ?: null, $state ? max(array_column($state, 'expires')) : 0, $valid);
        });
    }

    /** Refresh invalidates all existing challenges for this binding and scope. */
    public function revoke(string $scope, string $binding): void
    {
        $this->store->transact(Guard::key('captcha', $scope, $binding), function () {
            return new Change(null, 0, null);
        });
    }

    private function validateState(?array $state): void
    {
        if ($state === null) {
            return;
        }
        if (count($state) > 16) {
            throw new StorageException('Corrupt CAPTCHA state.');
        }
        foreach ($state as $id => $item) {
            if (!is_string($id) || !preg_match('/^[a-f0-9]{32}$/D', $id) || !is_array($item)
                || !isset($item['digest'], $item['expires'], $item['remaining'])
                || !is_string($item['digest']) || !preg_match('/^[a-f0-9]{64}$/D', $item['digest'])
                || !is_int($item['expires']) || $item['expires'] <= 0
                || !is_int($item['remaining']) || $item['remaining'] < 1 || $item['remaining'] > 10) {
                throw new StorageException('Corrupt CAPTCHA state.');
            }
        }
    }
}
