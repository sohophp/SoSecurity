<?php
declare(strict_types=1);

namespace SoSecurity\Support;

final class Guard
{
    public static function label(string $value): string
    {
        if ($value === '' || strlen($value) > 256 || preg_match('/[\x00-\x1f\x7f]/', $value)) {
            throw new \InvalidArgumentException('Expected a non-empty label of at most 256 bytes without controls.');
        }
        return $value;
    }

    public static function duration(int $value): int
    {
        if ($value < 1 || $value > 31536000) {
            throw new \InvalidArgumentException('Duration must be between 1 and 31536000 seconds.');
        }
        return $value;
    }

    public static function key(string $module, string $scope, string $binding): string
    {
        self::label($scope);
        if ($binding === '' || strlen($binding) > 1024) {
            throw new \InvalidArgumentException('A server-side binding is required (maximum 1024 bytes).');
        }
        return $module . ':' . hash('sha256', strlen($scope) . ':' . $scope . ':' . $binding);
    }
}
