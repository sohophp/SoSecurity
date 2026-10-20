<?php
declare(strict_types=1);
namespace SoSecurity\RateLimit;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Support\Guard;

/** Internal configured-name and per-request binding/cost validation before any quota is charged. */
final class BudgetBindings
{
    public static function name($name): void
    {
        if (!is_string($name) || !preg_match('/\A[a-z][a-z0-9_-]{0,63}\z/D', $name)) { throw new ConfigurationException('Invalid budget dimension name.', 'configuration.budget'); }
    }
    public static function costs(array $names, array $costs): array
    {
        if (!$costs) { $costs = array_fill_keys($names, 1); }
        $keys = array_keys($costs); $expected = $names; sort($keys); sort($expected);
        if ($keys !== $expected) { throw new ValidationException('Provide every configured dimension cost, without extra dimensions.', 'rate.cost'); }
        $copy = [];
        foreach ($names as $name) {
            if (!is_int($costs[$name]) || $costs[$name] < 1 || $costs[$name] > 1000000) { throw new ValidationException('Invalid budget dimension cost.', 'rate.cost'); }
            $copy[$name] = $costs[$name];
        }
        return $copy;
    }
    public static function subjects(array $names, array $subjects): array
    {
        $keys = array_keys($subjects); $expected = $names; sort($keys); sort($expected);
        if ($keys !== $expected) { throw new ValidationException('Provide every configured dimension binding.', 'rate.binding'); }
        $copy = [];
        foreach ($names as $name) {
            if (!is_string($subjects[$name])) { throw new ValidationException('Expected a server-derived budget binding.', 'rate.binding'); }
            Guard::key('budget', 'binding', $subjects[$name]); $copy[$name] = $subjects[$name];
        }
        return $copy;
    }
}
