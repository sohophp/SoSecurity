<?php
declare(strict_types=1);
namespace SoSecurity\Authorization;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

/** Internal immutable metadata/field preflight; no user object hooks or implicit wildcard semantics. */
final class Shape
{
    public static function name(string $name): void
    {
        if (!preg_match('/\A[a-z][a-z0-9_.:-]{0,63}\z/D', $name)) { throw new ConfigurationException('Invalid authorization action/type.', 'configuration.authorization'); }
    }
    public static function fields(array $fields): array
    {
        if (count($fields) > 64 || array_values($fields) !== $fields) { throw new ValidationException('Invalid requested field list.', 'authorization.fields'); }
        $copy = [];
        foreach ($fields as $field) {
            if (!is_string($field) || !preg_match('/\A[A-Za-z_][A-Za-z0-9_]{0,63}\z/D', $field) || in_array($field, $copy, true)) {
                throw new ValidationException('Invalid or duplicate field name.', 'authorization.fields');
            }
            $copy[] = $field;
        }
        return $copy;
    }
    public static function attributes(array $attributes): array
    {
        if (count($attributes) > 64) { throw new ConfigurationException('Too many resource attributes.', 'configuration.authorization'); }
        $copy = [];
        foreach ($attributes as $name => $value) {
            if (!is_string($name) || !preg_match('/\A[A-Za-z_][A-Za-z0-9_]{0,63}\z/D', $name)
                || (!is_null($value) && !is_bool($value) && !is_int($value) && !is_string($value))
                || (is_string($value) && (strlen($value) > 1024 || !preg_match('//u', $value)))) {
                throw new ConfigurationException('Resource attributes must be bounded named scalar values.', 'configuration.authorization');
            }
            $copy[$name] = $value;
        }
        ksort($copy);
        if (strlen(json_encode($copy)) > 8192) { throw new ConfigurationException('Resource attributes exceed 8 KiB.', 'configuration.authorization'); }
        return $copy;
    }
}
