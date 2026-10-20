<?php
declare(strict_types=1);
namespace SoSecurity\Operation;
use SoSecurity\Exception\ValidationException;

/** Internal typed canonicalization; never invokes JSON/object/serialization hooks. */
final class Shape
{
    public static function parameters(array $parameters): array
    {
        if (count($parameters) > 64) { throw new ValidationException('Too many operation parameters.','operation.parameters'); }
        foreach ($parameters as $key => $value) { self::name($key); }
        $nodes = 0; $copy = self::copy($parameters,0,$nodes);
        if (strlen(json_encode($copy)) > 16384) { throw new ValidationException('Operation parameters exceed 16 KiB.','operation.parameters'); }
        return $copy;
    }
    private static function name($name): void
    {
        if (!is_string($name) || !preg_match('/\A[A-Za-z_][A-Za-z0-9_]{0,63}\z/D',$name)) { throw new ValidationException('Invalid operation parameter name.','operation.parameters'); }
    }
    private static function copy($value,int $depth,int &$nodes)
    {
        if (++$nodes > 256 || $depth > 8) { throw new ValidationException('Operation parameter structure exceeds its budget.','operation.parameters'); }
        if (is_array($value)) {
            if (count($value) > 64) { throw new ValidationException('Too many operation values.','operation.parameters'); }
            $list = array_values($value) === $value; $copy = [];
            foreach ($value as $key => $item) { if (!$list) { self::name($key); } $copy[$key] = self::copy($item,$depth+1,$nodes); }
            if (!$list) { ksort($copy); } return $copy;
        }
        if (is_string($value)) {
            if (strlen($value) > 4096 || !preg_match('//u',$value)) { throw new ValidationException('Invalid bounded UTF-8 operation value.','operation.parameters'); }
            return (string) $value;
        }
        if (is_int($value) && $value >= -2147483647 && $value <= 2147483647) { return (int) $value; }
        if ($value === null || is_bool($value)) { return $value; }
        throw new ValidationException('Use bounded integers, booleans, null, strings and arrays; decimal amounts/large identifiers must be strings.','operation.parameters');
    }
}
