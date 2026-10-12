<?php
declare(strict_types=1);
namespace SoSecurity\Validation;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;

/** Bounded strict validation, without implicit coercion, HTML stripping or authentication decisions. */
final class Validator
{
    private $fields;
    private $maximumBytes;
    public function __construct(array $fields, int $maximumBytes = 262144)
    {
        if ($maximumBytes < 1 || $maximumBytes > 1048576) { throw new ConfigurationException('Input byte budget must be 1-1048576.'); }
        $count = 0;
        $this->fields = $this->compileFields($fields, 0, $count); $this->maximumBytes = $maximumBytes;
    }
    public function validate(array $input): Result
    {
        $nodes = 0; $bytes = 0;
        if (!$this->bounded($input, 0, $nodes, $bytes)) { return new Result([], [['path' => '', 'code' => 'validation.resources']]); }
        $errors = []; $data = $this->object($input, $this->fields, '', $errors);
        return new Result($errors === [] ? $data : [], $errors);
    }
    private function compileFields(array $fields, int $depth, int &$count): array
    {
        if ($depth > 12 || count($fields) > 128) { throw new ConfigurationException('Schema exceeds structural limits.'); }
        $compiled = [];
        foreach ($fields as $name => $spec) {
            if (!is_string($name) || !preg_match('/^[A-Za-z][A-Za-z0-9_]{0,63}$/D', $name) || !is_array($spec)) {
                throw new ConfigurationException('Schema field names and definitions are invalid.');
            }
            $compiled[$name] = $this->compile($spec, $depth + 1, $count);
        }
        return $compiled;
    }
    private function compile(array $spec, int $depth, int &$count): array
    {
        if ($depth > 12 || ++$count > 256) { throw new ConfigurationException('Schema exceeds structural limits.'); }
        $type = $spec['type'] ?? null;
        if (!in_array($type, ['string', 'integer', 'number', 'boolean', 'object', 'list'], true)) { throw new ConfigurationException('Specify a supported strict field type.'); }
        $allowed = ['type', 'required', 'nullable', 'enum', 'rules'];
        if ($type === 'string') { $allowed = array_merge($allowed, ['min', 'max', 'maximum_bytes', 'format', 'pattern', 'normalization']); }
        if (in_array($type, ['integer', 'number', 'list'], true)) { $allowed = array_merge($allowed, ['min', 'max']); }
        if ($type === 'object') { $allowed[] = 'fields'; }
        if ($type === 'list') { $allowed[] = 'items'; }
        if (array_diff(array_keys($spec), $allowed)) { throw new ConfigurationException('Unknown or misplaced validation option.'); }
        $copy = ['type' => $type, 'required' => true, 'nullable' => false];
        foreach (['required', 'nullable'] as $option) {
            if (array_key_exists($option, $spec)) {
                if (!is_bool($spec[$option])) { throw new ConfigurationException('Validation flags must be boolean.'); }
                $copy[$option] = $spec[$option];
            }
        }
        foreach (['min', 'max'] as $option) {
            if (array_key_exists($option, $spec)) {
                $value = $spec[$option];
                $this->validateRange($value, $type);
                $copy[$option] = $value;
            }
        }
        if (isset($copy['min'], $copy['max']) && $copy['min'] > $copy['max']) { throw new ConfigurationException('Validation range is reversed.'); }
        switch ($type) {
            case 'object':
                if (!isset($spec['fields']) || !is_array($spec['fields'])) { throw new ConfigurationException('Objects require fields.'); }
                $copy['fields'] = $this->compileFields($spec['fields'], $depth, $count); break;
            case 'list':
                if (!isset($spec['items']) || !is_array($spec['items'])) { throw new ConfigurationException('Lists require an item schema.'); }
                $copy['items'] = $this->compile($spec['items'], $depth + 1, $count); break;
            case 'string': $copy = array_merge($copy, $this->stringOptions($spec)); break;
        }
        if (array_key_exists('enum', $spec)) {
            if (!is_array($spec['enum']) || count($spec['enum']) < 1 || count($spec['enum']) > 128) { throw new ConfigurationException('Invalid enum.'); }
            $copy['enum'] = [];
            foreach ($spec['enum'] as $value) {
                if ((!is_string($value) && !is_int($value) && !is_bool($value) && !is_float($value) && $value !== null)
                    || (is_string($value) && (strlen($value) > 1024 || !preg_match('//u', $value)))
                    || (is_float($value) && !is_finite($value))) { throw new ConfigurationException('Enums contain only bounded scalar values.'); }
                $copy['enum'][] = $value;
            }
        }
        if (array_key_exists('rules', $spec)) {
            if (!is_array($spec['rules']) || count($spec['rules']) > 16) { throw new ConfigurationException('Invalid custom rule list.'); }
            $copy['rules'] = [];
            foreach ($spec['rules'] as $rule) {
                if (!$rule instanceof Rule) { throw new ConfigurationException('Invalid custom rule.'); }
                $code = $rule->code();
                if (!preg_match('/^[a-z][a-z0-9_.]{0,63}$/D', $code)) { throw new ConfigurationException('Invalid custom rule code.'); }
                $copy['rules'][] = ['rule' => $rule, 'code' => 'validation.custom.' . $code];
            }
        }
        return $copy;
    }
    private function stringOptions(array $spec): array
    {
        $copy = [];
        $copy['maximum_bytes'] = array_key_exists('maximum_bytes', $spec) ? $spec['maximum_bytes'] : 65536;
        if (!is_int($copy['maximum_bytes']) || $copy['maximum_bytes'] < 1 || $copy['maximum_bytes'] > 65536) { throw new ConfigurationException('Invalid string byte budget.'); }
        $copy['normalization'] = array_key_exists('normalization', $spec) ? $spec['normalization'] : 'none';
        if (!in_array($copy['normalization'], ['none', 'NFC'], true)) { throw new ConfigurationException('Unsupported normalization.'); }
        if ($copy['normalization'] === 'NFC' && !extension_loaded('intl')) { throw new DependencyException('NFC normalization requires ext-intl.', 'dependency.intl'); }
        if (array_key_exists('format', $spec)) {
            if (!in_array($spec['format'], ['email', 'uuid', 'date', 'ascii_identifier'], true)) { throw new ConfigurationException('Unsupported string format.'); }
            $copy['format'] = $spec['format'];
        }
        if (array_key_exists('pattern', $spec)) {
            if (!is_string($spec['pattern']) || strlen($spec['pattern']) > 1024 || @preg_match($spec['pattern'], '') === false) {
                throw new ConfigurationException('Invalid trusted regular expression.');
            }
            $copy['pattern'] = $spec['pattern'];
        }
        return $copy;
    }
    private function validateRange($value, string $type): void
    {
        if (!is_int($value) && ($type !== 'number' || !is_float($value))) { throw new ConfigurationException('Range must have a numeric type.'); }
        if (!is_finite((float) $value)) { throw new ConfigurationException('Range must be finite.'); }
        if (in_array($type, ['string', 'list'], true) && ($value < 0 || $value > 65536)) { throw new ConfigurationException('Invalid size range.'); }
    }
    private function bounded($value, int $depth, int &$nodes, int &$bytes): bool
    {
        if ($depth > 16 || ++$nodes > 4096) { return false; }
        if (is_array($value)) {
            if (count($value) > 256) { return false; }
            foreach ($value as $key => $item) {
                if (is_string($key) && (strlen($key) > 128 || !preg_match('//u', $key))) { return false; }
                $bytes += strlen((string) $key);
                if ($bytes > $this->maximumBytes || !$this->bounded($item, $depth + 1, $nodes, $bytes)) { return false; }
            }
        } elseif (is_string($value)) {
            $bytes += strlen($value);
            if (strlen($value) > 65536) { return false; }
        } elseif (!is_scalar($value) && $value !== null) { return false; }
        else { $bytes += 16; }
        return $bytes <= $this->maximumBytes;
    }
    private function object(array $input, array $fields, string $path, array &$errors): array
    {
        $data = [];
        foreach ($input as $name => $unused) {
            if (!array_key_exists($name, $fields)) { $errors[] = ['path' => $this->path($path, (string) $name), 'code' => 'validation.unknown']; }
        }
        foreach ($fields as $name => $spec) {
            $fieldPath = $this->path($path, $name);
            if (!array_key_exists($name, $input)) {
                if ($spec['required']) { $errors[] = ['path' => $fieldPath, 'code' => 'validation.required']; }
                continue;
            }
            $data[$name] = $this->field($input[$name], $spec, $fieldPath, $errors);
        }
        return $data;
    }
    private function field($value, array $spec, string $path, array &$errors)
    {
        if ($value === null && $spec['nullable']) { return null; }
        $type = $spec['type'];
        $correct = ($type === 'string' && is_string($value)) || ($type === 'integer' && is_int($value))
            || ($type === 'number' && (is_int($value) || (is_float($value) && is_finite($value))))
            || ($type === 'boolean' && is_bool($value)) || (in_array($type, ['object', 'list'], true) && is_array($value));
        if (!$correct) { $errors[] = ['path' => $path, 'code' => 'validation.type']; return null; }
        $code = null; $size = null;
        if ($type === 'string') {
            if (!preg_match('//u', $value)) { $code = 'validation.utf8'; }
            elseif (strlen($value) > $spec['maximum_bytes']) { $code = 'validation.bytes'; }
            else {
                if ($spec['normalization'] === 'NFC') {
                    $normalized = \Normalizer::normalize($value, \Normalizer::FORM_C);
                    if (!is_string($normalized)) { $code = 'validation.normalization'; }
                    else { $value = $normalized; }
                }
                if ($code === null) {
                    if (strlen($value) > $spec['maximum_bytes']) { $code = 'validation.bytes'; }
                    $size = preg_match_all('/./us', $value);
                    if (isset($spec['format']) && !$this->format($value, $spec['format'])) { $code = 'validation.format'; }
                    if (isset($spec['pattern'])) {
                        $matches = [];
                        $matched = @preg_match($spec['pattern'], $value, $matches, PREG_OFFSET_CAPTURE);
                        if ($matched !== 1 || $matches[0][1] !== 0 || strlen($matches[0][0]) !== strlen($value)) { $code = 'validation.pattern'; }
                    }
                }
            }
        } elseif ($type === 'list') {
            if ($value !== [] && array_keys($value) !== range(0, count($value) - 1)) { $code = 'validation.type'; }
            $size = count($value);
        } elseif (in_array($type, ['integer', 'number'], true)) { $size = $value; }
        if ($code === null && $size !== null) {
            if (isset($spec['min']) && $size < $spec['min']) { $code = 'validation.min'; }
            if (isset($spec['max']) && $size > $spec['max']) { $code = 'validation.max'; }
        }
        if ($code === null && isset($spec['enum']) && !in_array($value, $spec['enum'], true)) { $code = 'validation.enum'; }
        if ($code !== null) { $errors[] = ['path' => $path, 'code' => $code]; return null; }
        $before = count($errors);
        if ($type === 'object') { $value = $this->object($value, $spec['fields'], $path, $errors); }
        elseif ($type === 'list') {
            $items = [];
            foreach ($value as $index => $item) { $items[] = $this->field($item, $spec['items'], $this->path($path, (string) $index), $errors); }
            $value = $items;
        }
        if (count($errors) === $before) {
            foreach ($spec['rules'] ?? [] as $custom) {
                try { $passed = $custom['rule']->passes($value); }
                catch (\Throwable $e) { throw new SecurityException('Custom validation rule failed.', 'validation.rule_failure', $e); }
                if (!$passed) { $errors[] = ['path' => $path, 'code' => $custom['code']]; break; }
            }
        }
        return $value;
    }
    private function path(string $prefix, string $name): string { return $prefix . '/' . str_replace(['~', '/'], ['~0', '~1'], $name); }
    private function format(string $value, string $format): bool
    {
        switch ($format) {
            case 'email': return strlen($value) <= 254 && filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
            case 'uuid': return (bool) preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/iD', $value);
            case 'ascii_identifier': return (bool) preg_match('/^[A-Za-z][A-Za-z0-9_]{0,63}$/D', $value);
            case 'date':
                if (!preg_match('/^(\d{4})-(\d{2})-(\d{2})$/D', $value, $matches)) { return false; }
                return checkdate((int) $matches[2], (int) $matches[3], (int) $matches[1]);
        }
        return false;
    }
}
