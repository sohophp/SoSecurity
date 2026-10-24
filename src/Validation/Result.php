<?php
declare(strict_types=1);
namespace SoSecurity\Validation;

use SoSecurity\Exception\ValidationException;
use SoSecurity\Exception\ConfigurationException;

final class Result
{
    private $read;
    public function __construct(array $data, array $errors)
    {
        $this->read = static function () use ($data, $errors): array { return [$data, $errors]; };
    }
    public function valid(): bool { return $this->values()[1] === []; }
    /** Paths use JSON Pointer; errors contain no rejected values or translated presentation text. */
    public function errors(): array { return $this->values()[1]; }
    public function data(): array
    {
        if (!$this->valid()) { throw new ValidationException('Use data only after successful validation.', 'validation.invalid'); }
        return $this->values()[0];
    }
    private function values(): array
    {
        if (!$this->read instanceof \Closure) {
            throw new ConfigurationException('Rebuild validation results from explicit input.', 'configuration.validation_serialization');
        }
        return ($this->read)();
    }
    public function __debugInfo(): array { return ['validation_result' => '[redacted]']; }
    public function __sleep(): array
    {
        throw new ConfigurationException('Rebuild validation results from explicit input.', 'configuration.validation_serialization');
    }
    public function __wakeup(): void
    {
        throw new ConfigurationException('Rebuild validation results from explicit input.', 'configuration.validation_serialization');
    }
}
