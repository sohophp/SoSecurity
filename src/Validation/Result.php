<?php
declare(strict_types=1);
namespace SoSecurity\Validation;

use SoSecurity\Exception\ValidationException;

final class Result
{
    private $data;
    private $errors;
    public function __construct(array $data, array $errors) { $this->data = $data; $this->errors = $errors; }
    public function valid(): bool { return $this->errors === []; }
    /** Paths use JSON Pointer; errors contain no rejected values or translated presentation text. */
    public function errors(): array { return $this->errors; }
    public function data(): array
    {
        if (!$this->valid()) { throw new ValidationException('Use data only after successful validation.', 'validation.invalid'); }
        return $this->data;
    }
}
