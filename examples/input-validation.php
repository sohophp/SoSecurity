<?php
declare(strict_types=1);
namespace SoSecurity\Examples;

use SoSecurity\Validation\Validator;
use SoSecurity\Validation\Result;

/** Host parses request bodies and owns HTTP errors, output encoding, authorization and persistence. */
function validateProfile(array $input): Result
{
    return (new Validator(['profile' => ['type' => 'object', 'fields' => [
        'name' => ['type' => 'string', 'min' => 2, 'max' => 20],
        'age' => ['type' => 'integer', 'min' => 18, 'max' => 120],
        'email' => ['type' => 'string', 'format' => 'email'],
    ]]]))->validate($input);
}
