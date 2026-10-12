<?php
declare(strict_types=1);
namespace SoSecurity\Examples;

use SoSecurity\Upload\Validator;
use SoSecurity\Upload\Candidate;

/** Host invokes this AFTER its file-manager event has authenticated and authorized the source path. */
function inspectManagedUpload(Validator $validator, string $authorizedLocalPath, string $originalName): Candidate
{
    // Does not rewrite the manager's source or replace its persistence/permissions/thumbnail lifecycle.
    // Use returned contents for a validated private copy; raw source bytes can differ from sanitized image bytes.
    return $validator->inspectFile($authorizedLocalPath, $originalName);
}
