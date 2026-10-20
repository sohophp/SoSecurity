<?php
declare(strict_types=1);
namespace SoSecurity\Examples;

use SoSecurity\Upload\ArchiveInspector;

/** Call only after host authorization and private upload staging; no extraction occurs. */
function inspectPrivateZip(string $privatePath): array
{
    return (new ArchiveInspector())->inspect($privatePath);
}
