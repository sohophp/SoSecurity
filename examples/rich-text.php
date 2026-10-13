<?php
declare(strict_types=1);
namespace SoSecurity\Examples;
use SoSecurity\Output\HtmlCleaner;

/** Host authorizes editing, verifies CSRF and preserves original content before cleaning; returns body fragment only. */
function cleanRichText(HtmlCleaner $cleaner,string $input): string
{
    return $cleaner->clean($input);
}
