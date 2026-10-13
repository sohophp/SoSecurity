<?php
declare(strict_types=1);
namespace SoSecurity\Output;
/** Trusted HTML body-fragment sanitizer, called with preflight-bounded input by HtmlCleaner. Host reviews custom implementations. */
interface HtmlSanitizer
{
    public function sanitize(string $html): string;
}
