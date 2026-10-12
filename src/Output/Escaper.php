<?php
declare(strict_types=1);

namespace SoSecurity\Output;

final class Escaper
{
    /** HTML text or quoted ordinary attributes; not event handlers, style, srcdoc or URL policy. */
    public static function html(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8', true);
    }

    /** JSON data literal inside a script. Never concatenate into JavaScript source or identifiers. */
    public static function json($value): string
    {
        $encoded = json_encode($value, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
        if ($encoded === false) {
            throw new \InvalidArgumentException('Cannot encode JavaScript data.');
        }
        return $encoded;
    }

    public static function urlComponent(string $value): string
    {
        return rawurlencode($value);
    }
}
