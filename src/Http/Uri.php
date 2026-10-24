<?php
declare(strict_types=1);
namespace SoSecurity\Http;

use SoSecurity\Exception\ValidationException;
use SoSecurity\Exception\ConfigurationException;

/** Strict HTTP URI parser shared by format validation, redirects, CORS and outbound requests. No DNS or trust decision. */
final class Uri
{
    private $scheme;
    private $host;
    private $port;
    private $read;
    private function __construct() {}
    public static function parse(string $value, bool $allowFragment = false): self
    {
        self::safeText($value);
        if (!preg_match('/\A(https?):\/\/([^\/?#]+)([^#]*)(?:#(.*))?\z/iD', $value, $parts)) { throw new ValidationException('HTTP URI syntax is invalid.', 'url.invalid'); }
        if (!$allowFragment && isset($parts[4])) { throw new ValidationException('Fragments are not accepted here.', 'url.fragment'); }
        $authority = $parts[2]; $host = ''; $port = null;
        if ($authority[0] === '[') {
            if (!preg_match('/\A\[([^\]]+)\](?::([1-9][0-9]{0,4}))?\z/D', $authority, $address) || filter_var($address[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                throw new ValidationException('IPv6 URI authority is invalid.', 'url.host');
            }
            $host = inet_ntop(inet_pton($address[1])); $port = isset($address[2]) ? (int) $address[2] : null;
        } else {
            if (!preg_match('/\A([^:]+)(?::([1-9][0-9]{0,4}))?\z/D', $authority, $address)) { throw new ValidationException('URI authority is invalid.', 'url.host'); }
            $host = self::host($address[1]); $port = isset($address[2]) ? (int) $address[2] : null;
        }
        $scheme = strtolower($parts[1]); $port = $port ?? ($scheme === 'https' ? 443 : 80);
        if ($port > 65535) { throw new ValidationException('URI port is invalid.', 'url.port'); }
        $tail = $parts[3]; $question = strpos($tail, '?');
        $path = $question === false ? $tail : substr($tail, 0, $question);
        if ($path !== '' && $path[0] !== '/') { throw new ValidationException('URI path is invalid.', 'url.path'); }
        $uri = new self(); $uri->scheme = $scheme; $uri->host = $host; $uri->port = $port;
        $values = [self::dots($path === '' ? '/' : $path), $question === false ? null : substr($tail, $question + 1), $parts[4] ?? null];
        $uri->read = static function () use ($values): array { return $values; };
        return $uri;
    }
    public static function host(string $host): string
    {
        if (strlen($host) > 253) { throw new ValidationException('Host is too long.', 'url.host'); }
        $host = strtolower($host);
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false && preg_match('/\A(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}\z/D', $host)) { return $host; }
        if (preg_match('/\A(?:0x[a-f0-9]+|[0-9]+)(?:\.(?:0x[a-f0-9]+|[0-9]+)){0,3}\z/iD', $host)) { throw new ValidationException('Legacy numeric addresses are forbidden.', 'url.host'); }
        if (strlen($host) > 253 || !preg_match('/\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z/D', $host) || preg_match('/(?:^|\.)[0-9]+\z/D', $host)) {
            throw new ValidationException('Host must be canonical ASCII DNS or IPv4.', 'url.host');
        }
        foreach (explode('.', $host) as $label) {
            if (strlen($label) > 63 || !preg_match('/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/D', $label)) { throw new ValidationException('DNS label is invalid.', 'url.host'); }
        }
        return $host;
    }
    public static function originValue(string $value): string
    {
        $uri = self::parse($value);
        if (!preg_match('/\Ahttps?:\/\/[^\/?#]+\/?\z/iD', $value) || $uri->path() !== '/' || $uri->values()[1] !== null) { throw new ValidationException('An origin has no path or query.', 'url.origin'); }
        return $uri->origin();
    }
    public function scheme(): string { return $this->scheme; }
    public function hostName(): string { return $this->host; }
    public function port(): int { return $this->port; }
    public function path(): string { return $this->values()[0]; }
    public function origin(): string
    {
        $host = strpos($this->host, ':') === false ? $this->host : '[' . $this->host . ']';
        $default = $this->scheme === 'https' ? 443 : 80;
        return $this->scheme . '://' . $host . ($this->port === $default ? '' : ':' . $this->port);
    }
    public function target(): string
    {
        $values = $this->values();
        return $values[0] . ($values[1] === null ? '' : '?' . $values[1]);
    }
    public function url(): string
    {
        $values = $this->values();
        return $this->origin() . $this->target() . ($values[2] === null ? '' : '#' . $values[2]);
    }
    public function withoutFragment(): self
    {
        $values = $this->values(); $values[2] = null; $copy = clone $this;
        $copy->read = static function () use ($values): array { return $values; };
        return $copy;
    }
    public function resolve(string $reference): self
    {
        self::safeText($reference);
        if (preg_match('/\A[A-Za-z][A-Za-z0-9+.-]*:/', $reference)) { return self::parse($reference, true); }
        if (substr($reference, 0, 2) === '//') { return self::parse($this->scheme . ':' . $reference, true); }
        if ($reference[0] === '#') { return self::parse($this->origin() . $this->target() . $reference, true); }
        if ($reference[0] === '?') { return self::parse($this->origin() . $this->path() . $reference, true); }
        $path = $reference[0] === '/' ? $reference : substr($this->path(), 0, (int) strrpos($this->path(), '/') + 1) . $reference;
        return self::parse($this->origin() . $path, true);
    }
    private function values(): array
    {
        if (!$this->read instanceof \Closure) {
            throw new ConfigurationException('Rebuild URI values from explicit input.', 'configuration.uri_serialization');
        }
        return ($this->read)();
    }
    public function __debugInfo(): array { return ['uri' => '[redacted]']; }
    public function __sleep(): array
    {
        throw new ConfigurationException('Rebuild URI values from explicit input.', 'configuration.uri_serialization');
    }
    public function __wakeup(): void
    {
        throw new ConfigurationException('Rebuild URI values from explicit input.', 'configuration.uri_serialization');
    }
    private static function safeText(string $value): void
    {
        if ($value === '' || strlen($value) > 2048 || preg_match('/[\x00-\x20\x7f-\xff\\\\<>"`]/', $value)
            || preg_match('/%(?![a-f0-9]{2})/i', $value) || preg_match('/%(?:0[0-9a-f]|1[0-9a-f]|7f|5c)/i', $value)) {
            throw new ValidationException('URI contains unsafe or ambiguous bytes.', 'url.invalid');
        }
    }
    private static function dots(string $path): string
    {
        $parts = [];
        foreach (explode('/', $path) as $part) {
            if ($part === '..') { if (count($parts) > 1) { array_pop($parts); } }
            elseif ($part !== '.') { $parts[] = $part; }
        }
        $result = implode('/', $parts);
        if (substr($path, -2) === '/.' || substr($path, -3) === '/..') { $result .= '/'; }
        return $result === '' ? '/' : $result;
    }
}
