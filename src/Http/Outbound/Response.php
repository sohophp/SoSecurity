<?php
declare(strict_types=1);
namespace SoSecurity\Http\Outbound;

use SoSecurity\Exception\ConfigurationException;

final class Response
{
    private $status;
    private $headers;
    private $body;
    private $peer;
    private $headerBytes;
    public function __construct(int $status, array $headers, string $body, string $peer, ?int $wireHeaderBytes = null)
    {
        if ($status < 100 || $status > 599) { throw new ConfigurationException('Invalid HTTP response status.'); }
        $copy = []; $bytes = 32;
        foreach ($headers as $name=>$values) {
            if (!is_string($name) || !preg_match('/\A[a-zA-Z0-9!#$%&\x27*+.^_`|~-]+\z/D', $name) || !is_array($values)) { throw new ConfigurationException('Invalid response header map.'); }
            foreach ($values as $value) {
                if (!is_string($value) || preg_match('/[\x00-\x08\x0a-\x1f\x7f]/', $value)) { throw new ConfigurationException('Invalid response header value.'); }
                $copy[strtolower($name)][] = $value; $bytes += strlen($name) + strlen($value) + 4;
            }
        }
        if ($wireHeaderBytes !== null && $wireHeaderBytes < 0) { throw new ConfigurationException('Invalid wire header count.'); }
        $this->status = $status; $this->headers = $copy; $this->body = $body; $this->peer = $peer; $this->headerBytes = max($bytes, $wireHeaderBytes ?? 0);
    }
    public function status(): int { return $this->status; }
    public function headers(): array { return $this->headers; }
    public function values(string $name): array { return $this->headers[strtolower($name)] ?? []; }
    public function body(): string { return $this->body; }
    public function peer(): string { return $this->peer; }
    public function headerBytes(): int { return $this->headerBytes; }
}
