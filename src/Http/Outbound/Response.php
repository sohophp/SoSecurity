<?php
declare(strict_types=1);
namespace SoSecurity\Http\Outbound;

use SoSecurity\Exception\ConfigurationException;

final class Response
{
    private $status;
    private $read;
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
        $this->status = $status; $this->read = static function () use ($copy, $body): array { return [$copy, $body]; };
        $this->peer = $peer; $this->headerBytes = max($bytes, $wireHeaderBytes ?? 0);
    }
    private function data(): array
    {
        if (!($this->read instanceof \Closure)) { throw new ConfigurationException('Reload external HTTP responses.', 'configuration.outbound_serialization'); }
        return ($this->read)();
    }
    public function status(): int { return $this->status; }
    public function headers(): array { return $this->data()[0]; }
    public function values(string $name): array { return $this->headers()[strtolower($name)] ?? []; }
    public function body(): string { return $this->data()[1]; }
    public function peer(): string { return $this->peer; }
    public function headerBytes(): int { return $this->headerBytes; }
    public function __debugInfo(): array { return ['status'=>$this->status, 'headers'=>'[redacted]', 'body'=>'[redacted]', 'peer'=>$this->peer]; }
    public function __sleep(): array { throw new ConfigurationException('Do not cache external HTTP responses.', 'configuration.outbound_serialization'); }
    public function __wakeup(): void { throw new ConfigurationException('Reload external HTTP responses.', 'configuration.outbound_serialization'); }
}
