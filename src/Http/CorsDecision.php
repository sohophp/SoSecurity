<?php
declare(strict_types=1);
namespace SoSecurity\Http;

final class CorsDecision
{
    private $allowed;
    private $status;
    private $headers;
    private $reason;
    public function __construct(bool $allowed, int $status, array $headers, string $reason)
    {
        $this->allowed = $allowed; $this->status = $status; $this->headers = $headers; $this->reason = $reason;
    }
    public function allowed(): bool { return $this->allowed; }
    public function status(): int { return $this->status; }
    public function headers(): array { return $this->headers; }
    public function reason(): string { return $this->reason; }
}
