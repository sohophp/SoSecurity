<?php
declare(strict_types=1);
namespace SoSecurity\Password;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\ValidationException;

/** Optional HIBP SHA-1 range checker. Only a five-character prefix leaves this component. */
final class PwnedPasswords
{
    private $transport;
    private $timeout;
    public function __construct(?callable $rangeTransport = null, int $timeoutMs = 3000)
    {
        if ($timeoutMs < 500 || $timeoutMs > 10000) { throw new ConfigurationException('Breach transport timeout must be 500-10000ms.', 'configuration.password_breach'); }
        $this->transport = $rangeTransport; $this->timeout = $timeoutMs;
    }
    public function __invoke(string $password): bool
    {
        if ($password === '' || strlen($password) > 4096 || strpos($password, "\0") !== false || !preg_match('//u', $password)) {
            throw new ValidationException('Invalid breach-check password input.', 'password.input');
        }
        $digest = strtoupper(sha1($password)); $prefix = substr($digest, 0, 5); $suffix = substr($digest, 5);
        try {
            $body = $this->transport === null ? $this->request($prefix) : ($this->transport)($prefix, ['Add-Padding' => 'true', 'Accept' => 'text/plain']);
            return $this->match($body, $suffix);
        } catch (\Throwable $e) {
            // Never chain adapter/native errors: they may contain a password, full hash or dataset data.
            throw new DependencyException('Password breach check unavailable.', 'password.breach_unavailable');
        }
    }
    private function match($body, string $suffix): bool
    {
        if (!is_string($body) || $body === '' || strlen($body) > 262144) { throw new \RuntimeException('Invalid range response budget.'); }
        $lines = preg_split('/\r?\n/', $body);
        if (end($lines) === '') { array_pop($lines); }
        if (!$lines || count($lines) > 5000) { throw new \RuntimeException('Invalid range response count.'); }
        $seen = []; $matched = false;
        foreach ($lines as $line) {
            if (!preg_match('/\A([A-F0-9]{35}):(0|[1-9][0-9]{0,11})\z/D', $line, $parts) || isset($seen[$parts[1]])) { throw new \RuntimeException('Malformed range response.'); }
            $seen[$parts[1]] = true;
            if (hash_equals($suffix, $parts[1]) && $parts[2] !== '0') { $matched = true; }
        }
        return $matched; // Validate the entire body before returning, including after a matching row.
    }
    private function request(string $prefix): string
    {
        // Reuse pinned HTTPS and bounded DoH; OS resolver thread cleanup can outlive curl's transfer timeout.
        $client = new \SoSecurity\Http\Outbound\Client(new \SoSecurity\Http\Outbound\Policy([
            'hosts' => ['api.pwnedpasswords.com'], 'budget_ms' => $this->timeout, 'redirects' => 0,
            'request_bytes' => 0, 'response_bytes' => 262144, 'header_bytes' => 16384,
        ]));
        $response = $client->request('GET', 'https://api.pwnedpasswords.com/range/' . $prefix,
            ['add-padding' => 'true', 'accept' => 'text/plain', 'user-agent' => 'SoSecurity Pwned Passwords checker']);
        if ($response->status() !== 200) { throw new DependencyException('Breach transport failed.'); }
        return $response->body();
    }
    public function __debugInfo(): array { return ['breach_checker' => '[redacted]', 'timeout_ms' => $this->timeout]; }
    public function __sleep(): array { throw new ConfigurationException('Do not serialize breach transports.', 'configuration.password_breach'); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Breach checkers are immutable.', 'configuration.immutable'); }
}
