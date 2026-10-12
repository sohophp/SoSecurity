<?php
declare(strict_types=1);
namespace SoSecurity\Http\Outbound;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Http\Uri;
use SoSecurity\Http\RequestException;
use SoSecurity\Support\Deadline;

/** Explicit bounded Google-compatible JSON DoH service; bootstrap IP is pinned, never resolved natively. */
final class DohResolver implements Resolver
{
    private $transport;
    private $endpoint;
    private $bootstrap;
    public function __construct(?Transport $transport = null, string $endpoint = 'https://dns.google/resolve', string $bootstrap = '8.8.8.8')
    {
        try { $uri = Uri::parse($endpoint); } catch (\SoSecurity\Exception\ValidationException $e) { throw new ConfigurationException('Invalid configured DoH endpoint.', 'configuration.resolver', $e); }
        if ($uri->scheme() !== 'https' || $uri->port() !== 443 || strpos($uri->target(), '?') !== false || !PublicAddress::allows($bootstrap)) {
            throw new ConfigurationException('Configure a trusted HTTPS JSON DoH endpoint and public bootstrap pin.');
        }
        $this->endpoint = $uri->url(); $this->bootstrap = inet_ntop(inet_pton($bootstrap)); $this->transport = $transport ?? new CurlTransport();
    }
    public function resolve(string $host, Deadline $deadline): array
    {
        $host = Uri::host($host); $addresses = [];
        foreach ([1,28] as $type) {
            if ($deadline->remaining() <= 0) { throw new RequestException('DNS budget expired.', 'http.timeout'); }
            $uri = Uri::parse($this->endpoint . '?name=' . rawurlencode($host) . '&type=' . $type . '&edns_client_subnet=0.0.0.0%2F0');
            $response = $this->transport->send($uri, $this->bootstrap, 'GET', ['accept'=>'application/dns-json'], '', $deadline, 16384, 8192);
            if ($response->status() !== 200 || @inet_pton($response->peer()) !== @inet_pton($this->bootstrap) || strlen($response->body()) > 16384) { throw new RequestException('DoH service failed.', 'http.dns'); }
            $data = json_decode($response->body(), true, 12);
            $question = is_array($data) && isset($data['Question']) && is_array($data['Question']) && isset($data['Question'][0]) && is_array($data['Question'][0]) ? $data['Question'][0] : [];
            if (!is_array($data) || ($data['Status'] ?? null) !== 0 || (array_key_exists('TC', $data) && (!is_bool($data['TC']) || $data['TC']))
                || !isset($data['Question']) || !is_array($data['Question']) || count($data['Question']) !== 1
                || !isset($question['name']) || !is_string($question['name']) || strtolower(rtrim($question['name'], '.')) !== $host || ($question['type'] ?? null) !== $type) {
                throw new RequestException('Invalid or unsuccessful DNS response.', 'http.dns');
            }
            $answers = array_key_exists('Answer', $data) ? $data['Answer'] : [];
            if (!is_array($answers) || count($answers) > 64) { throw new RequestException('DNS answer limit exceeded.', 'http.dns'); }
            $aliases = []; $records = [];
            foreach ($answers as $answer) {
                if (!is_array($answer) || !isset($answer['name'],$answer['type'],$answer['data']) || !is_string($answer['name']) || !is_string($answer['data'])) { throw new RequestException('Invalid DNS record.', 'http.dns'); }
                $owner = strtolower(rtrim($answer['name'], '.'));
                if ($answer['type'] === 5) {
                    $alias = strtolower(rtrim($answer['data'], '.'));
                    try { Uri::host($alias); } catch (\SoSecurity\Exception\ValidationException $e) { throw new RequestException('Invalid CNAME target.', 'http.dns', $e); }
                    if (isset($aliases[$owner]) && $aliases[$owner] !== $alias) { throw new RequestException('Conflicting CNAME records.', 'http.dns'); }
                    $aliases[$owner] = $alias;
                } elseif ($answer['type'] === $type) { $records[$owner][] = $answer['data']; }
            }
            $owner = $host; $seen = [];
            while (isset($aliases[$owner])) {
                if (isset($seen[$owner]) || count($seen) >= 8) { throw new RequestException('CNAME chain is cyclic or too long.', 'http.dns'); }
                $seen[$owner] = true; $owner = $aliases[$owner];
            }
            foreach ($records[$owner] ?? [] as $address) {
                if (filter_var($address, FILTER_VALIDATE_IP, $type === 1 ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6) === false) { throw new RequestException('Invalid DNS address record.', 'http.dns'); }
                $addresses[] = inet_ntop(inet_pton($address));
            }
        }
        $addresses = array_values(array_unique($addresses));
        if (!$addresses || count($addresses) > 16) { throw new RequestException('No bounded final DNS addresses.', 'http.dns'); }
        return $addresses;
    }
}
