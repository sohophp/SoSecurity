<?php
declare(strict_types=1);
namespace SoSecurity\Http\Outbound;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Http\Uri;

final class Policy
{
    private $options;
    public function __construct(array $options)
    {
        $defaults = ['hosts'=>[], 'ports'=>[443], 'allow_http'=>false, 'budget_ms'=>5000, 'redirects'=>3,
            'request_bytes'=>65536, 'response_bytes'=>1048576, 'header_bytes'=>16384];
        if (array_diff(array_keys($options), array_keys($defaults))) { throw new ConfigurationException('Unknown outbound policy option.'); }
        $options += $defaults;
        if (!is_array($options['hosts']) || !$options['hosts'] || count($options['hosts']) > 64 || !is_array($options['ports']) || !$options['ports'] || count($options['ports']) > 16) {
            throw new ConfigurationException('Provide exact bounded outbound host/port allowlists.');
        }
        $hosts = [];
        foreach ($options['hosts'] as $host) {
            if (!is_string($host)) { throw new ConfigurationException('Outbound hosts must be strings.'); }
            try { $hosts[] = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? inet_ntop(inet_pton($host)) : Uri::host($host); }
            catch (ValidationException $e) { throw new ConfigurationException('Invalid outbound host allowlist.', 'configuration.outbound', $e); }
        }
        foreach ($hosts as $host) { if (filter_var($host, FILTER_VALIDATE_IP) === false && (strpos($host, '.') === false || substr($host, -10) === '.localhost')) { throw new ConfigurationException('Outbound DNS hosts must be fixed fully qualified names.'); } }
        $ports = [];
        foreach ($options['ports'] as $port) { if (!is_int($port) || $port < 1 || $port > 65535) { throw new ConfigurationException('Invalid outbound port.'); } $ports[] = $port; }
        if (!is_bool($options['allow_http'])) { throw new ConfigurationException('HTTP opt-in must be boolean.'); }
        foreach (['budget_ms'=>[1,30000], 'redirects'=>[0,5], 'request_bytes'=>[0,1048576], 'response_bytes'=>[0,20971520], 'header_bytes'=>[256,65536]] as $name=>$range) {
            if (!is_int($options[$name]) || $options[$name] < $range[0] || $options[$name] > $range[1]) { throw new ConfigurationException('Invalid outbound resource limit.'); }
        }
        $this->options = ['hosts'=>array_values(array_unique($hosts)), 'ports'=>array_values(array_unique($ports))];
        foreach ($options as $name=>$value) { if ($name !== 'hosts' && $name !== 'ports') { $this->options[$name] = $value; } }
    }
    public function options(): array { return $this->options; }
    public function budgetMs(): int { return $this->options['budget_ms']; }
    public function redirects(): int { return $this->options['redirects']; }
    public function requestBytes(): int { return $this->options['request_bytes']; }
    public function responseBytes(): int { return $this->options['response_bytes']; }
    public function headerBytes(): int { return $this->options['header_bytes']; }
    public function check(Uri $uri): void
    {
        if (($uri->scheme() !== 'https' && !$this->options['allow_http']) || !in_array($uri->hostName(), $this->options['hosts'], true) || !in_array($uri->port(), $this->options['ports'], true)) {
            throw new ValidationException('Outbound target is not explicitly approved.', 'http.target');
        }
    }
    public function __set(string $name, $value): void { throw new ConfigurationException('Outbound policy is immutable.', 'configuration.immutable'); }
}
