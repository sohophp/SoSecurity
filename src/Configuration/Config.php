<?php
declare(strict_types=1);
namespace SoSecurity\Configuration;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Http\Cookie;
use SoSecurity\Password\PasswordHasher;
use SoSecurity\Password\PasswordPolicy;
use SoSecurity\RateLimit\Policy;
use SoSecurity\Support\Guard;

/** Validated configuration, with no environment lookup, session lifecycle or connection side effects. */
final class Config
{
    private $site;
    private $storage;
    private $tokens;
    private $csrf;
    private $captcha;
    private $limits;
    private $password;
    private $session;

    public function __construct(array $config)
    {
        self::known($config, ['site', 'storage', 'token_storage', 'csrf', 'captcha', 'rate_limits', 'password', 'session']);
        $this->site = self::text($config['site'] ?? null, 'site');
        Guard::label($this->site);
        if (strlen($this->site) > 128) { throw new ConfigurationException('Site identifier must be at most 128 bytes.'); }
        $this->storage = array_key_exists('storage', $config) ? self::store(self::map($config['storage'], 'storage')) : null;
        $this->tokens = self::store(self::map(self::provided($config, 'token_storage', ['driver' => 'session']), 'token_storage'));
        if ($this->tokens['driver'] === 'session') { Guard::sessionKey('_sosecurity_' . $this->site . ':tokens'); }
        Guard::sessionKey('_sosecurity_session_' . $this->site);
        $this->csrf = self::options(self::provided($config, 'csrf', []), ['ttl' => 7200, 'capacity' => 16], 'csrf');
        Guard::duration(self::integer($this->csrf['ttl'], 'csrf.ttl'));
        self::range($this->csrf['capacity'], 1, 64, 'csrf.capacity');
        $this->captcha = self::options(self::provided($config, 'captcha', []), ['ttl' => 300, 'attempts' => 3, 'capacity' => 4], 'captcha');
        Guard::duration(self::integer($this->captcha['ttl'], 'captcha.ttl'));
        self::range($this->captcha['attempts'], 1, 10, 'captcha.attempts');
        self::range($this->captcha['capacity'], 1, 16, 'captcha.capacity');
        $limits = self::map(self::provided($config, 'rate_limits', ['default' => []]), 'rate_limits');
        if (count($limits) > 64) { throw new ConfigurationException('Too many rate policies.'); }
        $this->limits = [];
        foreach ($limits as $name => $options) {
            if (!is_string($name)) { throw new ConfigurationException('Rate policy names must be strings.'); }
            Guard::label($name);
            $options = self::options($options, ['limit' => 5, 'window' => 300, 'bans' => [60, 300, 900], 'history_ttl' => 86400], 'rate_limits.' . $name);
            if (!is_array($options['bans'])) { throw new ConfigurationException('Ban durations must be an array.'); }
            $this->limits[$name] = new Policy(self::integer($options['limit'], 'limit'), self::integer($options['window'], 'window'),
                $options['bans'], self::integer($options['history_ttl'], 'history_ttl'));
        }
        $this->password = self::options(self::provided($config, 'password', []), ['profile' => 'bcrypt', 'options' => [], 'minimum' => 15, 'maximum_bytes' => 72], 'password');
        if (!is_array($this->password['options'])) { throw new ConfigurationException('Password options must be an array.'); }
        // Validate the selected native profile without hashing or installing an extension.
        new PasswordHasher(self::text($this->password['profile'], 'password.profile'), $this->password['options']);
        new PasswordPolicy(self::integer($this->password['minimum'], 'password.minimum'), self::integer($this->password['maximum_bytes'], 'password.maximum_bytes'));
        $session = self::map(self::provided($config, 'session', []), 'session');
        self::known($session, ['idle', 'absolute', 'secure', 'same_site', 'path', 'domain', 'lifetime']);
        foreach (['path', 'domain'] as $field) {
            if (array_key_exists($field, $session) && !is_string($session[$field])) {
                throw new ConfigurationException('Cookie path and domain must be strings.');
            }
        }
        $this->session = $session + ['idle' => 1800, 'absolute' => 28800, 'secure' => true, 'same_site' => 'Lax'];
        Guard::duration(self::integer($this->session['idle'], 'session.idle'));
        Guard::duration(self::integer($this->session['absolute'], 'session.absolute'));
        if (!is_bool($this->session['secure'])) { throw new ConfigurationException('Session secure must be bool.'); }
        Cookie::header('session', '', self::text($session['path'] ?? '/', 'session.path'), $this->session['secure'], true,
            self::text($this->session['same_site'], 'session.same_site'), isset($session['lifetime']) ? self::integer($session['lifetime'], 'session.lifetime') : null,
            isset($session['domain']) && $session['domain'] !== '' ? self::text($session['domain'], 'session.domain') : null);
        // Copy scalar option values into independent arrays; caller-owned array references must not mutate configuration.
        $this->csrf = self::copy($this->csrf); $this->captcha = self::copy($this->captcha);
        $this->password = self::copy($this->password); $this->session = self::copy($this->session);
    }

    public function site(): string { return $this->site; }
    public function storage(): ?array { return $this->storage; }
    public function tokenStorage(): array { return $this->tokens; }
    public function csrf(): array { return $this->csrf; }
    public function captcha(): array { return $this->captcha; }
    public function password(): array { return $this->password; }
    public function session(): array { return $this->session; }
    public function policy(string $name): Policy
    {
        if (!isset($this->limits[$name])) { throw new ConfigurationException('Unknown rate policy.', 'configuration.unknown_policy'); }
        return $this->limits[$name];
    }
    public function __set(string $name, $value): void { throw new ConfigurationException('Configuration is immutable.', 'configuration.immutable'); }

    private static function store(array $options): array
    {
        $driver = self::text($options['driver'] ?? null, 'storage.driver');
        $schemas = ['session' => [], 'memory' => [], 'file' => ['directory', 'lock_timeout_ms'],
            'redis' => ['connection', 'budget_ms', 'attempts'], 'provided' => ['connection']];
        if (!isset($schemas[$driver])) { throw new ConfigurationException('Unknown storage driver.', 'configuration.driver'); }
        self::known($options, array_merge(['driver'], $schemas[$driver]));
        if ($driver === 'file') {
            self::text($options['directory'] ?? null, 'storage.directory');
            self::range($options['lock_timeout_ms'] ?? 1000, 1, 30000, 'storage.lock_timeout_ms');
        }
        if ($driver === 'redis' || $driver === 'provided') { self::text($options['connection'] ?? null, 'storage.connection'); }
        if ($driver === 'redis') {
            self::range($options['budget_ms'] ?? 1000, 1, 30000, 'storage.budget_ms');
            self::range($options['attempts'] ?? 32, 1, 128, 'storage.attempts');
        }
        return self::copy($options);
    }
    private static function provided(array $data, string $name, $default) { return array_key_exists($name, $data) ? $data[$name] : $default; }
    private static function options($options, array $defaults, string $name): array
    {
        $options = self::map($options, $name); self::known($options, array_keys($defaults));
        return $options + $defaults;
    }
    private static function known(array $data, array $keys): void
    {
        if (array_diff(array_keys($data), $keys)) { throw new ConfigurationException('Unknown configuration option.', 'configuration.unknown_option'); }
    }
    private static function map($value, string $name): array
    {
        if (!is_array($value)) { throw new ConfigurationException('Expected an array for ' . $name . '.'); }
        return $value;
    }
    private static function text($value, string $name): string
    {
        if (!is_string($value) || $value === '' || strlen($value) > 4096 || preg_match('/[\x00-\x1f\x7f]/', $value)) {
            throw new ConfigurationException('Expected a non-empty string for ' . $name . '.');
        }
        return $value;
    }
    private static function integer($value, string $name): int
    {
        if (!is_int($value)) { throw new ConfigurationException('Expected an integer for ' . $name . '.'); }
        return $value;
    }
    private static function range($value, int $min, int $max, string $name): void
    {
        $value = self::integer($value, $name);
        if ($value < $min || $value > $max) { throw new ConfigurationException('Value is outside its range for ' . $name . '.'); }
    }
    private static function copy(array $value): array
    {
        $copy = [];
        foreach ($value as $key => $item) { $copy[$key] = is_array($item) ? self::copy($item) : $item; }
        return $copy;
    }
}
