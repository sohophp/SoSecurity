<?php
declare(strict_types=1);
namespace SoSecurity;

use SoSecurity\Configuration\Config;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\RedisStore;
use SoSecurity\Storage\SessionStore;
use SoSecurity\Support\Clock;
use SoSecurity\Support\SystemClock;

/** Optional lazy factory. Individual component classes remain independent public APIs. */
final class Security
{
    private $config;
    private $clock;
    private $services;
    private $stores = [];

    private function __construct(Config $config, array $services, Clock $clock)
    {
        $this->config = $config; $this->services = []; $this->clock = $clock;
        foreach ($services as $name => $service) { $this->services[$name] = $service; }
    }
    public static function fromArray(array $config, array $services = [], ?Clock $clock = null): self
    {
        return new self(new Config($config), $services, $clock ?? new SystemClock());
    }
    public function config(): Config { return $this->config; }
    public function csrf(): Csrf\CsrfTokens
    {
        $options = $this->config->csrf();
        return new Csrf\CsrfTokens($this->store('tokens'), $options['ttl'], $options['capacity'], $this->clock);
    }
    public function captcha(): Captcha\Captcha
    {
        $options = $this->config->captcha();
        return new Captcha\Captcha($this->store('tokens'), $options['ttl'], $options['attempts'], $options['capacity'], $this->clock);
    }
    public function rateLimiter(string $policy = 'default'): RateLimit\RateLimiter
    {
        $store = $this->store('shared');
        if (!$this->shared($store)) {
            throw new ConfigurationException('Cross-session limiting needs a shared atomic backend.', 'configuration.shared_store');
        }
        return new RateLimit\RateLimiter($store, $this->config->policy($policy), $this->clock);
    }
    public function resetTokens(int $ttl = 1800): Password\ResetTokens
    {
        $store = $this->store('shared');
        if (!$this->shared($store)) {
            throw new ConfigurationException('Password recovery needs shared state across sessions.', 'configuration.shared_store');
        }
        return new Password\ResetTokens($store, $ttl, $this->clock);
    }
    public function passwordHasher(): Password\PasswordHasher
    {
        $options = $this->config->password(); return new Password\PasswordHasher($options['profile'], $options['options']);
    }
    public function passwordPolicy(): Password\PasswordPolicy
    {
        $options = $this->config->password(); return new Password\PasswordPolicy($options['minimum'], $options['maximum_bytes']);
    }
    public function outbound(): Http\Outbound\Client
    {
        $options = $this->config->outbound();
        if ($options === null) { throw new ConfigurationException('Configure exact outbound hosts.', 'configuration.outbound'); }
        $resolver = isset($options['resolver']) ? ($this->services[$options['resolver']] ?? null) : null;
        $transport = isset($options['transport']) ? ($this->services[$options['transport']] ?? null) : null;
        if (isset($options['resolver']) && !$resolver instanceof Http\Outbound\Resolver) { throw new ConfigurationException('Inject a bounded Resolver.', 'configuration.resolver'); }
        if (isset($options['transport']) && !$transport instanceof Http\Outbound\Transport) { throw new ConfigurationException('Inject a pinned Transport.', 'configuration.transport'); }
        return new Http\Outbound\Client(new Http\Outbound\Policy(array_diff_key($options, array_flip(['resolver','transport']))), $resolver, $transport);
    }
    public function apiKeys(): Api\ApiKeys { return new Api\ApiKeys($this->apiStore(), $this->clock); }
    public function hmacSigner(Api\SigningKey $key): Api\HmacSigner { return new Api\HmacSigner($this->apiPolicy(), $key, $this->clock); }
    public function hmacVerifier(): Api\HmacVerifier
    {
        $policy = $this->apiPolicy(); $options = $this->config->api();
        $provider = isset($options['key_provider']) ? ($this->services[$options['key_provider']] ?? null) : null;
        if (!$provider instanceof Api\KeyProvider) { throw new ConfigurationException('Inject a signing KeyProvider.','configuration.key_provider'); }
        return new Api\HmacVerifier($policy, $provider, new Api\NonceStore($this->apiStore(), $this->clock), $this->clock);
    }
    private function apiPolicy(): Api\SignaturePolicy
    {
        $options = $this->config->api();
        if ($options === null) { throw new ConfigurationException('Configure a trusted signature origin.','configuration.api'); }
        return new Api\SignaturePolicy(array_diff_key($options, ['key_provider'=>true]));
    }
    private function apiStore(): AtomicStore
    {
        $store = $this->store('shared');
        if (!$this->shared($store)) { throw new ConfigurationException('API credentials and replay protection need shared atomic storage.','configuration.shared_store'); }
        return $store;
    }
    public function uploader(): Upload\Saver
    {
        $options = $this->config->upload();
        if ($options === null) { throw new ConfigurationException('Configure private upload storage.', 'configuration.upload'); }
        $scanner = isset($options['scanner']) ? ($this->services[$options['scanner']] ?? null) : null;
        if (isset($options['scanner']) && !$scanner instanceof Upload\Scanner) { throw new ConfigurationException('Inject a Scanner adapter.', 'configuration.scanner'); }
        $policy = new Upload\Policy(array_diff_key($options, array_flip(['directory', 'document_root', 'scanner'])));
        return new Upload\Saver(new Upload\Validator($policy), $options['directory'], $options['document_root'], $scanner);
    }
    public function session(): Session\SessionSecurity
    {
        $options = $this->config->session();
        return new Session\SessionSecurity($options['idle'], $options['absolute'], $this->config->site(), $this->clock);
    }
    /** Explicit host action; factory construction does not call this or start a session. */
    public function configureSession(): void
    {
        $options = $this->config->session();
        $overrides = array_intersect_key($options, array_flip(['path', 'domain', 'lifetime']));
        Session\SessionSecurity::configure($options['secure'], $options['same_site'], $overrides);
    }
    public function sessionCookieHeader(): string
    {
        $options = $this->config->session();
        return Session\SessionSecurity::cookieHeader($options['secure'], $options['same_site']);
    }
    public function diagnose(?string $documentRoot = null, bool $probe = false): array
    {
        return (new Diagnostics\Inspector())->inspect($this->config, $this->services, $documentRoot, $probe);
    }
    /** Explicit trusted deployment action. No request handler calls initialization automatically. */
    public function initializeStorage(bool $recover = false): array
    {
        $results = [];
        foreach (['shared' => $this->config->storage(), 'tokens' => $this->config->tokenStorage()] as $kind => $options) {
            if ($options !== null && $options['driver'] === 'redis') {
                $store = $this->store($kind);
                $results[$kind] = $store instanceof RedisStore && $store->initialize($recover) ? 'initialized' : 'unchanged';
            } elseif ($options !== null && $options['driver'] === 'mysql') {
                $pdo = $this->services[$options['connection']] ?? null;
                if (!$pdo instanceof \PDO) { throw new ConfigurationException('Inject a PDO MySQL connection.', 'configuration.connection'); }
                Storage\MySqlStore::install($pdo); $results[$kind] = 'schema_verified';
            } else { $results[$kind] = 'not_required'; }
        }
        return $results;
    }
    private function shared(AtomicStore $store): bool
    {
        while ($store instanceof Storage\NamespacedStore) { $store = $store->underlying(); }
        return !$store instanceof MemoryStore && !$store instanceof SessionStore;
    }
    private function store(string $kind): AtomicStore
    {
        if (isset($this->stores[$kind])) { return $this->stores[$kind]; }
        $options = $kind === 'tokens' ? $this->config->tokenStorage() : $this->config->storage();
        if ($options === null) { throw new ConfigurationException('Configure shared storage before using this module.', 'configuration.missing_store'); }
        $namespace = $this->config->site() . ':' . $kind;
        switch ($options['driver']) {
            case 'session': $store = new SessionStore($namespace, $this->clock); break;
            case 'memory': $store = new MemoryStore($this->clock); break;
            case 'file': $store = new FileStore($options['directory'], $namespace, $this->clock, $options['lock_timeout_ms'] ?? 1000); break;
            case 'redis':
                $redis = $this->services[$options['connection']] ?? null;
                if (!$redis instanceof \Redis) { throw new ConfigurationException('Inject a connected phpredis client.', 'configuration.connection'); }
                $store = new RedisStore($redis, $namespace, $this->clock, $options['budget_ms'] ?? 1000, $options['attempts'] ?? 32); break;
            case 'mysql':
                $pdo = $this->services[$options['connection']] ?? null;
                if (!$pdo instanceof \PDO) { throw new ConfigurationException('Inject a PDO MySQL connection.', 'configuration.connection'); }
                $store = new Storage\MySqlStore($pdo, $namespace, $this->clock, $options['lock_wait_seconds'] ?? 1); break;
            default:
                $store = $this->services[$options['connection']] ?? null;
                if (!$store instanceof AtomicStore) { throw new ConfigurationException('Inject an AtomicStore.', 'configuration.connection'); }
                // Custom backend must own its physical site namespace; the wrapper scopes logical keys.
                $store = new Storage\NamespacedStore($store, $namespace);
        }
        $this->stores[$kind] = $store;
        return $store;
    }
}
