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
    public function __debugInfo(): array { return ['site'=>$this->config->site(),'services'=>'[redacted]','stores'=>'[redacted]']; }
    public function csrf(): Csrf\CsrfTokens
    {
        $options = $this->config->csrf();
        return new Csrf\CsrfTokens($this->store('tokens'), $options['ttl'], $options['capacity'], $this->clock);
    }
    public function csrfPolicy(): Csrf\RequestPolicy { return new Csrf\RequestPolicy($this->config->csrf()['exemptions']); }
    public function signedCsrf(): Csrf\SignedTokens
    {
        $options=$this->config->statelessCsrf();
        if ($options===null) { throw new ConfigurationException('Configure signed CSRF keys explicitly.','configuration.stateless_csrf'); }
        $keys=$this->services[$options['keys']] ?? null;
        if (!$keys instanceof Support\HmacKeys) { throw new ConfigurationException('Inject private HmacKeys.','configuration.keys'); }
        return new Csrf\SignedTokens($keys,$this->config->site(),$options['ttl'],$this->clock);
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
    public function budgetLimiter(string $name): RateLimit\BudgetLimiter
    {
        $policy = $this->config->budgetPolicy($name);
        return new RateLimit\BudgetLimiter($this->apiStore(), $policy, $this->clock);
    }
    public function leases(): Concurrency\LeaseManager
    {
        $policy = $this->config->leasePolicy();
        if ($policy === null) { throw new ConfigurationException('Configure leases explicitly.', 'configuration.lease'); }
        return new Concurrency\LeaseManager($this->apiStore(), $policy, $this->clock);
    }
    public function budgetGroup(array $names): RateLimit\BudgetGroup
    {
        return new RateLimit\BudgetGroup($this->apiStore(), $this->budgetPolicies($names), $this->clock);
    }
    public function budgetComposite(array $names): RateLimit\CompositeLimiter
    {
        $policies = $this->budgetPolicies($names); $limits = [];
        foreach ($policies as $name => $policy) { $limits[$name] = new RateLimit\BudgetLimiter($this->apiStore(), $policy, $this->clock); }
        return new RateLimit\CompositeLimiter($limits, $this->clock);
    }
    private function budgetPolicies(array $names): array
    {
        if (!$names || count($names) > 8 || array_values($names) !== $names) { throw new ConfigurationException('Select 1-8 named budget policies.', 'configuration.budget'); }
        $policies = [];
        foreach ($names as $name) {
            if (!is_string($name) || isset($policies[$name])) { throw new ConfigurationException('Budget policy names must be unique strings.', 'configuration.budget'); }
            $policies[$name] = $this->config->budgetPolicy($name);
        }
        return $policies;
    }
    public function mfa(): Mfa\TotpFactors
    {
        $options = $this->config->mfa();
        if ($options === null) { throw new ConfigurationException('Configure MFA explicitly.', 'configuration.mfa'); }
        $store = $this->store('shared');
        if (!$this->shared($store)) { throw new ConfigurationException('MFA requires shared atomic storage.', 'configuration.shared_store'); }
        $cipher = $this->services[$options['cipher']] ?? null;
        if (!$cipher instanceof Crypto\Cipher) { throw new ConfigurationException('Inject a purpose-specific Cipher for MFA.', 'configuration.mfa_cipher'); }
        return new Mfa\TotpFactors($store, $cipher, $options['issuer'], $this->clock, $options['enrollment_ttl'], $options['attempts'],
            $options['cooldown'], new Mfa\Totp($options['algorithm'], $options['digits'], $options['period']));
    }
    public function sessions(): Auth\SessionRegistry
    {
        $options = $this->authOptions();
        return new Auth\SessionRegistry($this->apiStore(), $this->identityProvider(), $this->authFactor(), $this->clock,
            $options['idle'], $options['absolute'], $options['capacity']);
    }
    public function authentication(): Auth\AuthenticationFlow
    {
        $options = $this->authOptions();
        $guard = $options['request_guard'] === null ? null : ($this->services[$options['request_guard']] ?? null);
        if (!is_callable($guard)) { throw new ConfigurationException('Inject a request guard confirming CSRF and request budgets.', 'configuration.authentication_guard'); }
        return new Auth\AuthenticationFlow($this->apiStore(), $this->identityProvider(), $this->sessions(), $guard, $this->authFactor(), $this->clock,
            $options['challenge_ttl'], $options['claim_seconds'], $options['attempts']);
    }
    public function rememberedLogin(): Auth\RememberedLogin
    {
        $options = $this->config->remember(); $auth = $this->authOptions();
        if ($options === null) { throw new ConfigurationException('Opt in to persistent login explicitly.', 'configuration.remember'); }
        $keys = $this->services[$options['keys']] ?? null;
        $guard = $auth['request_guard'] === null ? null : ($this->services[$auth['request_guard']] ?? null);
        $riskGuard = $options['risk_guard'] === null ? null : ($this->services[$options['risk_guard']] ?? null);
        if (!$keys instanceof Support\HmacKeys) { throw new ConfigurationException('Inject independent persistent-login HmacKeys.', 'configuration.remember_keys'); }
        if (!is_callable($guard)) { throw new ConfigurationException('Inject a persistent-login request guard.', 'configuration.authentication_guard'); }
        if ($options['risk_guard'] !== null && !is_callable($riskGuard)) { throw new ConfigurationException('Inject a trusted-device risk guard.', 'configuration.device_risk'); }
        return new Auth\RememberedLogin($this->apiStore(), $this->identityProvider(), $this->sessions(), $keys, $guard, $this->authFactor(), $this->clock,
            $options['ttl'], $options['capacity'], $options['fresh_age'], $options['concurrency_grace'], $riskGuard);
    }
    public function rememberCookieHeader(Auth\RememberCredential $credential): string
    {
        $options = $this->config->remember();
        if ($options === null) { throw new ConfigurationException('Configure persistent cookies.', 'configuration.remember'); }
        return $this->rememberedLogin()->cookieHeader($credential, $options['cookie_name'], $options['secure'], $options['path']);
    }
    public function clearRememberCookieHeader(): string
    {
        $options = $this->config->remember();
        if ($options === null) { throw new ConfigurationException('Configure persistent cookies.', 'configuration.remember'); }
        return $this->rememberedLogin()->clearCookieHeader($options['cookie_name'], $options['secure'], $options['path']);
    }
    private function authOptions(): array
    {
        $options = $this->config->authentication();
        if ($options === null) { throw new ConfigurationException('Configure authentication explicitly.', 'configuration.authentication'); }
        return $options;
    }
    private function identityProvider(): Auth\IdentityProvider
    {
        $options = $this->authOptions(); $provider = $this->services[$options['identity_provider']] ?? null;
        if (!$provider instanceof Auth\IdentityProvider) { throw new ConfigurationException('Inject an IdentityProvider.', 'configuration.identity_provider'); }
        return $provider;
    }
    private function authFactor(): ?Auth\SecondFactor
    {
        $options = $this->authOptions();
        if ($options['managed_factors']) { return $this->managedSecondFactor(); }
        if ($options['second_factor'] === null) { return $this->config->mfa() === null ? null : new Auth\TotpSecondFactor($this->mfa()); }
        $factor = $this->services[$options['second_factor']] ?? null;
        if (!$factor instanceof Auth\SecondFactor) { throw new ConfigurationException('Inject a SecondFactor adapter.', 'configuration.second_factor'); }
        return $factor;
    }
    public function authorization(): Authorization\Authorizer
    {
        $options = $this->config->authorization();
        if ($options === null) { throw new ConfigurationException('Configure authorization explicitly.', 'configuration.authorization'); }
        $identities = $this->services[$options['identity_provider']] ?? null;
        $policy = $options['policy'] === null ? null : ($this->services[$options['policy']] ?? null);
        $audit = $options['audit'] === null ? null : ($this->services[$options['audit']] ?? null);
        if (!$identities instanceof Auth\IdentityProvider) { throw new ConfigurationException('Inject an authorization identity provider.', 'configuration.authorization_identity'); }
        if ($options['policy'] !== null && !$policy instanceof Authorization\PolicyProvider) { throw new ConfigurationException('Inject a policy provider.', 'configuration.authorization_policy'); }
        if ($options['audit'] !== null && !$audit instanceof Audit\AuditLogger) { throw new ConfigurationException('Inject an authorization audit logger.', 'configuration.authorization_audit'); }
        return new Authorization\Authorizer($identities, $policy, $audit);
    }
    public function operations(): Operation\Grants
    {
        $options=$this->config->operations();
        if ($options===null) { throw new ConfigurationException('Configure operation grants explicitly.','configuration.operation'); }
        $guard=$this->services[$options['request_guard']] ?? null;
        if (!is_callable($guard)) { throw new ConfigurationException('Inject an operation request guard.','configuration.operation_guard'); }
        $policy=new Operation\Policy($options['ttl'],$options['capacity'],$options['maximum_age'],$options['minimum_strength'],$options['methods']);
        return new Operation\Grants($this->apiStore(),$this->sessions(),$this->authorization(),$guard,$policy,$this->clock);
    }
    public function signedLinks(): Link\Links
    {
        $options=$this->config->signedLinks();
        if($options===null){throw new ConfigurationException('Configure signed links explicitly.','configuration.link');}
        $keys=$this->services[$options['keys']] ?? null;$guard=$this->services[$options['request_guard']] ?? null;
        if(!$keys instanceof Support\HmacKeys){throw new ConfigurationException('Inject independent signed-link HmacKeys.','configuration.link_keys');}
        if(!is_callable($guard)){throw new ConfigurationException('Inject a signed-link request guard.','configuration.link_guard');}
        $policy=new Link\Policy($options['origin'],$options['ttl'],$options['maximum_ttl'],$options['capacity'],$options['allow_http']);
        return new Link\Links($this->apiStore(),$keys,$this->config->site(),$policy,$guard,$this->clock);
    }
    public function downloads(): Download\Downloads
    {
        $options=$this->config->downloads();if($options===null){throw new ConfigurationException('Configure private downloads explicitly.','configuration.download');}
        return new Download\Downloads($options['directory'],$options['temporary_directory'],$options['document_root'],new Download\Policy($options['policy']),$this->clock);
    }
    public function resetTokens(int $ttl = 1800): Password\ResetTokens
    {
        $store = $this->store('shared');
        if (!$this->shared($store)) {
            throw new ConfigurationException('Password recovery needs shared state across sessions.', 'configuration.shared_store');
        }
        return new Password\ResetTokens($store, $ttl, $this->clock);
    }

    /** Lost-mailbox recovery requires explicit current authority and independent strong approval. */
    public function mailboxRecovery():Account\MailboxRecovery
    {
        list($options,$services)=$this->accountDependencies();$guard=$options['mailbox_authority']===null?null:($this->services[$options['mailbox_authority']] ?? null);$approval=$options['mailbox_approval']===null?null:($this->services[$options['mailbox_approval']] ?? null);
        $factor=$options['recovery_factor']===null?null:($this->services[$options['recovery_factor']] ?? null);
        if(!is_callable($guard)||!is_callable($approval)||!$services['repository'] instanceof Account\IdentityRepository||($options['recovery_factor']!==null&&!$factor instanceof Auth\SecondFactor)){throw new ConfigurationException('Configure independent mailbox authority, strong approval and current identity mapping.','configuration.account_mailbox_recovery');}
        return new Account\MailboxRecovery($services['connection'],$this->config->site(),$options['scope'],$options['epoch'],$services['integrity_keys'],$services['outbox_keys'],$services['repository'],$services['notifications'],$guard,$services['request_budget'],$approval,new Account\Policy($options['policy']),$this->clock,$services['management_guard'],$services['delivery_guard'],$factor);
    }
    public function passwordHasher(): Password\PasswordHasher
    {
        $options = $this->config->password(); return new Password\PasswordHasher($options['profile'], $options['options']);
    }
    public function passwordPolicy(): Password\PasswordPolicy
    {
        $options = $this->config->password();
        $blocklist = $options['blocklist'] === 'builtin' ? Password\PasswordBlocklist::baseline()
            : ($options['blocklist'] === null ? null : ($this->services[$options['blocklist']] ?? null));
        if ($options['blocklist'] !== null && !$blocklist instanceof Password\PasswordBlocklist) { throw new ConfigurationException('Inject a PasswordBlocklist snapshot.', 'configuration.password_blocklist'); }
        $checker = $options['breach_checker'] === null ? null : ($this->services[$options['breach_checker']] ?? null);
        if ($options['breach_checker'] !== null && !is_callable($checker)) { throw new ConfigurationException('Inject an explicit password breach checker.', 'configuration.password_breach'); }
        return Password\PasswordPolicy::forHasher($this->passwordHasher(), $options['minimum'], $options['maximum_bytes'], $blocklist, $checker);
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
    public function apiCredentials(): Api\CredentialRegistry
    {
        $options=$this->config->apiCredentials();if($options===null){throw new ConfigurationException('Configure managed API credentials explicitly.','configuration.api_credentials');}
        $keys=$this->services[$options['keys']] ?? null;$guard=$this->services[$options['request_guard']] ?? null;$scopes=$this->services[$options['scope_provider']] ?? null;
        if(!$keys instanceof Support\HmacKeys){throw new ConfigurationException('Inject independent managed-credential HMAC keys.','configuration.api_credential_keys');}
        if(!is_callable($guard)||!is_callable($scopes)){throw new ConfigurationException('Inject managed-credential request/scope providers.','configuration.api_credential_provider');}
        $management=$options['management_authorization']===null?null:($this->services[$options['management_authorization']] ?? null);$subject=$options['management_subject']===null?null:($this->services[$options['management_subject']] ?? null);
        if($options['management_authorization']!==null&&(!$management instanceof Authorization\Authorizer||!is_callable($subject))){throw new ConfigurationException('Inject delegated operator resolution and Authorizer.','configuration.api_credential_management');}
        return new Api\CredentialRegistry($this->apiStore(),$this->sessions(),$this->identityProvider(),$keys,$this->config->site(),$guard,$scopes,new Api\CredentialPolicy($options['policy']),$this->clock,$this->authFactor(),$management,$subject);
    }
    private function webhookOptions(string $name):array
    {
        $options=$this->config->webhooks();if(!isset($options[$name])){throw new ConfigurationException('Configure the named webhook endpoint explicitly.','configuration.webhook_name');}return $options[$name];
    }
    public function webhook(string $name):Webhook\Verifier
    {
        $options=$this->webhookOptions($name);if($options['key_provider']===null){throw new ConfigurationException('This endpoint is configured for historical processing only.','configuration.webhook_provider');}$keys=$this->services[$options['key_provider']] ?? null;$guard=$this->services[$options['request_guard']] ?? null;
        if(!is_callable($keys)||!is_callable($guard)){throw new ConfigurationException('Inject webhook key authority and request protection.','configuration.webhook_provider');}
        if($options['protocol']==='standard-ed25519'&&(!extension_loaded('sodium')||!function_exists('sodium_crypto_sign_verify_detached'))){throw new \SoSecurity\Exception\DependencyException('Ed25519 webhook verification requires ext-sodium.','dependency.sodium');}
        return new Webhook\Verifier(new Webhook\Endpoint($name,$options['scope'],$options['account'],$options['url'],$options['protocol'],$options['policy']),$keys,$guard,$this->clock);
    }
    public function webhookInbox(string $name):Webhook\SqlInbox
    {
        $options=$this->webhookOptions($name);if($options['inbox']===null){throw new ConfigurationException('Configure durable webhook receive explicitly.','configuration.webhook_inbox');}$inbox=$options['inbox'];$connection=$this->services[$inbox['connection']] ?? null;$keys=$this->services[$inbox['integrity_keys']] ?? null;$guard=$this->services[$inbox['association_guard']] ?? null;
        if(!$connection instanceof \PDO||!$keys instanceof Support\HmacKeys||!is_callable($guard)){throw new ConfigurationException('Inject webhook PDO, independent integrity keys and current association guard.','configuration.webhook_inbox');}
        return new Webhook\SqlInbox($connection,$this->config->site(),$this->webhook($name),$keys,$guard,$this->clock);
    }
    /** Historical receipt processing does not fetch publisher keys or require its verification extension. */
    public function webhookProcessor(string $name):Webhook\SqlProcessor
    {
        $options=$this->webhookOptions($name);$processing=$options['processing'];
        if($processing===null){throw new ConfigurationException('Configure durable webhook processing explicitly.','configuration.webhook_processing');}
        $connection=$this->services[$processing['connection']] ?? null;$keys=$this->services[$processing['integrity_keys']] ?? null;
        $mapper=$this->services[$processing['mapper']] ?? null;$association=$this->services[$processing['association_guard']] ?? null;$worker=$this->services[$processing['worker_guard']] ?? null;
        $management=$processing['management_guard']===null?null:($this->services[$processing['management_guard']] ?? null);
        if(!$connection instanceof \PDO||!$keys instanceof Support\HmacKeys||!is_callable($mapper)||!is_callable($association)||!is_callable($worker)||($processing['management_guard']!==null&&!is_callable($management))){throw new ConfigurationException('Inject processing PDO, receipt integrity keys and explicit processing authorities.','configuration.webhook_processing');}
        $endpoint=new Webhook\Endpoint($name,$options['scope'],$options['account'],$options['url'],$options['protocol'],$options['policy']);
        return new Webhook\SqlProcessor($connection,$this->config->site(),$endpoint,$keys,$mapper,$association,$worker,new Webhook\ProcessingPolicy($processing['policy']),$this->clock,$management);
    }
    public function idempotency():Idempotency\SqlExecutor
    {
        $options=$this->config->idempotency();if($options===null){throw new ConfigurationException('Configure SQL idempotency explicitly.','configuration.idempotency');}
        $connection=$this->services[$options['connection']] ?? null;$keys=$this->services[$options['integrity_keys']] ?? null;$authority=$this->services[$options['authority']] ?? null;$management=$options['management_guard']===null?null:($this->services[$options['management_guard']] ?? null);
        if(!$connection instanceof \PDO||!$keys instanceof Support\HmacKeys||!is_callable($authority)||($options['management_guard']!==null&&!is_callable($management))){throw new ConfigurationException('Inject idempotency PDO, independent integrity keys and current authorities.','configuration.idempotency');}
        return new Idempotency\SqlExecutor($connection,$this->config->site(),$options['epoch'],$keys,$authority,new Idempotency\Policy($options['policy']),$this->clock,$management);
    }
    public function outbox():Outbox\SqlOutbox
    {
        $options=$this->config->outbox();if($options===null){throw new ConfigurationException('Configure SQL outbox explicitly.','configuration.outbox');}
        $connection=$this->services[$options['connection']] ?? null;$keys=$this->services[$options['integrity_keys']] ?? null;$authority=$this->services[$options['authority']] ?? null;$management=$options['management_guard']===null?null:($this->services[$options['management_guard']] ?? null);
        if(!$connection instanceof \PDO||!$keys instanceof Support\HmacKeys||!is_callable($authority)||($options['management_guard']!==null&&!is_callable($management))){throw new ConfigurationException('Inject outbox PDO, independent integrity keys and current authorities.','configuration.outbox');}
        return new Outbox\SqlOutbox($connection,$this->config->site(),$options['epoch'],$keys,$authority,new Outbox\Policy($options['policy']),$this->clock,$management);
    }
    /** Explicit registered MFA directory. Construction never provisions fences, ledgers or account state. */
    public function accountFactors():Account\FactorRegistry
    {
        $options=$this->config->accountFactors();if($options===null){throw new ConfigurationException('Configure the managed factor directory explicitly.','configuration.account_factor');}
        $services=[];foreach(['connection','repository','integrity_keys','totp','fence','worker_guard','read_guard','management_guard'] as $name){$services[$name]=$this->services[$options[$name]]??null;}
        if(!$services['connection'] instanceof \PDO||!$services['repository'] instanceof Account\FactorRepository||!$services['integrity_keys'] instanceof Support\HmacKeys||!$services['totp'] instanceof Mfa\TotpFactors||!$services['fence'] instanceof Account\LocalEpochFence){throw new ConfigurationException('Inject the exact PDO, factor repository, keys, raw TOTP and worker fence.','configuration.account_factor');}
        foreach(['worker_guard','read_guard','management_guard'] as $name){if(!is_callable($services[$name])){throw new ConfigurationException('Inject explicit current factor authorities.','configuration.account_factor');}}
        $policy=new Account\Policy($options['policy']);$workers=new Account\FactorWorkerAuthority($services['connection'],$this->config->site(),$options['scope'],$options['epoch'],$services['integrity_keys'],$services['fence'],$services['worker_guard'],$policy,$this->clock);
        $managed=$services['totp']->managedRegistered($this->config->site(),$options['scope'],$options['epoch'],$services['integrity_keys'],$services['fence'],$workers);
        return new Account\FactorRegistry($services['connection'],$this->config->site(),$options['scope'],$options['epoch'],$services['integrity_keys'],$services['repository'],$managed,$services['read_guard'],$services['management_guard'],$policy,$this->clock,$services['fence']);
    }
    /** Resolve the same registered directory for authentication; never fall back to raw TOTP. */
    public function managedSecondFactor():Auth\SecondFactor
    {
        return new Account\ManagedSecondFactor($this->accountFactors());
    }
    /** Explicit account services; constructors never install schemas, initialize ledgers or send notifications. */
    private function accountDependencies():array
    {
        $options=$this->config->accounts();if($options===null){throw new ConfigurationException('Configure account lifecycle services explicitly.','configuration.accounts');}
        $values=[];foreach(['connection','repository','integrity_keys','outbox_keys','notifications','request_budget'] as $name){$values[$name]=$this->services[$options[$name]] ?? null;}
        if(!$values['connection'] instanceof \PDO||!$values['repository'] instanceof Account\Repository||!$values['integrity_keys'] instanceof Support\HmacKeys||!$values['outbox_keys'] instanceof Support\HmacKeys||!$values['notifications'] instanceof Account\Notifications||!$values['request_budget'] instanceof Account\RequestBudgets){throw new ConfigurationException('Inject account PDO, repository, independent keys, notifications and formal request budgets.','configuration.accounts_dependencies');}
        $values['request_budget']->validateConfiguration($this->config->site(),$this->clock);$values['notifications']->validateConfiguration($this->clock,$options['policy']['smtp_utf8']);
        foreach(['management_guard','delivery_guard'] as $name){$values[$name]=$options[$name]===null?null:($this->services[$options[$name]] ?? null);if($options[$name]!==null&&!is_callable($values[$name])){throw new ConfigurationException('Inject an explicit account management/delivery authority.','configuration.accounts_authority');}}
        return [$options,$values];
    }
    public function registration():Account\Registration
    {
        list($options,$services)=$this->accountDependencies();$guard=$options['registration_authority']===null?null:($this->services[$options['registration_authority']] ?? null);
        if(!is_callable($guard)){throw new ConfigurationException('Enable registration with its own current authority.','configuration.account_registration');}
        return new Account\Registration($services['connection'],$this->config->site(),$options['scope'],$options['epoch'],$services['integrity_keys'],$services['outbox_keys'],$services['repository'],$services['notifications'],$this->passwordHasher(),$this->passwordPolicy(),$guard,$services['request_budget'],new Account\Policy($options['policy']),$this->clock,$services['management_guard'],$services['delivery_guard']);
    }
    public function addressChange():Account\AddressChange
    {
        list($options,$services)=$this->accountDependencies();$guard=$options['request_guard']===null?null:($this->services[$options['request_guard']] ?? null);
        if(!is_callable($guard)||!$services['repository'] instanceof Account\IdentityRepository){throw new ConfigurationException('Enable address changes with current identity mapping and its own request guard.','configuration.account_address_change');}
        return new Account\AddressChange($services['connection'],$this->config->site(),$options['scope'],$options['epoch'],$services['integrity_keys'],$services['outbox_keys'],$services['repository'],$services['notifications'],$this->sessions(),$this->operations(),$guard,$services['request_budget'],new Account\Policy($options['policy']),$this->clock,$services['management_guard'],$services['delivery_guard']);
    }
    /** Recovery changes only the password; MFA binding/approval and worker permission remain explicit. */
    public function recovery():Account\Recovery
    {
        list($options,$services)=$this->accountDependencies();$guard=$options['recovery_authority']===null?null:($this->services[$options['recovery_authority']] ?? null);
        $factor=$options['recovery_factor']===null?null:($this->services[$options['recovery_factor']] ?? null);$strong=$options['strong_recovery']===null?null:($this->services[$options['strong_recovery']] ?? null);
        if(!is_callable($guard)||!$services['repository'] instanceof Account\IdentityRepository||($options['recovery_factor']!==null&&!$factor instanceof Auth\SecondFactor)||($options['strong_recovery']!==null&&!is_callable($strong))){throw new ConfigurationException('Configure independent recovery authority, current identity mapping and explicit factor/strong approval dependencies.','configuration.account_recovery');}
        return new Account\Recovery($services['connection'],$this->config->site(),$options['scope'],$options['epoch'],$services['integrity_keys'],$services['outbox_keys'],$services['repository'],$services['notifications'],$this->passwordHasher(),$this->passwordPolicy(),$guard,$services['request_budget'],new Account\Policy($options['policy']),$this->clock,$services['management_guard'],$services['delivery_guard'],$factor,$strong);
    }
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
    public function quarantine(): Upload\Quarantine
    {
        $options = $this->config->uploadQuarantine();
        if ($options === null) { throw new ConfigurationException('Configure upload quarantine explicitly.', 'configuration.quarantine'); }
        $scanner = $this->services[$options['scanner']] ?? null;
        if (!$scanner instanceof Upload\Scanner) { throw new ConfigurationException('Inject a Scanner adapter.', 'configuration.scanner'); }
        $storage = $this->config->storage();
        if ($storage !== null && $storage['driver'] === 'file') {
            $statePath = realpath($storage['directory']); $web = realpath($options['document_root']);
            if ($statePath !== false && $web !== false) {
                if (DIRECTORY_SEPARATOR === '\\') { $statePath = strtolower($statePath); $web = strtolower($web); }
                if ($statePath === $web || strpos($statePath, rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0) {
                    throw new ConfigurationException('Quarantine metadata must be outside the Web root.', 'configuration.web_root');
                }
            }
        }
        $scope = Support\Guard::key('factory-upload-quarantine', $this->config->site(), $options['scope']);
        return new Upload\Quarantine($this->apiStore(), new Upload\Policy($options['policy']), $scanner,
            $options['directory'], $options['document_root'], $scope, $options['queue'], $this->clock);
    }
    public function htmlCleaner(): Output\HtmlCleaner
    {
        $options=$this->config->html();
        if ($options===null) { throw new ConfigurationException('Opt in to reviewed rich-text cleaning.','configuration.html'); }
        $sanitizer=isset($options['sanitizer']) ? ($this->services[$options['sanitizer']] ?? null) : new Output\HtmlPurifierSanitizer($options['allow_links']);
        if (!$sanitizer instanceof Output\HtmlSanitizer) { throw new ConfigurationException('Inject a reviewed HtmlSanitizer.','configuration.html_sanitizer'); }
        return new Output\HtmlCleaner($sanitizer,new Output\HtmlPolicy(array_diff_key($options,['sanitizer'=>true])));
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
