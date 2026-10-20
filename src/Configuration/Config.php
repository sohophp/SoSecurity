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
    private $upload;
    private $uploadQuarantine;
    private $outbound;
    private $api;
    private $statelessCsrf;
    private $html;
    private $mfa;
    private $authentication;
    private $remember;
    private $authorization;
    private $budgets;
    private $leases;
    private $operations;
    private $links;
    private $downloads;
    private $credentials;
    private $webhooks;
    private $idempotency;
    private $outbox;
    private $accounts;
    private $accountFactors;

    public function __construct(array $config)
    {
        self::known($config, ['site', 'storage', 'token_storage', 'csrf', 'stateless_csrf', 'captcha', 'rate_limits', 'password', 'session', 'upload', 'upload_quarantine', 'outbound', 'api', 'html', 'mfa', 'authentication', 'remember', 'authorization', 'budgets', 'leases', 'operations', 'signed_links', 'downloads', 'api_credentials', 'webhooks', 'idempotency', 'outbox', 'accounts', 'account_factors']);
        $this->site = self::text($config['site'] ?? null, 'site');
        Guard::label($this->site);
        if (strlen($this->site) > 128) { throw new ConfigurationException('Site identifier must be at most 128 bytes.'); }
        $this->storage = array_key_exists('storage', $config) ? self::store(self::map($config['storage'], 'storage')) : null;
        $this->tokens = self::store(self::map(self::provided($config, 'token_storage', ['driver' => 'session']), 'token_storage'));
        if ($this->tokens['driver'] === 'session') { Guard::sessionKey('_sosecurity_' . $this->site . ':tokens'); }
        Guard::sessionKey('_sosecurity_session_' . $this->site);
        $this->csrf = self::options(self::provided($config, 'csrf', []), ['ttl' => 7200, 'capacity' => 16, 'exemptions'=>[]], 'csrf');
        Guard::duration(self::integer($this->csrf['ttl'], 'csrf.ttl'));
        self::range($this->csrf['capacity'], 1, 64, 'csrf.capacity');
        if (!is_array($this->csrf['exemptions'])) { throw new ConfigurationException('CSRF exemptions must be an array.','configuration.csrf_exemptions'); }
        new \SoSecurity\Csrf\RequestPolicy($this->csrf['exemptions']);
        $this->statelessCsrf=null;
        if (array_key_exists('stateless_csrf',$config)) {
            $options=self::options($config['stateless_csrf'],['keys'=>null,'ttl'=>7200],'stateless_csrf');
            self::text($options['keys'],'stateless_csrf.keys'); self::range($options['ttl'],1,86400,'stateless_csrf.ttl');
            $this->statelessCsrf=self::copy($options);
        }
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
        $this->budgets = []; $budgets = self::map(self::provided($config, 'budgets', []), 'budgets');
        if (count($budgets) > 64) { throw new ConfigurationException('Too many request-budget policies.', 'configuration.budget'); }
        foreach ($budgets as $name => $options) {
            if (!is_string($name) || !preg_match('/\A[a-z][a-z0-9_-]{0,63}\z/D', $name)) { throw new ConfigurationException('Invalid request-budget name.', 'configuration.budget'); }
            $options = self::options($options, ['algorithm' => 'token_bucket', 'limit' => 10, 'window' => 60, 'burst' => null, 'maximum_entries' => 512], 'budgets.' . $name);
            $this->budgets[$name] = new \SoSecurity\RateLimit\BudgetPolicy(self::text($options['algorithm'], 'budget.algorithm'), self::integer($options['limit'], 'budget.limit'),
                self::integer($options['window'], 'budget.window'), $options['burst'] === null ? null : self::integer($options['burst'], 'budget.burst'), self::integer($options['maximum_entries'], 'budget.maximum_entries'));
        }
        $this->leases = null;
        if (array_key_exists('leases', $config)) {
            $options = self::options($config['leases'], ['maximum' => 1, 'ttl' => 30, 'maximum_lifetime' => 300], 'leases');
            $this->leases = new \SoSecurity\Concurrency\LeasePolicy(self::integer($options['maximum'], 'leases.maximum'), self::integer($options['ttl'], 'leases.ttl'), self::integer($options['maximum_lifetime'], 'leases.maximum_lifetime'));
        }
        $this->links=null;
        if (array_key_exists('signed_links',$config)) {
            $options=self::options($config['signed_links'],['keys'=>null,'request_guard'=>null,'origin'=>null,'ttl'=>300,'maximum_ttl'=>86400,'capacity'=>32,'allow_http'=>false],'signed_links');
            self::text($options['keys'],'signed_links.keys');self::text($options['request_guard'],'signed_links.request_guard');
            if(!is_bool($options['allow_http'])){throw new ConfigurationException('signed_links.allow_http must be bool.','configuration.link');}
            new \SoSecurity\Link\Policy(self::text($options['origin'],'signed_links.origin'),self::integer($options['ttl'],'signed_links.ttl'),self::integer($options['maximum_ttl'],'signed_links.maximum_ttl'),self::integer($options['capacity'],'signed_links.capacity'),$options['allow_http']);
            $this->links=self::copy($options);
        }
        $this->downloads=null;
        if(array_key_exists('downloads',$config)){
            $options=self::options($config['downloads'],['directory'=>null,'temporary_directory'=>null,'document_root'=>null,'policy'=>[]],'downloads');
            foreach(['directory','temporary_directory','document_root'] as $name){self::text($options[$name],'downloads.'.$name);}
            if(!is_array($options['policy'])){throw new ConfigurationException('Download policy must be an array.','configuration.download');}new \SoSecurity\Download\Policy($options['policy']);$this->downloads=self::copy($options);
        }
        $passwordInput = self::provided($config, 'password', []);
        $defaultMaximum = is_array($passwordInput) && ($passwordInput['profile'] ?? null) === 'argon2id' ? 4096 : 72;
        $this->password = self::options($passwordInput, ['profile' => 'bcrypt', 'options' => [], 'minimum' => 15, 'maximum_bytes' => $defaultMaximum,
            'blocklist' => 'builtin', 'breach_checker' => null], 'password');
        if (!is_array($this->password['options'])) { throw new ConfigurationException('Password options must be an array.'); }
        // Validate the selected native profile without hashing or installing an extension.
        $passwordHasher = new PasswordHasher(self::text($this->password['profile'], 'password.profile'), $this->password['options']);
        PasswordPolicy::forHasher($passwordHasher, self::integer($this->password['minimum'], 'password.minimum'), self::integer($this->password['maximum_bytes'], 'password.maximum_bytes'));
        foreach (['blocklist', 'breach_checker'] as $service) {
            if ($this->password[$service] !== null) { self::text($this->password[$service], 'password.' . $service); }
        }
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
            self::text($this->session['same_site'], 'session.same_site'), array_key_exists('lifetime', $session) ? self::integer($session['lifetime'], 'session.lifetime') : null,
            isset($session['domain']) && $session['domain'] !== '' ? self::text($session['domain'], 'session.domain') : null);
        $this->upload = null;
        if (array_key_exists('upload', $config)) {
            $upload = self::map($config['upload'], 'upload');
            $policyOptions = array_diff_key($upload, array_flip(['directory', 'document_root', 'scanner']));
            $policy = new \SoSecurity\Upload\Policy($policyOptions);
            self::text($upload['directory'] ?? null, 'upload.directory'); self::text($upload['document_root'] ?? null, 'upload.document_root');
            if (array_key_exists('scanner', $upload)) { self::text($upload['scanner'], 'upload.scanner'); }
            $this->upload = self::copy($upload + $policy->options());
        }
        $this->uploadQuarantine = null;
        if (array_key_exists('upload_quarantine', $config)) {
            $options = self::options($config['upload_quarantine'], ['directory' => null, 'document_root' => null,
                'scanner' => null, 'scope' => 'uploads', 'policy' => [], 'queue' => []], 'upload_quarantine');
            foreach (['directory', 'document_root', 'scanner', 'scope'] as $name) { self::text($options[$name], 'upload_quarantine.' . $name); }
            Guard::label($options['scope']);
            $policy = self::map($options['policy'], 'upload_quarantine.policy');
            if (array_key_exists('require_scan', $policy) && $policy['require_scan'] !== true) {
                throw new ConfigurationException('Quarantine always requires scanning.', 'configuration.quarantine');
            }
            $policy['require_scan'] = true;
            $options['policy'] = (new \SoSecurity\Upload\Policy($policy))->options();
            $options['queue'] = \SoSecurity\Upload\QuarantineState::options(self::map($options['queue'], 'upload_quarantine.queue'));
            $this->uploadQuarantine = self::copy($options);
        }
        $this->outbound = null;
        if (array_key_exists('outbound', $config)) {
            $outbound = self::map($config['outbound'], 'outbound');
            foreach (['resolver','transport'] as $service) { if (array_key_exists($service, $outbound)) { self::text($outbound[$service], 'outbound.' . $service); } }
            $policy = new \SoSecurity\Http\Outbound\Policy(array_diff_key($outbound, array_flip(['resolver','transport'])));
            $this->outbound = self::copy($outbound + $policy->options());
        }
        // Copy scalar option values into independent arrays; caller-owned array references must not mutate configuration.
        $this->api = null;
        if (array_key_exists('api', $config)) {
            $api = self::map($config['api'], 'api');
            if (array_key_exists('key_provider', $api)) { self::text($api['key_provider'], 'api.key_provider'); }
            $policy = new \SoSecurity\Api\SignaturePolicy(array_diff_key($api, ['key_provider'=>true]));
            $this->api = self::copy($api + $policy->options());
        }
        $this->csrf = self::copy($this->csrf); $this->captcha = self::copy($this->captcha);
        $this->password = self::copy($this->password); $this->session = self::copy($this->session);
        $this->html=null;
        if (array_key_exists('html',$config)) {
            $html=self::map($config['html'],'html');
            if (array_key_exists('sanitizer',$html)) { self::text($html['sanitizer'],'html.sanitizer'); }
            $policy=new \SoSecurity\Output\HtmlPolicy(array_diff_key($html,['sanitizer'=>true]));
            $this->html=self::copy($html+$policy->options());
        }
        $this->mfa = null;
        if (array_key_exists('mfa', $config)) {
            $options = self::options($config['mfa'], ['issuer' => null, 'cipher' => null, 'enrollment_ttl' => 300,
                'attempts' => 5, 'cooldown' => 60, 'algorithm' => 'sha1', 'digits' => 6, 'period' => 30], 'mfa');
            $issuer = self::text($options['issuer'], 'mfa.issuer'); Guard::label($issuer);
            if (strpos($issuer, ':') !== false) { throw new ConfigurationException('MFA issuer must not contain colons.', 'configuration.mfa'); }
            self::text($options['cipher'], 'mfa.cipher');
            self::range($options['enrollment_ttl'], 30, 900, 'mfa.enrollment_ttl');
            self::range($options['attempts'], 1, 10, 'mfa.attempts'); self::range($options['cooldown'], 1, 3600, 'mfa.cooldown');
            new \SoSecurity\Mfa\Totp(self::text($options['algorithm'], 'mfa.algorithm'), self::integer($options['digits'], 'mfa.digits'), self::integer($options['period'], 'mfa.period'));
            $this->mfa = self::copy($options);
        }
        $this->authentication = null;
        if (array_key_exists('authentication', $config)) {
            $options = self::options($config['authentication'], ['identity_provider' => null, 'request_guard' => null, 'second_factor' => null, 'managed_factors' => false,
                'idle' => 1800, 'absolute' => 28800, 'capacity' => 16, 'challenge_ttl' => 300, 'claim_seconds' => 10, 'attempts' => 5], 'authentication');
            self::text($options['identity_provider'], 'authentication.identity_provider');
            foreach (['request_guard', 'second_factor'] as $service) { if ($options[$service] !== null) { self::text($options[$service], 'authentication.' . $service); } }
            if (!is_bool($options['managed_factors']) || ($options['managed_factors'] && $options['second_factor'] !== null)) { throw new ConfigurationException('Select either the managed factor directory or one explicit second-factor service.','configuration.authentication_factor'); }
            Guard::duration(self::integer($options['idle'], 'authentication.idle')); Guard::duration(self::integer($options['absolute'], 'authentication.absolute'));
            if ($options['idle'] > $options['absolute']) { throw new ConfigurationException('Authentication idle timeout must not exceed absolute timeout.', 'configuration.authentication'); }
            self::range($options['capacity'], 1, 32, 'authentication.capacity'); self::range($options['challenge_ttl'], 30, 600, 'authentication.challenge_ttl');
            self::range($options['claim_seconds'], 1, 30, 'authentication.claim_seconds'); self::range($options['attempts'], 1, 10, 'authentication.attempts');
            $this->authentication = self::copy($options);
        }
        $this->authorization = null;
        if (array_key_exists('authorization', $config)) {
            $options = self::options($config['authorization'], ['identity_provider' => $this->authentication['identity_provider'] ?? null, 'policy' => null, 'audit' => null], 'authorization');
            self::text($options['identity_provider'], 'authorization.identity_provider');
            foreach (['policy', 'audit'] as $name) { if ($options[$name] !== null) { self::text($options[$name], 'authorization.' . $name); } }
            $this->authorization = self::copy($options);
        }
        $this->operations = null;
        if (array_key_exists('operations',$config)) {
            if ($this->authentication===null || $this->authorization===null) { throw new ConfigurationException('Configure authentication and authorization before operation grants.','configuration.operation'); }
            $options=self::options($config['operations'],['request_guard'=>$this->authentication['request_guard'],'ttl'=>120,'capacity'=>8,'maximum_age'=>300,'minimum_strength'=>2,'methods'=>['totp','webauthn']],'operations');
            self::text($options['request_guard'],'operations.request_guard');
            if (!is_array($options['methods'])) { throw new ConfigurationException('Operation methods must be an explicit list.','configuration.operation'); }
            $policy=new \SoSecurity\Operation\Policy(self::integer($options['ttl'],'operations.ttl'),self::integer($options['capacity'],'operations.capacity'),
                self::integer($options['maximum_age'],'operations.maximum_age'),self::integer($options['minimum_strength'],'operations.minimum_strength'),$options['methods']);
            $options['methods']=$policy->methods();$this->operations=self::copy($options);
        }
        $this->credentials=null;
        if(array_key_exists('api_credentials',$config)){
            if($this->authentication===null){throw new ConfigurationException('Configure authentication before managed API credentials.','configuration.api_credentials');}
            $options=self::options($config['api_credentials'],['keys'=>null,'request_guard'=>null,'scope_provider'=>null,'management_subject'=>null,'management_authorization'=>null,'policy'=>[]],'api_credentials');
            foreach(['keys','request_guard','scope_provider'] as $service){self::text($options[$service],'api_credentials.'.$service);}
            if(($options['management_subject']===null)!==($options['management_authorization']===null)){throw new ConfigurationException('Configure both delegated management services.','configuration.api_credential_management');}
            foreach(['management_subject','management_authorization'] as $service){if($options[$service]!==null){self::text($options[$service],'api_credentials.'.$service);}}
            if(!is_array($options['policy'])){throw new ConfigurationException('Managed API credential policy must be an array.','configuration.api_credentials');}$options['policy']=(new \SoSecurity\Api\CredentialPolicy($options['policy']))->options();$this->credentials=self::copy($options);
        }
        $this->webhooks=[];$endpoints=self::copy(self::map(self::provided($config,'webhooks',[]),'webhooks'));if(count($endpoints)>32){throw new ConfigurationException('Configure at most 32 webhook endpoints.','configuration.webhook');}
        foreach($endpoints as $name=>$definition){
            if(!is_string($name)||!preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$name)){throw new ConfigurationException('Invalid webhook endpoint name.','configuration.webhook');}
            $options=self::options($definition,['scope'=>null,'account'=>null,'url'=>null,'protocol'=>null,'key_provider'=>null,'request_guard'=>null,'policy'=>[],'inbox'=>null,'processing'=>null],'webhooks.'.$name);
            foreach(['scope','account','url','protocol'] as $field){self::text($options[$field],'webhooks.'.$name.'.'.$field);}
            if(!is_array($options['policy'])){throw new ConfigurationException('Webhook policy must be an array.','configuration.webhook');}
            $endpoint=new \SoSecurity\Webhook\Endpoint($name,$options['scope'],$options['account'],$options['url'],$options['protocol'],$options['policy']);$options['policy']=$endpoint->options();
            if($options['inbox']!==null){$inbox=self::options($options['inbox'],['connection'=>null,'integrity_keys'=>null,'association_guard'=>null],'webhooks.'.$name.'.inbox');foreach(['connection','integrity_keys','association_guard'] as $field){self::text($inbox[$field],'webhooks.'.$name.'.inbox.'.$field);}$options['inbox']=$inbox;}
            if(($options['key_provider']===null)!==($options['request_guard']===null)){throw new ConfigurationException('Configure receiving key authority and request protection together.','configuration.webhook_provider');}
            foreach(['key_provider','request_guard'] as $field){if($options[$field]!==null){self::text($options[$field],'webhooks.'.$name.'.'.$field);}}
            if($options['processing']!==null){
                $processing=self::options($options['processing'],['connection'=>null,'integrity_keys'=>null,'mapper'=>null,'association_guard'=>null,'worker_guard'=>null,'management_guard'=>null,'policy'=>[]],'webhooks.'.$name.'.processing');
                foreach(['connection','integrity_keys','mapper','association_guard','worker_guard'] as $field){self::text($processing[$field],'webhooks.'.$name.'.processing.'.$field);}
                if($processing['management_guard']!==null){self::text($processing['management_guard'],'webhooks.'.$name.'.processing.management_guard');}
                if(!is_array($processing['policy'])){throw new ConfigurationException('Processing policy must be an array.','configuration.webhook_processing');}
                $processing['policy']=(new \SoSecurity\Webhook\ProcessingPolicy($processing['policy']))->options();$options['processing']=$processing;
            }
            if($options['key_provider']===null&&($options['inbox']!==null||$options['processing']===null)){throw new ConfigurationException('Configure receiving protection, or an explicit worker-only processing endpoint.','configuration.webhook_provider');}
            $this->webhooks[$name]=self::copy($options);
        }
        $this->idempotency=null;
        if(array_key_exists('idempotency',$config)){
            $options=self::copy(self::options($config['idempotency'],['connection'=>null,'epoch'=>null,'integrity_keys'=>null,'authority'=>null,'management_guard'=>null,'policy'=>[]],'idempotency'));
            foreach(['connection','epoch','integrity_keys','authority'] as $field){self::text($options[$field],'idempotency.'.$field);}
            if(!preg_match('/\A[a-f0-9]{64}\z/D',$options['epoch'])){throw new ConfigurationException('Use a trusted deployment epoch.','configuration.idempotency');}
            if($options['management_guard']!==null){self::text($options['management_guard'],'idempotency.management_guard');}
            if(!is_array($options['policy'])){throw new ConfigurationException('Idempotency policy must be an array.','configuration.idempotency');}
            $options['policy']=(new \SoSecurity\Idempotency\Policy($options['policy']))->options();$this->idempotency=$options;
        }
        $this->outbox=null;
        if(array_key_exists('outbox',$config)){
            $options=self::copy(self::options($config['outbox'],['connection'=>null,'epoch'=>null,'integrity_keys'=>null,'authority'=>null,'management_guard'=>null,'policy'=>[]],'outbox'));
            foreach(['connection','epoch','integrity_keys','authority'] as $field){self::text($options[$field],'outbox.'.$field);}
            if(!preg_match('/\A[a-f0-9]{64}\z/D',$options['epoch'])){throw new ConfigurationException('Use a trusted external deployment epoch.','configuration.outbox');}
            if($options['management_guard']!==null){self::text($options['management_guard'],'outbox.management_guard');}
            if(!is_array($options['policy'])){throw new ConfigurationException('Outbox policy must be an array.','configuration.outbox');}
            $options['policy']=(new \SoSecurity\Outbox\Policy($options['policy']))->options();$this->outbox=$options;
        }
        $this->accounts=null;
        if(array_key_exists('accounts',$config)){
            $options=self::copy(self::options($config['accounts'],['connection'=>null,'scope'=>null,'epoch'=>null,'repository'=>null,'integrity_keys'=>null,'outbox_keys'=>null,'notifications'=>null,'request_budget'=>null,'registration_authority'=>null,'request_guard'=>null,'management_guard'=>null,'delivery_guard'=>null,'recovery_authority'=>null,'recovery_factor'=>null,'strong_recovery'=>null,'mailbox_authority'=>null,'mailbox_approval'=>null,'policy'=>[]],'accounts'));
            foreach(['connection','scope','epoch','repository','integrity_keys','outbox_keys','notifications','request_budget'] as $field){self::text($options[$field],'accounts.'.$field);}
            Guard::label($options['scope']);if(preg_match('//u',$options['scope'])!==1||!preg_match('/\A[a-f0-9]{64}\z/D',$options['epoch'])){throw new ConfigurationException('Use a UTF-8 account scope and an external trusted epoch.','configuration.accounts');}
            foreach(['registration_authority','request_guard','management_guard','delivery_guard','recovery_authority','recovery_factor','strong_recovery','mailbox_authority','mailbox_approval'] as $field){if($options[$field]!==null){self::text($options[$field],'accounts.'.$field);}}
            if($options['registration_authority']===null&&$options['request_guard']===null&&$options['recovery_authority']===null&&$options['mailbox_authority']===null){throw new ConfigurationException('Enable at least one explicit account operation authority.','configuration.accounts');}
            if($options['mailbox_authority']!==null&&$options['mailbox_approval']===null){throw new ConfigurationException('Mailbox recovery requires an explicit strong approval service.','configuration.account_mailbox_recovery');}
            if($options['request_guard']!==null&&($this->authentication===null||$this->operations===null)){throw new ConfigurationException('Account address changes require authentication and operation grants.','configuration.accounts_authentication');}
            if(!is_array($options['policy'])){throw new ConfigurationException('Account policy must be an explicit array.','configuration.account_policy');}
            $options['policy']=(new \SoSecurity\Account\Policy($options['policy']))->options();$this->accounts=$options;
        }
        $this->accountFactors=null;
        if(array_key_exists('account_factors',$config)){
            $options=self::copy(self::options($config['account_factors'],['connection'=>null,'scope'=>null,'epoch'=>null,'repository'=>null,'integrity_keys'=>null,'totp'=>null,'fence'=>null,'worker_guard'=>null,'read_guard'=>null,'management_guard'=>null,'policy'=>[]],'account_factors'));
            foreach(['connection','scope','epoch','repository','integrity_keys','totp','fence','worker_guard','read_guard','management_guard'] as $field){self::text($options[$field],'account_factors.'.$field);}
            Guard::label($options['scope']);if(preg_match('//u',$options['scope'])!==1||!preg_match('/\A[a-f0-9]{64}\z/D',$options['epoch'])){throw new ConfigurationException('Use a UTF-8 factor scope and external trusted epoch.','configuration.account_factor');}
            if(!is_array($options['policy'])){throw new ConfigurationException('Use an explicit factor lifecycle policy.','configuration.account_factor');}
            $options['policy']=(new \SoSecurity\Account\Policy($options['policy']))->options();$this->accountFactors=$options;
        }
        if ($this->authentication!==null && $this->authentication['managed_factors'] && $this->accountFactors===null) { throw new ConfigurationException('Managed authentication requires an explicit factor directory.','configuration.authentication_factor'); }
        if ($this->authentication!==null && $this->authentication['managed_factors'] && $this->mfa!==null) { throw new ConfigurationException('Managed authentication cannot expose the legacy raw MFA factory.','configuration.authentication_factor'); }
        $this->remember = null;
        if (array_key_exists('remember', $config)) {
            if ($this->authentication === null) { throw new ConfigurationException('Configure authentication before persistent login.', 'configuration.remember'); }
            $options = self::options($config['remember'], ['keys' => null, 'risk_guard' => null, 'ttl' => 2592000, 'capacity' => 8, 'fresh_age' => 300, 'concurrency_grace' => 5,
                'cookie_name' => '__Host-SoSecurityRemember', 'secure' => true, 'path' => '/'], 'remember');
            self::text($options['keys'], 'remember.keys'); Guard::duration(self::integer($options['ttl'], 'remember.ttl'));
            if ($options['risk_guard'] !== null) { self::text($options['risk_guard'], 'remember.risk_guard'); }
            self::range($options['capacity'], 1, 16, 'remember.capacity'); self::range($options['fresh_age'], 1, 3600, 'remember.fresh_age');
            self::range($options['concurrency_grace'], 0, 10, 'remember.concurrency_grace');
            if (!is_bool($options['secure'])) { throw new ConfigurationException('Persistent cookie secure must be bool.', 'configuration.remember'); }
            Cookie::header(self::text($options['cookie_name'], 'remember.cookie_name'), '', self::text($options['path'], 'remember.path'), $options['secure'], true, 'Lax', 0);
            $this->remember = self::copy($options);
        }
    }

    public function site(): string { return $this->site; }
    public function storage(): ?array { return $this->storage; }
    public function tokenStorage(): array { return $this->tokens; }
    public function csrf(): array { return $this->csrf; }
    public function statelessCsrf(): ?array { return $this->statelessCsrf; }
    public function html(): ?array { return $this->html; }
    public function mfa(): ?array { return $this->mfa; }
    public function authentication(): ?array { return $this->authentication; }
    public function remember(): ?array { return $this->remember; }
    public function authorization(): ?array { return $this->authorization; }
    public function operations(): ?array { return $this->operations; }
    public function signedLinks(): ?array { return $this->links; }
    public function downloads(): ?array { return $this->downloads; }
    public function apiCredentials(): ?array { return $this->credentials; }
    public function webhooks(): array { return $this->webhooks; }
    public function idempotency(): ?array { return $this->idempotency; }
    public function outbox(): ?array { return $this->outbox; }
    public function accounts(): ?array { return $this->accounts; }
    public function accountFactors(): ?array { return $this->accountFactors; }
    public function budgetPolicy(string $name): \SoSecurity\RateLimit\BudgetPolicy
    {
        if (!isset($this->budgets[$name])) { throw new ConfigurationException('Unknown request-budget policy.', 'configuration.budget_name'); }
        return $this->budgets[$name];
    }
    public function budgetPolicies(): array { return $this->budgets; }
    public function leasePolicy(): ?\SoSecurity\Concurrency\LeasePolicy { return $this->leases; }
    public function captcha(): array { return $this->captcha; }
    public function password(): array { return $this->password; }
    public function outbound(): ?array { return $this->outbound; }
    public function api(): ?array { return $this->api; }
    public function upload(): ?array { return $this->upload; }
    public function uploadQuarantine(): ?array { return $this->uploadQuarantine; }
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
            'redis' => ['connection', 'budget_ms', 'attempts'], 'mysql' => ['connection', 'lock_wait_seconds'], 'provided' => ['connection']];
        if (!isset($schemas[$driver])) { throw new ConfigurationException('Unknown storage driver.', 'configuration.driver'); }
        self::known($options, array_merge(['driver'], $schemas[$driver]));
        if ($driver === 'file') {
            self::text($options['directory'] ?? null, 'storage.directory');
            self::range(self::provided($options, 'lock_timeout_ms', 1000), 1, 30000, 'storage.lock_timeout_ms');
        }
        if (in_array($driver, ['redis', 'mysql', 'provided'], true)) { self::text($options['connection'] ?? null, 'storage.connection'); }
        if ($driver === 'mysql') { self::range(self::provided($options, 'lock_wait_seconds', 1), 1, 30, 'storage.lock_wait_seconds'); }
        if ($driver === 'redis') {
            self::range(self::provided($options, 'budget_ms', 1000), 1, 30000, 'storage.budget_ms');
            self::range(self::provided($options, 'attempts', 32), 1, 128, 'storage.attempts');
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
