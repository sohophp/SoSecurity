<?php
declare(strict_types=1);
namespace SoSecurity\Diagnostics;

use SoSecurity\Configuration\Config;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\SessionStore;
use SoSecurity\Storage\NamespacedStore;

/** Diagnostic results never contain connection objects, passwords, tokens, raw exception text or filesystem paths. */
final class Inspector
{
    public function inspect(Config $config, array $services = [], ?string $documentRoot = null, bool $probe = false): array
    {
        $checks = [['check' => 'configuration', 'status' => 'pass', 'reason' => 'configuration.valid']];
        foreach (['session', 'gd', 'curl', 'redis', 'pdo_mysql', 'fileinfo'] as $extension) {
            $checks[] = ['check' => 'extension.' . $extension, 'status' => extension_loaded($extension) ? 'pass' : 'optional',
                'reason' => extension_loaded($extension) ? 'dependency.available' : 'dependency.not_installed'];
        }
        foreach (['shared' => $config->storage(), 'tokens' => $config->tokenStorage()] as $kind => $options) {
            $name = 'storage.' . $kind;
            if ($options === null) { $checks[] = ['check' => $name, 'status' => 'not_configured', 'reason' => 'configuration.missing_store']; continue; }
            if ($options['driver'] === 'file') {
                $path = realpath($options['directory']);
                $valid = $path !== false && is_dir($path) && is_writable($path) && (fileperms($path) & 0077) === 0;
                $checks[] = ['check' => $name, 'status' => $valid ? 'pass' : 'fail', 'reason' => $valid ? 'storage.private_directory' : 'storage.directory'];
                $root = $documentRoot === null ? false : realpath($documentRoot);
                $public = $path !== false && $root !== false && ($path === $root || strpos($path, rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0);
                $checks[] = ['check' => $name . '.location', 'status' => $public ? 'fail' : ($root === false ? 'manual' : 'pass'),
                    'reason' => $public ? 'storage.web_root' : ($root === false ? 'storage.location_unverified' : 'storage.outside_web_root')];
            } elseif ($options['driver'] === 'session') {
                $active = extension_loaded('session') && session_status() === PHP_SESSION_ACTIVE;
                $checks[] = ['check' => $name, 'status' => $kind === 'shared' ? 'fail' : ($active ? 'pass' : 'manual'),
                    'reason' => $kind === 'shared' ? 'storage.not_shared' : ($active ? 'session.active' : 'session.host_must_start')];
                $checks[] = ['check' => $name . '.locking', 'status' => $active && ini_get('session.save_handler') === 'files' ? 'pass' : 'manual',
                    'reason' => $active && ini_get('session.save_handler') === 'files' ? 'session.native_files_lock' : 'session.locking_unverified'];
            } elseif ($options['driver'] === 'memory') {
                $checks[] = ['check' => $name, 'status' => 'fail', 'reason' => 'storage.test_only'];
            } elseif ($options['driver'] === 'provided') {
                $store = $services[$options['connection']] ?? null;
                while ($store instanceof NamespacedStore) { $store = $store->underlying(); }
                $unsafe = $store instanceof MemoryStore || ($kind === 'shared' && $store instanceof SessionStore);
                $valid = $store instanceof \SoSecurity\Storage\AtomicStore;
                $checks[] = ['check' => $name, 'status' => $unsafe || !$valid ? 'fail' : 'manual',
                    'reason' => $unsafe ? 'storage.not_shared' : (!$valid ? 'configuration.connection' : 'storage.custom_contract_unverified')];
            } elseif ($options['driver'] === 'mysql') {
                $pdo = $services[$options['connection']] ?? null;
                if (!$pdo instanceof \PDO || $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) !== 'mysql') {
                    $checks[] = ['check' => $name, 'status' => 'fail', 'reason' => 'configuration.connection']; continue;
                }
                if (!$probe) { $checks[] = ['check' => $name, 'status' => 'manual', 'reason' => 'storage.connection_unverified']; continue; }
                try {
                    new \SoSecurity\Storage\MySqlStore($pdo, $config->site() . ':' . $kind, null, $options['lock_wait_seconds'] ?? 1);
                    $checks[] = ['check' => $name, 'status' => 'pass', 'reason' => 'storage.schema_verified'];
                    $checks[] = ['check' => $name . '.network_timeout', 'status' => 'manual', 'reason' => 'storage.transport_timeout_unverified'];
                } catch (\SoSecurity\Exception\SecurityException $e) {
                    $checks[] = ['check' => $name, 'status' => 'fail', 'reason' => $e->reason()];
                } catch (\SoSecurity\Exception\ConfigurationException $e) {
                    $checks[] = ['check' => $name, 'status' => 'fail', 'reason' => $e->reason()];
                }
            } else {
                $redis = $services[$options['connection']] ?? null;
                if (!$redis instanceof \Redis) { $checks[] = ['check' => $name, 'status' => 'fail', 'reason' => 'configuration.connection']; continue; }
                if (!$probe) { $checks[] = ['check' => $name, 'status' => 'manual', 'reason' => 'storage.connection_unverified']; continue; }
                foreach ($this->redis($redis, $config->site() . ':' . $kind) as $item) { $item['check'] = $name . '.' . $item['check']; $checks[] = $item; }
            }
        }
        $upload = $config->upload();
        if ($upload === null) { $checks[] = ['check' => 'upload', 'status' => 'not_configured', 'reason' => 'configuration.upload']; }
        else {
            $needsImage = count(array_intersect($upload['extensions'], ['jpg', 'jpeg', 'png', 'webp'])) > 0;
            $ready = extension_loaded('fileinfo') && (!$needsImage || extension_loaded('gd'));
            $checks[] = ['check' => 'upload.inspection', 'status' => $ready ? 'pass' : 'fail',
                'reason' => $ready ? 'dependency.available' : (extension_loaded('fileinfo') ? 'dependency.gd' : 'dependency.fileinfo')];
            $path = realpath($upload['directory']); $root = realpath($upload['document_root']);
            $valid = $path !== false && is_dir($path) && is_writable($path) && (fileperms($path) & 0077) === 0;
            $checks[] = ['check' => 'upload.directory', 'status' => $valid ? 'pass' : 'fail', 'reason' => $valid ? 'storage.private_directory' : 'upload.directory'];
            $public = $path !== false && $root !== false && ($path === $root || strpos($path, rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0);
            $actual = $documentRoot === null ? false : realpath($documentRoot);
            $mismatch = $actual !== false && $root !== $actual;
            $checks[] = ['check' => 'upload.location', 'status' => $root === false || $public || $mismatch ? 'fail' : 'pass',
                'reason' => $root === false || $mismatch ? 'configuration.document_root' : ($public ? 'storage.web_root' : 'storage.outside_web_root')];
            $scanner = isset($upload['scanner']) ? ($services[$upload['scanner']] ?? null) : null;
            $checks[] = ['check' => 'upload.scanner', 'status' => $scanner instanceof \SoSecurity\Upload\Scanner ? 'manual' : ($upload['require_scan'] || isset($upload['scanner']) ? 'fail' : 'not_configured'),
                'reason' => $scanner instanceof \SoSecurity\Upload\Scanner ? 'upload.scanner_unverified' : 'configuration.scanner'];
        }
        $quarantine = $config->uploadQuarantine();
        if ($quarantine === null) { $checks[] = ['check' => 'quarantine', 'status' => 'not_configured', 'reason' => 'configuration.quarantine']; }
        else {
            $needsImage = count(array_intersect($quarantine['policy']['extensions'], ['jpg', 'jpeg', 'png', 'webp'])) > 0;
            $ready = extension_loaded('fileinfo') && (!$needsImage || extension_loaded('gd'));
            $checks[] = ['check' => 'quarantine.inspection', 'status' => $ready ? 'pass' : 'fail',
                'reason' => $ready ? 'dependency.available' : (extension_loaded('fileinfo') ? 'dependency.gd' : 'dependency.fileinfo')];
            try {
                new \SoSecurity\Upload\QuarantineFiles($quarantine['directory'], $quarantine['document_root'], new \SoSecurity\Upload\Policy($quarantine['policy']));
                $checks[] = ['check' => 'quarantine.directory', 'status' => 'pass', 'reason' => 'storage.private_directory'];
            } catch (\Throwable $failure) { $checks[] = ['check' => 'quarantine.directory', 'status' => 'fail', 'reason' => 'upload.quarantine_directory']; }
            $actual = $documentRoot === null ? false : realpath($documentRoot); $configured = realpath($quarantine['document_root']);
            $checks[] = ['check' => 'quarantine.document_root', 'status' => $configured === false || ($documentRoot !== null && ($actual === false || $actual !== $configured)) ? 'fail' : ($actual === false ? 'manual' : 'pass'),
                'reason' => $actual !== false && $actual === $configured ? 'storage.location_verified' : 'configuration.document_root'];
            $scanner = $services[$quarantine['scanner']] ?? null;
            $checks[] = ['check' => 'quarantine.scanner', 'status' => $scanner instanceof \SoSecurity\Upload\Scanner ? 'manual' : 'fail',
                'reason' => $scanner instanceof \SoSecurity\Upload\Scanner ? 'upload.scanner_unverified' : 'configuration.scanner'];
            $shared = array_column($checks, null, 'check')['storage.shared'];
            $status = in_array($shared['status'], ['fail', 'not_configured'], true) ? 'fail' : 'manual';
            foreach ($checks as $check) { if (strpos($check['check'], 'storage.shared.') === 0 && $check['status'] === 'fail') { $status = 'fail'; } }
            $checks[] = ['check' => 'quarantine.storage', 'status' => $status, 'reason' => $status === 'fail' ? 'configuration.shared_store' : 'storage.quarantine_persistence_unverified'];
            $checks[] = ['check' => 'quarantine.workflow', 'status' => 'manual', 'reason' => 'upload.quarantine_workflow_unverified'];
        }
        $outbound = $config->outbound();
        if ($outbound === null) { $checks[] = ['check'=>'outbound', 'status'=>'not_configured', 'reason'=>'configuration.outbound']; }
        else {
            $curl = extension_loaded('curl') && curl_version()['version_number'] >= 0x073900;
            $defaultNeeded = !isset($outbound['resolver']) || !isset($outbound['transport']);
            $checks[] = ['check'=>'outbound.curl', 'status'=>$defaultNeeded && !$curl ? 'fail' : ($defaultNeeded ? 'pass' : 'optional'),
                'reason'=>$curl ? 'dependency.available' : 'dependency.curl'];
            foreach (['resolver'=>\SoSecurity\Http\Outbound\Resolver::class, 'transport'=>\SoSecurity\Http\Outbound\Transport::class] as $kind=>$contract) {
                if (!isset($outbound[$kind])) { continue; }
                $service = $services[$outbound[$kind]] ?? null;
                $checks[] = ['check'=>'outbound.' . $kind, 'status'=>$service instanceof $contract ? 'manual' : 'fail',
                    'reason'=>$service instanceof $contract ? 'http.adapter_unverified' : 'configuration.' . $kind];
            }
            $checks[] = ['check'=>'outbound.network', 'status'=>'manual', 'reason'=>'http.network_unverified'];
        }
        if ($config->budgetPolicies()) {
            $checks[] = ['check' => 'budgets.bindings', 'status' => 'manual', 'reason' => 'rate.server_context_unverified'];
            $checks[] = ['check' => 'budgets.clock', 'status' => 'manual', 'reason' => 'rate.shared_clock_unverified'];
            $checks[] = ['check' => 'budgets.atomicity', 'status' => 'manual', 'reason' => 'rate.composition_scope_unverified'];
        }
        if ($config->leasePolicy() !== null) {
            $checks[] = ['check' => 'leases.provisioning', 'status' => 'manual', 'reason' => 'lease.ledger_recovery_unverified'];
            $checks[] = ['check' => 'leases.fencing', 'status' => 'manual', 'reason' => 'lease.host_fencing_unverified'];
            $checks[] = ['check' => 'leases.clock', 'status' => 'manual', 'reason' => 'lease.shared_clock_unverified'];
        }
        if($config->downloads()!==null){
            $options=$config->downloads();$web=realpath($options['document_root']);
            foreach(['directory','temporary_directory'] as $name){
                $path=realpath($options[$name]);$private=DIRECTORY_SEPARATOR==='/'&&$path!==false&&is_dir($path)&&!is_link($options[$name])&&$path===rtrim($options[$name],'/')&&(fileperms($path)&0077)===0;
                $outside=$path!==false&&$web!==false&&$path!==$web&&strpos($path,rtrim($web,'/').'/')!==0;
                $checks[]=['check'=>'downloads.'.$name,'status'=>$private&&$outside?'manual':'fail','reason'=>$private&&$outside?'download.local_storage_unverified':'configuration.download_directory'];
            }
            if($documentRoot!==null){$checks[]=['check'=>'downloads.document_root','status'=>$web!==false&&$web===realpath($documentRoot)?'pass':'fail','reason'=>$web!==false&&$web===realpath($documentRoot)?'download.web_root_matches':'configuration.document_root'];}
            foreach(['authorization','content_version','metadata_source','response_writer','global_quota'] as $name){$checks[]=['check'=>'downloads.'.$name,'status'=>'manual','reason'=>'download.'.$name.'_unverified'];}
        }
        if ($config->signedLinks()!==null) {
            $options=$config->signedLinks();$keys=$services[$options['keys']] ?? null;$guard=$services[$options['request_guard']] ?? null;
            $checks[]=['check'=>'signed_links.keys','status'=>$keys instanceof \SoSecurity\Support\HmacKeys?'manual':'fail','reason'=>$keys instanceof \SoSecurity\Support\HmacKeys?'link.key_lifecycle_unverified':'configuration.link_keys'];
            $checks[]=['check'=>'signed_links.request_guard','status'=>is_callable($guard)?'manual':'fail','reason'=>is_callable($guard)?'link.request_boundary_unverified':'configuration.link_guard'];
            $checks[]=['check'=>'signed_links.transport','status'=>strpos($options['origin'],'https://')===0?'manual':'fail','reason'=>strpos($options['origin'],'https://')===0?'link.transport_unverified':'link.local_http_only'];
            $checks[]=['check'=>'signed_links.resource','status'=>'manual','reason'=>'link.current_resource_unverified'];
            $checks[]=['check'=>'signed_links.cache','status'=>'manual','reason'=>'link.cache_and_prefetch_unverified'];
        }
        if ($config->operations() !== null) {
            $options=$config->operations();$guard=$services[$options['request_guard']] ?? null;
            $checks[]=['check'=>'operations.request_guard','status'=>is_callable($guard) ? 'manual' : 'fail','reason'=>is_callable($guard) ? 'operation.request_boundary_unverified' : 'configuration.operation_guard'];
            $checks[]=['check'=>'operations.confirmation','status'=>'manual','reason'=>'operation.user_confirmation_unverified'];
            $checks[]=['check'=>'operations.business_transaction','status'=>'manual','reason'=>'operation.transaction_unverified'];
        }
        $credentials=$config->apiCredentials();
        if($credentials!==null){
            $keys=$services[$credentials['keys']] ?? null;$guard=$services[$credentials['request_guard']] ?? null;$scopes=$services[$credentials['scope_provider']] ?? null;
            $checks[]=['check'=>'api_credentials.keys','status'=>$keys instanceof \SoSecurity\Support\HmacKeys?'manual':'fail','reason'=>$keys instanceof \SoSecurity\Support\HmacKeys?'api_credentials.key_lifecycle_unverified':'configuration.api_credential_keys'];
            $checks[]=['check'=>'api_credentials.request_guard','status'=>is_callable($guard)?'manual':'fail','reason'=>is_callable($guard)?'api_credentials.request_boundary_unverified':'configuration.api_credential_provider'];
            $checks[]=['check'=>'api_credentials.scope_provider','status'=>is_callable($scopes)?'manual':'fail','reason'=>is_callable($scopes)?'api_credentials.current_scopes_unverified':'configuration.api_credential_provider'];
            $checks[]=['check'=>'api_credentials.scopes','status'=>$credentials['policy']['allowed_scopes']?'manual':'fail','reason'=>$credentials['policy']['allowed_scopes']?'api_credentials.route_scopes_unverified':'api_credentials.default_deny'];
            if($credentials['management_authorization']!==null){$management=$services[$credentials['management_authorization']] ?? null;$subject=$services[$credentials['management_subject']] ?? null;$checks[]=['check'=>'api_credentials.delegated_management','status'=>$management instanceof \SoSecurity\Authorization\Authorizer&&is_callable($subject)?'manual':'fail','reason'=>$management instanceof \SoSecurity\Authorization\Authorizer&&is_callable($subject)?'api_credentials.delegation_unverified':'configuration.api_credential_management'];}
            foreach(['account_lifecycle','management_session','transport','business_authorization','retention'] as $check){$checks[]=['check'=>'api_credentials.'.$check,'status'=>'manual','reason'=>'api_credentials.'.$check.'_unverified'];}
        }
        foreach($config->webhooks() as $name=>$options){
            $prefix='webhooks.'.$name.'.';$provider=$options['key_provider']===null?null:($services[$options['key_provider']] ?? null);$guard=$options['request_guard']===null?null:($services[$options['request_guard']] ?? null);
            if($options['key_provider']===null){$checks[]=['check'=>$prefix.'receive','status'=>'not_configured','reason'=>'configuration.webhook_receive'];}
            else{
                foreach(['key_provider'=>is_callable($provider),'request_guard'=>is_callable($guard)] as $item=>$valid){$checks[]=['check'=>$prefix.$item,'status'=>$valid?'manual':'fail','reason'=>$valid?'webhook.'.$item.'_unverified':'configuration.webhook_provider'];}
                $checks[]=['check'=>$prefix.'transport','status'=>strpos($options['url'],'https://')===0?'manual':'fail','reason'=>strpos($options['url'],'https://')===0?'webhook.tls_proxy_unverified':'webhook.http_demo_only'];
                if($options['protocol']==='standard-ed25519'){$sodium=extension_loaded('sodium')&&function_exists('sodium_crypto_sign_verify_detached');$checks[]=['check'=>$prefix.'ed25519','status'=>$sodium?'pass':'fail','reason'=>$sodium?'dependency.available':'dependency.sodium'];}
                if($options['protocol']==='github-sha256'){$checks[]=['check'=>$prefix.'freshness','status'=>'manual','reason'=>'webhook.unsigned_freshness_unverified'];}
            }
            if($options['inbox']!==null){$inbox=$options['inbox'];$connection=$services[$inbox['connection']] ?? null;$keys=$services[$inbox['integrity_keys']] ?? null;$association=$services[$inbox['association_guard']] ?? null;
                foreach(['connection'=>$connection instanceof \PDO,'integrity_keys'=>$keys instanceof \SoSecurity\Support\HmacKeys,'association_guard'=>is_callable($association)] as $item=>$valid){$checks[]=['check'=>$prefix.'inbox.'.$item,'status'=>$valid?'manual':'fail','reason'=>$valid?'webhook.inbox_'.$item.'_unverified':'configuration.webhook_inbox'];}
                foreach(['schema_durability','business_association','backlog_retention','key_separation','receive_processing'] as $item){$checks[]=['check'=>$prefix.'inbox.'.$item,'status'=>'manual','reason'=>'webhook.'.$item.'_unverified'];}
            }
            if($options['processing']!==null){
                $processing=$options['processing'];$typed=['connection'=>\PDO::class,'integrity_keys'=>\SoSecurity\Support\HmacKeys::class];
                foreach(['connection','integrity_keys','mapper','association_guard','worker_guard'] as $item){$service=$services[$processing[$item]] ?? null;$valid=isset($typed[$item])?$service instanceof $typed[$item]:is_callable($service);$checks[]=['check'=>$prefix.'processing.'.$item,'status'=>$valid?'manual':'fail','reason'=>$valid?'webhook.processing_'.$item.'_unverified':'configuration.webhook_processing'];}
                if($processing['management_guard']===null){$checks[]=['check'=>$prefix.'processing.management_guard','status'=>'not_configured','reason'=>'webhook.processing_retry_disabled'];}
                else{$valid=is_callable($services[$processing['management_guard']] ?? null);$checks[]=['check'=>$prefix.'processing.management_guard','status'=>$valid?'manual':'fail','reason'=>$valid?'webhook.processing_operator_unverified':'configuration.webhook_processing'];}
                foreach(['history_provenance','schema_durability','current_business','transactional_handler','worker_identity','recovery_retention','transport_timeout'] as $item){$checks[]=['check'=>$prefix.'processing.'.$item,'status'=>'manual','reason'=>'webhook.processing_'.$item.'_unverified'];}
            }
        }
        $idempotency=$config->idempotency();
        if($idempotency!==null){
            $typed=['connection'=>\PDO::class,'integrity_keys'=>\SoSecurity\Support\HmacKeys::class];
            foreach(['connection','integrity_keys','authority'] as $item){$service=$services[$idempotency[$item]] ?? null;$valid=isset($typed[$item])?$service instanceof $typed[$item]:is_callable($service);$checks[]=['check'=>'idempotency.'.$item,'status'=>$valid?'manual':'fail','reason'=>$valid?'idempotency.'.$item.'_unverified':'configuration.idempotency'];}
            if($idempotency['management_guard']===null){$checks[]=['check'=>'idempotency.management_guard','status'=>'not_configured','reason'=>'idempotency.management_disabled'];}
            else{$valid=is_callable($services[$idempotency['management_guard']] ?? null);$checks[]=['check'=>'idempotency.management_guard','status'=>$valid?'manual':'fail','reason'=>$valid?'idempotency.management_unverified':'configuration.idempotency'];}
            foreach(['schema_durability','request_identity','current_business','transactional_handler','key_separation','recovery_retention','transport_timeout'] as $item){$checks[]=['check'=>'idempotency.'.$item,'status'=>'manual','reason'=>'idempotency.'.$item.'_unverified'];}
        }
        $outbox=$config->outbox();
        if($outbox!==null){
            $typed=['connection'=>\PDO::class,'integrity_keys'=>\SoSecurity\Support\HmacKeys::class];
            foreach(['connection','integrity_keys','authority'] as $item){$service=$services[$outbox[$item]] ?? null;$valid=isset($typed[$item])?$service instanceof $typed[$item]:is_callable($service);$checks[]=['check'=>'outbox.'.$item,'status'=>$valid?'manual':'fail','reason'=>$valid?'outbox.'.$item.'_unverified':'configuration.outbox'];}
            if($outbox['management_guard']===null){$checks[]=['check'=>'outbox.management_guard','status'=>'not_configured','reason'=>'outbox.management_disabled'];}
            else{$valid=is_callable($services[$outbox['management_guard']] ?? null);$checks[]=['check'=>'outbox.management_guard','status'=>$valid?'manual':'fail','reason'=>$valid?'outbox.management_unverified':'configuration.outbox'];}
            foreach(['schema_durability','host_transaction','business_event_identity','current_business','worker_identity','destination_contract','receiver_deduplication','key_separation','recovery_retention','capacity_maintenance','transport_timeout','reconciliation_evidence','resolution_audit','format_rollout'] as $item){$checks[]=['check'=>'outbox.'.$item,'status'=>'manual','reason'=>'outbox.'.$item.'_unverified'];}
        }
        $api = $config->api();
        if ($api === null) { $checks[] = ['check'=>'api.signatures','status'=>'not_configured','reason'=>'configuration.api']; }
        else {
            $provider = isset($api['key_provider']) ? ($services[$api['key_provider']] ?? null) : null;
            $checks[] = ['check'=>'api.key_provider','status'=>!isset($api['key_provider']) ? 'not_configured' : ($provider instanceof \SoSecurity\Api\KeyProvider ? 'manual' : 'fail'),
                'reason'=>$provider instanceof \SoSecurity\Api\KeyProvider ? 'api.key_lifecycle_unverified' : 'configuration.key_provider'];
            $checks[] = ['check'=>'api.request_boundary','status'=>'manual','reason'=>'api.raw_request_unverified'];
            $checks[] = ['check'=>'api.transport','status'=>strpos($api['origin'],'https://')===0 ? 'manual' : 'fail',
                'reason'=>strpos($api['origin'],'https://')===0 ? 'api.tls_proxy_unverified' : 'api.http_demo_only'];
        }
        $signed=$config->statelessCsrf();
        if ($signed===null) { $checks[]=['check'=>'csrf.signed','status'=>'not_configured','reason'=>'configuration.stateless_csrf']; }
        else {
            $keys=$services[$signed['keys']] ?? null;
            $checks[]=['check'=>'csrf.signed.keys','status'=>$keys instanceof \SoSecurity\Support\HmacKeys ? 'manual' : 'fail',
                'reason'=>$keys instanceof \SoSecurity\Support\HmacKeys ? 'csrf.key_lifecycle_unverified' : 'configuration.keys'];
            $checks[]=['check'=>'csrf.signed.binding','status'=>'manual','reason'=>'csrf.auth_binding_unverified'];
        }
        $html=$config->html();
        if ($html===null) { $checks[]=['check'=>'html','status'=>'not_configured','reason'=>'configuration.html']; }
        else {
            $dom=extension_loaded('dom'); $checks[]=['check'=>'html.dom','status'=>$dom ? 'pass' : 'fail','reason'=>$dom ? 'dependency.available' : 'dependency.dom'];
            if (isset($html['sanitizer'])) {
                $sanitizer=$services[$html['sanitizer']] ?? null;
                $checks[]=['check'=>'html.sanitizer','status'=>$sanitizer instanceof \SoSecurity\Output\HtmlSanitizer ? 'manual' : 'fail',
                    'reason'=>$sanitizer instanceof \SoSecurity\Output\HtmlSanitizer ? 'html.adapter_unverified' : 'configuration.html_sanitizer'];
            } else {
                // Does not invoke application autoloaders, initialize provider configuration, or write a cache.
                $provider=class_exists('HTMLPurifier',false) && defined('HTMLPurifier::VERSION');
                $version=$provider && \SoSecurity\Output\HtmlPurifierSanitizer::supportsVersion(\HTMLPurifier::VERSION);
                $checks[]=['check'=>'html.purifier','status'=>$version && extension_loaded('ctype') ? 'pass' : 'manual',
                    'reason'=>$version ? (extension_loaded('ctype') ? 'dependency.available' : 'dependency.ctype') : 'dependency.htmlpurifier_unverified'];
            }
            $checks[]=['check'=>'html.render_context','status'=>'manual','reason'=>'html.body_context_unverified'];
        }
        $factorOptions=$config->accountFactors();
        $factorReady=$factorOptions!==null;
        if($factorOptions===null){$checks[]=['check'=>'account_factors','status'=>'not_configured','reason'=>'configuration.account_factor'];}
        else{
            foreach(['connection','repository','integrity_keys','totp','fence','worker_guard','read_guard','management_guard'] as $name){
                $service=$services[$factorOptions[$name]]??null;
                if($name==='connection'){$valid=$service instanceof \PDO;}
                elseif($name==='repository'){$valid=$service instanceof \SoSecurity\Account\FactorRepository;}
                elseif($name==='integrity_keys'){$valid=$service instanceof \SoSecurity\Support\HmacKeys;}
                elseif($name==='totp'){$valid=$service instanceof \SoSecurity\Mfa\TotpFactors&&!$service->isManaged();}
                elseif($name==='fence'){$valid=$service instanceof \SoSecurity\Account\LocalEpochFence&&$service->matches($config->site(),$factorOptions['scope'],$factorOptions['epoch']);}
                else{$valid=is_callable($service);}
                $factorReady=$factorReady&&$valid;
                $checks[]=['check'=>'account_factors.'.$name,'status'=>$valid?'manual':'fail','reason'=>$valid?'account_factors.host_contract_unverified':'configuration.account_factor'];
            }
            foreach(['same_pdo','clock_matching','worker_registration','old_workers_stopped','migration_approval','notification_delivery','backup_epoch','physical_retention','native_request_protection'] as $name){$checks[]=['check'=>'account_factors.'.$name,'status'=>'manual','reason'=>'account_factors.host_contract_unverified'];}
        }
        $accounts=$config->accounts();
        if($accounts===null){$checks[]=['check'=>'accounts','status'=>'not_configured','reason'=>'configuration.accounts'];}
        else{
            foreach(['connection','repository','integrity_keys','outbox_keys','notifications','request_budget','registration_authority','request_guard','management_guard','delivery_guard','recovery_authority','recovery_factor','strong_recovery','mailbox_authority','mailbox_approval'] as $name){
                $service=$accounts[$name]===null?null:($services[$accounts[$name]] ?? null);$valid=false;$reason='configuration.accounts_dependencies';
                if($name==='connection'){$valid=$service instanceof \PDO;}
                elseif($name==='repository'){$valid=$service instanceof \SoSecurity\Account\Repository&&(($accounts['request_guard']===null&&$accounts['recovery_authority']===null&&$accounts['mailbox_authority']===null)||$service instanceof \SoSecurity\Account\IdentityRepository);}
                elseif($name==='recovery_factor'){$valid=$service instanceof \SoSecurity\Auth\SecondFactor;}
                elseif(in_array($name,['integrity_keys','outbox_keys'],true)){$valid=$service instanceof \SoSecurity\Support\HmacKeys;}
                elseif($name==='notifications'){
                    if($service instanceof \SoSecurity\Account\Notifications){try{$service->validateConfiguration(null,$accounts['policy']['smtp_utf8']);$valid=true;}catch(\SoSecurity\Exception\ConfigurationException $error){$reason=$error->reason();}}
                }elseif($name==='request_budget'){
                    if($service instanceof \SoSecurity\Account\RequestBudgets){try{$service->validateConfiguration($config->site());$valid=true;}catch(\SoSecurity\Exception\ConfigurationException $error){$reason=$error->reason();}}
                }else{$valid=is_callable($service);}
                $checks[]=['check'=>'accounts.'.$name,'status'=>$accounts[$name]===null?'not_configured':($valid?'manual':'fail'),'reason'=>$accounts[$name]===null?'configuration.accounts_optional_authority':($valid?'accounts.host_contract_unverified':$reason)];
            }
            foreach(['schema_durability','repository_connection','identity_mapping','clock_matching','key_separation','request_protection','notification_delivery','transport_budget','restore_epoch','capacity_maintenance'] as $name){$checks[]=['check'=>'accounts.'.$name,'status'=>'manual','reason'=>'accounts.host_contract_unverified'];}
        }
        $mfa = $config->mfa();
        if ($mfa === null) { $checks[] = ['check' => 'mfa', 'status' => 'not_configured', 'reason' => 'configuration.mfa']; }
        else {
            $cipher = $services[$mfa['cipher']] ?? null;
            $checks[] = ['check' => 'mfa.cipher', 'status' => $cipher instanceof \SoSecurity\Crypto\Cipher ? 'manual' : 'fail',
                'reason' => $cipher instanceof \SoSecurity\Crypto\Cipher ? 'mfa.key_lifecycle_unverified' : 'configuration.mfa_cipher'];
            $checks[] = ['check' => 'mfa.host_authorization', 'status' => 'manual', 'reason' => 'mfa.host_authorization_unverified'];
        }
        $authentication = $config->authentication();
        if ($authentication === null) { $checks[] = ['check' => 'authentication', 'status' => 'not_configured', 'reason' => 'configuration.authentication']; }
        else {
            $provider = $services[$authentication['identity_provider']] ?? null;
            $guard = $authentication['request_guard'] === null ? null : ($services[$authentication['request_guard']] ?? null);
            $factor = $authentication['second_factor'] === null ? null : ($services[$authentication['second_factor']] ?? null);
            $checks[] = ['check' => 'authentication.identity', 'status' => $provider instanceof \SoSecurity\Auth\IdentityProvider ? 'manual' : 'fail',
                'reason' => $provider instanceof \SoSecurity\Auth\IdentityProvider ? 'auth.identity_lifecycle_unverified' : 'configuration.identity_provider'];
            $checks[] = ['check' => 'authentication.request_guard', 'status' => is_callable($guard) ? 'manual' : 'fail',
                'reason' => is_callable($guard) ? 'auth.request_guard_unverified' : 'configuration.authentication_guard'];
            if ($authentication['managed_factors']) {
                $checks[] = ['check' => 'authentication.second_factor', 'status' => $factorReady ? 'manual' : 'fail', 'reason' => $factorReady ? 'account_factors.host_contract_unverified' : 'configuration.account_factor'];
            } elseif ($authentication['second_factor'] !== null) {
                $checks[] = ['check' => 'authentication.second_factor', 'status' => $factor instanceof \SoSecurity\Auth\SecondFactor ? 'manual' : 'fail',
                    'reason' => $factor instanceof \SoSecurity\Auth\SecondFactor ? 'auth.factor_contract_unverified' : 'configuration.second_factor'];
            }
            $checks[] = ['check' => 'authentication.host_session', 'status' => 'manual', 'reason' => 'auth.host_session_rotation_unverified'];
        }
        $remember = $config->remember();
        if ($remember === null) { $checks[] = ['check' => 'authentication.remember', 'status' => 'not_configured', 'reason' => 'configuration.remember']; }
        else {
            $keys = $services[$remember['keys']] ?? null;
            $checks[] = ['check' => 'authentication.remember.keys', 'status' => $keys instanceof \SoSecurity\Support\HmacKeys ? 'manual' : 'fail',
                'reason' => $keys instanceof \SoSecurity\Support\HmacKeys ? 'auth.remember_key_lifecycle_unverified' : 'configuration.remember_keys'];
            $checks[] = ['check' => 'authentication.remember.cookie', 'status' => $remember['secure'] ? 'manual' : 'fail',
                'reason' => $remember['secure'] ? 'auth.remember_transport_unverified' : 'auth.remember_local_http_only'];
            $checks[] = ['check' => 'authentication.remember.consent', 'status' => 'manual', 'reason' => 'auth.remember_opt_in_unverified'];
        }
        $authorization = $config->authorization();
        if ($authorization === null) { $checks[] = ['check' => 'authorization', 'status' => 'not_configured', 'reason' => 'configuration.authorization']; }
        else {
            $identity = $services[$authorization['identity_provider']] ?? null;
            $policy = $authorization['policy'] === null ? null : ($services[$authorization['policy']] ?? null);
            $audit = $authorization['audit'] === null ? null : ($services[$authorization['audit']] ?? null);
            $checks[] = ['check' => 'authorization.identity', 'status' => $identity instanceof \SoSecurity\Auth\IdentityProvider ? 'manual' : 'fail',
                'reason' => $identity instanceof \SoSecurity\Auth\IdentityProvider ? 'authorization.identity_lifecycle_unverified' : 'configuration.authorization_identity'];
            $checks[] = ['check' => 'authorization.policy', 'status' => $authorization['policy'] === null ? 'not_configured' : ($policy instanceof \SoSecurity\Authorization\PolicyProvider ? 'manual' : 'fail'),
                'reason' => $authorization['policy'] === null ? 'authorization.default_deny' : ($policy instanceof \SoSecurity\Authorization\PolicyProvider ? 'authorization.rules_unverified' : 'configuration.authorization_policy')];
            if ($authorization['audit'] !== null) { $checks[] = ['check' => 'authorization.audit', 'status' => $audit instanceof \SoSecurity\Audit\AuditLogger ? 'manual' : 'fail',
                'reason' => $audit instanceof \SoSecurity\Audit\AuditLogger ? 'authorization.audit_delivery_unverified' : 'configuration.authorization_audit']; }
        }
        $password = $config->password(); $blocklist = $password['blocklist'] === 'builtin' ? 'builtin' : ($password['blocklist'] === null ? null : ($services[$password['blocklist']] ?? null));
        $validBlocklist = $blocklist === 'builtin' || $blocklist instanceof \SoSecurity\Password\PasswordBlocklist;
        $checks[] = ['check' => 'password.blocklist', 'status' => $validBlocklist ? 'manual' : 'fail',
            'reason' => $validBlocklist ? 'password.blocklist_coverage_unverified' : 'configuration.password_blocklist'];
        $breach = $password['breach_checker'] === null ? null : ($services[$password['breach_checker']] ?? null);
        $checks[] = ['check' => 'password.breach', 'status' => $password['breach_checker'] === null ? 'not_configured' : (is_callable($breach) ? 'manual' : 'fail'),
            'reason' => $password['breach_checker'] === null ? 'password.breach_optional' : (is_callable($breach) ? 'password.breach_service_unverified' : 'configuration.password_breach')];
        return $checks;
    }
    private function redis(\Redis $redis, string $namespace): array
    {
        $timeout = null; $healthy = true;
        try {
            if (!$redis->isConnected()) { return [['check' => 'connection', 'status' => 'fail', 'reason' => 'storage.connection']]; }
            if ($redis->getOption(\Redis::OPT_SERIALIZER) !== \Redis::SERIALIZER_NONE
                || !in_array($redis->getOption(\Redis::OPT_PREFIX), ['', null], true)) {
                return [['check' => 'options', 'status' => 'fail', 'reason' => 'storage.configuration']];
            }
            $timeout = (float) $redis->getOption(\Redis::OPT_READ_TIMEOUT);
            $timeout = $timeout > 0 ? $timeout : max(.2, (float) ini_get('default_socket_timeout'));
            $redis->setOption(\Redis::OPT_READ_TIMEOUT, '0.200000');
            if (!$redis->ping()) { return [['check' => 'connection', 'status' => 'fail', 'reason' => 'storage.connection']]; }
            $redis->clearLastError();
            $policy = $redis->config('GET', 'maxmemory-policy');
            $name = is_array($policy) ? ($policy['maxmemory-policy'] ?? null) : null;
            $result = [['check' => 'connection', 'status' => 'pass', 'reason' => 'storage.connected'],
                ['check' => 'eviction', 'status' => $name === null ? 'manual' : ($name === 'noeviction' ? 'pass' : 'fail'),
                    'reason' => $name === null ? 'storage.eviction_unverified' : ($name === 'noeviction' ? 'storage.noeviction' : 'storage.unsafe_eviction')]];
            $redis->clearLastError();
            $lua = $redis->eval('return 1', [], 0);
            $result[] = ['check' => 'cas_permission', 'status' => $lua === 1 ? 'pass' : 'fail', 'reason' => $lua === 1 ? 'storage.lua_available' : 'storage.lua_unavailable'];
            $redis->clearLastError();
            $info = $redis->info('server');
            try {
                $ready = \SoSecurity\Storage\RedisRead::value($redis, 'sosecurity:' . hash('sha256', $namespace) . ':ready', 512);
                $result[] = ['check' => 'bounded_read_permission', 'status' => 'pass', 'reason' => 'storage.bounded_read_available'];
            } catch (\SoSecurity\Storage\StorageException $error) {
                $result[] = ['check' => 'bounded_read_permission', 'status' => 'fail', 'reason' => $error->reason()];
                $result[] = ['check' => 'readiness', 'status' => 'fail', 'reason' => 'storage.read_unavailable']; return $result;
            }
            $metadata = is_string($ready) && strlen($ready) <= 512 ? json_decode($ready, true, 4) : null;
            $initialized = is_array($metadata) && isset($metadata['server'], $metadata['epoch']) && is_array($info)
                && ($info['run_id'] ?? null) === $metadata['server'] && is_string($metadata['epoch']) && preg_match('/^[a-f0-9]{64}$/D', $metadata['epoch']);
            $result[] = ['check' => 'readiness', 'status' => $initialized ? 'pass' : 'fail', 'reason' => $initialized ? 'storage.initialized' : 'storage.initialization_required'];
            return $result;
        } catch (\RedisException $e) {
            $healthy = false; $redis->close();
            return [['check' => 'connection', 'status' => 'fail', 'reason' => 'storage.connection']];
        } finally {
            if ($healthy && $timeout !== null && $redis->isConnected()) { $redis->setOption(\Redis::OPT_READ_TIMEOUT, (string) $timeout); }
        }
    }
}
