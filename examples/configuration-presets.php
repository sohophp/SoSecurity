<?php
declare(strict_types=1);

// Select ONE preset and replace trusted deployment values. Requiring this file has no side effects.
// Connections and private keys are injected separately; never load them from request parameters.
return (static function (): array {
    $loginPolicies = [
        'ip' => ['limit' => 100, 'window' => 300],
        'login' => ['limit' => 5, 'window' => 300, 'bans' => [60, 300, 900]],
    ];
    return [
        'form_session' => ['site' => 'example-site'],
        'login_file' => [
            'site' => 'example-site',
            'storage' => ['driver' => 'file', 'directory' => '/srv/example/private/security'],
            'rate_limits' => $loginPolicies,
        ],
        'login_redis' => [
            'site' => 'example-site',
            'storage' => ['driver' => 'redis', 'connection' => 'security_redis'],
            'rate_limits' => $loginPolicies,
        ],
        'login_mysql' => [
            'site' => 'example-site',
            'storage' => ['driver' => 'mysql', 'connection' => 'security_db'],
            'rate_limits' => $loginPolicies,
        ],
        'api_signing' => ['site' => 'example-site', 'api' => ['origin' => 'https://api.example.com']],
        'signed_form' => ['site' => 'example-site', 'stateless_csrf' => ['keys' => 'csrf_keys']],
        'rich_text' => ['site' => 'example-site', 'html' => []],
    ];
})();
