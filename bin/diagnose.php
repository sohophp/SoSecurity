<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require dirname(__DIR__) . '/vendor/autoload.php';
// The file is trusted PHP configuration, not a user-submitted upload.
$path = $argv[1] ?? '';
if ($path === '' || !is_file($path)) {
    fwrite(STDERR, "Usage: php bin/diagnose.php /private/security-config.php [--probe]\n"); exit(2);
}
try {
    $input = require $path;
    if (!is_array($input) || !isset($input['config']) || !is_array($input['config'])) {
        throw new SoSecurity\Exception\ConfigurationException('Diagnostic file must return config and optional services.');
    }
    $security = SoSecurity\Security::fromArray($input['config'], $input['services'] ?? []);
    $results = $security->diagnose($input['document_root'] ?? null, in_array('--probe', $argv, true));
    echo json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
    foreach ($results as $result) { if ($result['status'] === 'fail') { exit(1); } }
} catch (SoSecurity\Exception\ConfigurationException $e) {
    fwrite(STDERR, $e->reason() . "\n"); exit(2);
} catch (Throwable $e) {
    fwrite(STDERR, "diagnostic.unavailable\n"); exit(1);
}
