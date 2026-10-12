<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require dirname(__DIR__) . '/vendor/autoload.php';
$path = $argv[1] ?? '';
if ($path === '' || !is_file($path)) { fwrite(STDERR, "Usage: php bin/initialize-storage.php /private/config.php [--recover]\n"); exit(2); }
try {
    $input = require $path;
    if (!is_array($input) || !isset($input['config']) || !is_array($input['config'])) {
        throw new SoSecurity\Exception\ConfigurationException('Trusted configuration must return config.');
    }
    $security = SoSecurity\Security::fromArray($input['config'], $input['services'] ?? []);
    echo json_encode($security->initializeStorage(in_array('--recover', $argv, true))) . "\n";
} catch (SoSecurity\Exception\ConfigurationException $e) { fwrite(STDERR, $e->reason() . "\n"); exit(2); }
catch (SoSecurity\Exception\SecurityException $e) { fwrite(STDERR, $e->reason() . "\n"); exit(1); }
catch (Throwable $e) { fwrite(STDERR, "storage.initialization_failed\n"); exit(1); }
