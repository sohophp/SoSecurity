<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require dirname(__DIR__) . '/vendor/autoload.php';
$directory = getenv('SOSECURITY_DEMO_STORAGE') ?: '/var/lib/sosecurity-demo';
$store = new SoSecurity\Storage\FileStore($directory, 'sosecurity-demo');
echo 'Pruned ' . $store->prune() . " expired demonstration records.\n";
