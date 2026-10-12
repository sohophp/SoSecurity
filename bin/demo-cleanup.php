<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require dirname(__DIR__) . '/vendor/autoload.php';
$directory = getenv('SOSECURITY_DEMO_STORAGE') ?: '/var/lib/sosecurity-demo';
$store = new SoSecurity\Storage\FileStore($directory, 'sosecurity-demo');
$removed = 0;
do { $batch = $store->pruneBatch(1000); $removed += $batch->removed(); } while (!$batch->complete());
echo 'Pruned ' . $removed . " expired demonstration records.\n";

if (is_dir($directory . '/uploads')) {
    require dirname(__DIR__) . '/demo/uploads.php';
    echo 'Pruned ' . (new SoSecurityDemo\UploadSandbox($directory, dirname(__DIR__) . '/demo/public'))->prune() . " expired demo uploads.\n";
}
