<?php
declare(strict_types=1);

ini_set('display_errors', '0');
require dirname(__DIR__, 2) . '/vendor/autoload.php';
require dirname(__DIR__) . '/app.php';

try {
    (new SoSecurityDemo\DemoApp())->run();
} catch (Throwable $e) {
    http_response_code(503);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    echo '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>演示暂时不可用</title>'
        . '<h1>演示暂时不可用</h1><p>请检查演示存储、扩展或外部服务配置后重试。</p></html>';
}
