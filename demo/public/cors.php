<?php
declare(strict_types=1);
ini_set('display_errors','0');
require dirname(__DIR__,2).'/vendor/autoload.php';
try {
    $directory=getenv('SOSECURITY_DEMO_STORAGE') ?: '/var/lib/sosecurity-demo';
    $store=new SoSecurity\Storage\FileStore($directory,'sosecurity-demo-cors');
    $budget=(new SoSecurity\RateLimit\RateLimiter($store,new SoSecurity\RateLimit\Policy(30,60,[10],120)))
        ->consume('static-cors',(new SoSecurity\Http\ClientIp())->resolve($_SERVER));
    if (!$budget->allowed) { http_response_code(429); header('Retry-After: '.$budget->retryAfter); exit; }
    $origin=getenv('SOSECURITY_DEMO_CORS_ORIGIN') ?: 'http://72.rocky.wsl:3000';
    $decision=(new SoSecurity\Http\Cors([$origin],['GET'],['x-demo-token'],false,0))->evaluate(
        $_SERVER['REQUEST_METHOD'] ?? 'GET', $_SERVER['HTTP_ORIGIN'] ?? null,
        $_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD'] ?? null, $_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'] ?? null);
    header('Cache-Control: no-store');
    foreach ($decision->headers() as $name=>$value) { header($name.': '.$value); }
    if (!$decision->allowed()) { http_response_code(403); exit; }
    if ($decision->status()===204) { http_response_code(204); exit; }
    if (($_SERVER['REQUEST_METHOD'] ?? '')!=='GET') { http_response_code(405); header('Allow: GET, OPTIONS'); exit; }
    header('Content-Type: application/json; charset=utf-8'); header('X-Content-Type-Options: nosniff');
    echo '{"demo":true,"message":"固定公开演示数据，不读取会话或业务账号"}';
} catch (Throwable $e) { http_response_code(503); header('Content-Type: application/json'); echo '{"reason":"demo.unavailable"}'; }
