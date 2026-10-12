<?php
declare(strict_types=1);

// Demonstration adapter. Replace the credential lookup with the host's existing parameterized query.
require dirname(__DIR__) . '/vendor/autoload.php';

use SoSecurity\Captcha\Captcha;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Http\ClientIp;
use SoSecurity\Output\Escaper;
use SoSecurity\Password\PasswordHasher;
use SoSecurity\RateLimit\Policy;
use SoSecurity\RateLimit\RateLimiter;
use SoSecurity\Session\SessionSecurity;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\SessionStore;

function respond(int $status, array $data): void
{
    http_response_code($status);
    header('Cache-Control: no-store');
    if (strpos($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') !== false) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data);
    } else {
        header('Content-Type: text/html; charset=utf-8');
        if (isset($data['csrf'], $data['captcha'])) {
            echo '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>登录示例</title><form method="post">'
                . '<input type="hidden" name="_csrf" value="' . Escaper::html($data['csrf']) . '">'
                . '<input type="hidden" name="captcha_id" value="' . Escaper::html($data['captcha']['id']) . '">'
                . '<label>账号<input name="username" maxlength="128" autocomplete="username" required></label>'
                . '<label>密码<input type="password" name="password" autocomplete="current-password" required></label>'
                . '<label>' . Escaper::html($data['captcha']['prompt']) . '<input name="captcha_answer" required></label>'
                . '<button type="submit">登录</button></form></html>';
        } else { echo Escaper::html($data['message']); }
    }
}

try {
    $directory = getenv('SOSECURITY_EXAMPLE_STORE');
    $expectedUser = getenv('SOSECURITY_EXAMPLE_USER');
    $expectedHash = getenv('SOSECURITY_EXAMPLE_PASSWORD_HASH');
    if (!$directory || !$expectedUser || !$expectedHash) {
        throw new RuntimeException('Configure the example storage and credentials before use.');
    }
    // Only an explicitly configured local demonstration disables Secure. Real sites require HTTPS.
    $secure = getenv('SOSECURITY_EXAMPLE_HTTPS') !== '0';
    SessionSecurity::configure($secure);
    if (!session_start()) { throw new RuntimeException('Cannot start host session.'); }
    header('Set-Cookie: ' . SessionSecurity::cookieHeader($secure), false);
    $session = new SessionSecurity();
    if (!$session->touch()) {
        unset($_SESSION['example_user'], $_SESSION['example_binding']);
        $session->rotate();
        header('Set-Cookie: ' . SessionSecurity::cookieHeader($secure), false);
        respond(401, ['message' => '会话已过期，请重新登录。']);
        return;
    }
    $ip = (new ClientIp())->resolve($_SERVER); // Explicitly configure trusted proxies if needed.
    $store = new FileStore($directory, 'legacy-example');
    $renderBudget = new RateLimiter($store, new Policy(60, 60));
    $broadBudget = new RateLimiter($store, new Policy(100, 300));
    $loginBudget = new RateLimiter($store, new Policy(5, 300));
    $sessionStore = new SessionStore('legacy-example');
    $csrf = new CsrfTokens($sessionStore);
    $captcha = new Captcha($sessionStore);
    if (!isset($_SESSION['example_binding'])) { $_SESSION['example_binding'] = bin2hex(random_bytes(32)); }
    $binding = $_SESSION['example_binding'];
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if ($method === 'GET') {
        if (isset($_SESSION['example_user'])) {
            respond(200, ['message' => '已登录。']); return;
        }
        $decision = $renderBudget->consume('login-render', $ip);
        if (!$decision->allowed) {
            header('Retry-After: ' . $decision->retryAfter);
            respond(429, ['message' => '请求过于频繁。']); return;
        }
        $challenge = $captcha->arithmetic('login', $binding);
        respond(200, ['csrf' => $csrf->issue('login', $binding),
            'captcha' => ['id' => $challenge->id, 'prompt' => $challenge->prompt, 'expires_at' => $challenge->expiresAt]]);
        return;
    }
    if ($method !== 'POST') {
        header('Allow: GET, POST'); respond(405, ['message' => '不支持的请求方法。']); return;
    }
    $decision = $broadBudget->consume('login-ip', $ip);
    if (!$decision->allowed) {
        header('Retry-After: ' . $decision->retryAfter); respond(429, ['message' => '请求过于频繁。']); return;
    }
    if (!$csrf->verify('login', $binding, $_POST['_csrf'] ?? null)) {
        respond(403, ['message' => '表单验证失败，请刷新页面。']); return;
    }
    $user = $_POST['username'] ?? null; $password = $_POST['password'] ?? null;
    if (!is_string($user) || $user === '' || strlen($user) > 128 || !preg_match('//u', $user)
        || preg_match('/[\x00-\x1f\x7f]/', $user) || !is_string($password) || strlen($password) > 72) {
        respond(400, ['message' => '输入格式不正确。']); return;
    }
    // Must match the host's account normalization. This example uses exact case-sensitive account names.
    $subject = hash('sha256', json_encode([$ip, $user]));
    $decision = $loginBudget->consume('login-pair', $subject);
    if (!$decision->allowed) {
        header('Retry-After: ' . $decision->retryAfter); respond(429, ['message' => '请求过于频繁。']); return;
    }
    if (!$captcha->verify('login', $binding, $_POST['captcha_id'] ?? null, $_POST['captcha_answer'] ?? null)) {
        respond(403, ['message' => '验证码无效，请刷新页面。']); return;
    }
    // Always perform password work, including unknown accounts, for a uniform public error.
    $passwordValid = (new PasswordHasher())->verify($password, $expectedHash);
    if (!$passwordValid || !hash_equals($expectedUser, $user)) {
        respond(401, ['message' => '账号或密码不正确。']); return;
    }
    $csrf->revoke('login', $binding); $captcha->revoke('login', $binding);
    $session->rotate();
    $_SESSION['example_binding'] = bin2hex(random_bytes(32));
    $_SESSION['example_user'] = $user;
    header('Set-Cookie: ' . SessionSecurity::cookieHeader($secure), false);
    respond(200, ['message' => '登录成功。']);
} catch (Throwable $e) {
    // Never print/log credentials, session IDs, challenge answers or full exception payloads here.
    respond(503, ['message' => '安全服务暂时不可用，请稍后重试。']);
}
