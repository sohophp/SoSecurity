<?php
declare(strict_types=1);

// Test-only pilot entry. The host bootstrap/credentials are deliberately not loaded.
require getenv('SOSECURITY_PILOT_AUTOLOAD');
$core = realpath((string)getenv('SOSECURITY_PILOT_CORE'));
if ($core === false) { throw new RuntimeException('Configure an isolated CoreRepo worktree.'); }
require getenv('SOSECURITY_PILOT_HOST_AUTOLOAD');
spl_autoload_register(static function (string $class) use ($core): void {
    if (strpos($class, 'App\\') === 0) {
        $file = $core . '/App/' . str_replace('\\', '/', substr($class, 4)) . '.php';
        if (is_file($file)) { require $file; }
    }
}, true, true);

use App\Components\Csrf;
use App\Components\Session\Session;
use SoSecurity\Captcha\Captcha;
use SoSecurity\Http\ClientIp;
use SoSecurity\RateLimit\Policy;
use SoSecurity\RateLimit\RateLimiter;
use SoSecurity\Session\SessionSecurity;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\SessionStore;

function pilotRespond(int $status, array $data): void
{
    http_response_code($status);
    header('Cache-Control: no-store');
    if (strpos($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') !== false) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data);
        return;
    }
    header('Content-Type: text/html; charset=utf-8');
    $twig = new Twig\Environment(new Twig\Loader\ArrayLoader([
        'login' => '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>旧站组件试点</title>'
            . '{% if csrf is defined %}<form method="post"><input type="hidden" name="{{ csrf.name }}" value="{{ csrf.value }}">'
            . '<input type="hidden" name="captcha_id" value="{{ captcha.id }}">'
            . '<label>账号<input name="username" autocomplete="username"></label>'
            . '<label>密码<input name="password" type="password" autocomplete="current-password"></label>'
            . '<label>{{ captcha.prompt }}<input name="captcha_answer"></label><button>登录</button></form>{% endif %}'
            . '<p>{{ message|default("") }}</p></html>',
    ]), ['autoescape' => 'html', 'cache' => false]);
    echo $twig->render('login', $data);
}
try {
    // Verify that Composer's existing App mapping cannot silently use the dirty original workspace.
    foreach ([Session::class, App\Components\Session\SessionManager::class, Csrf::class,
        App\Components\Session\CsrfTokenStorage::class] as $class) {
        if (strpos((string)(new ReflectionClass($class))->getFileName(), $core . '/App/') !== 0) {
            throw new RuntimeException('Host component must come from the isolated worktree.');
        }
    }
    Session::setup(['save_handler' => 'files', 'save_path' => getenv('SOSECURITY_PILOT_SESSIONS'),
        'name' => 'COREPILOT', 'cookie_path' => '/pilot/', 'cookie_domain' => '',
        'cookie_secure' => false, 'cookie_httponly' => true, 'cookie_samesite' => 'Lax']);
    if (!Session::start()) { throw new RuntimeException('Host Session start failed.'); }
    header('Set-Cookie: ' . SessionSecurity::cookieHeader(false), false);
    if (!Session::get('pilot.binding')) { Session::set('pilot.binding', bin2hex(random_bytes(32))); }
    if (!Session::get('pilot.host_marker')) { Session::set('pilot.host_marker', 'preserved-host-data'); }
    $binding = Session::get('pilot.binding');
    $csrf = new Csrf('sosecurity-pilot-login'); // Preserve the host's existing Symfony CSRF mechanism.
    $captcha = new Captcha(new SessionStore('core-pilot-captcha'));
    $shared = new FileStore((string)getenv('SOSECURITY_PILOT_STATE'), 'core-pilot-rate');
    $ip = (new ClientIp())->resolve($_SERVER); // No untrusted forwarded headers.
    $broad = (new RateLimiter($shared, new Policy(60, 60)))->consume('ip', $ip);
    if (!$broad->allowed) { header('Retry-After: ' . $broad->retryAfter); pilotRespond(429, ['message' => '请求过于频繁']); return; }
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET') {
        $challenge = $captcha->arithmetic('login', $binding);
        pilotRespond(200, ['csrf' => $csrf->make(), 'captcha' => ['id' => $challenge->id, 'prompt' => $challenge->prompt],
            'host_marker' => Session::get('pilot.host_marker'), 'user' => Session::get('pilot.user'), 'component_origin_verified' => true]);
        return;
    }
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { header('Allow: GET, POST'); pilotRespond(405, ['message' => '请求方法不支持']); return; }
    if (!$csrf->verify($_POST)) { pilotRespond(403, ['message' => '表单验证失败']); return; }
    $user = $_POST['username'] ?? null; $password = $_POST['password'] ?? null;
    if (!is_string($user) || $user === '' || strlen($user) > 128 || !preg_match('//u', $user)
        || preg_match('/[\x00-\x1f\x7f]/', $user) || !is_string($password) || strlen($password) > 72) {
        pilotRespond(400, ['message' => '输入格式不正确']); return;
    }
    $pair = hash('sha256', json_encode([$ip, $user]));
    $decision = (new RateLimiter($shared, new Policy(3, 60)))->consume('login-pair', $pair);
    if (!$decision->allowed) { header('Retry-After: ' . $decision->retryAfter); pilotRespond(429, ['message' => '请求过于频繁']); return; }
    if (!$captcha->verify('login', $binding, $_POST['captcha_id'] ?? null, $_POST['captcha_answer'] ?? null)) {
        pilotRespond(403, ['message' => '验证码验证失败']); return;
    }
    // Test identity only. Production integration retains the host's own credential provider/SSO.
    $valid = password_verify($password, (string)getenv('SOSECURITY_PILOT_PASSWORD_HASH'));
    if (!$valid || !hash_equals((string)getenv('SOSECURITY_PILOT_USER'), $user)) {
        pilotRespond(401, ['message' => '账号或密码不正确']); return;
    }
    $csrf->destroy(); $captcha->revoke('login', $binding);
    (new SessionSecurity())->rotate();
    Session::set('pilot.binding', bin2hex(random_bytes(32))); Session::set('pilot.user', $user);
    header('Set-Cookie: ' . SessionSecurity::cookieHeader(false), false);
    pilotRespond(200, ['message' => '登录成功', 'host_marker' => Session::get('pilot.host_marker')]);
} catch (Throwable $error) {
    error_log('CoreRepo pilot refusal: ' . get_class($error));
    pilotRespond(503, ['message' => '安全服务暂时不可用']);
}
