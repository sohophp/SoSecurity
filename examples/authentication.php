<?php
declare(strict_types=1);
namespace SoSecurity\Examples\Authentication;

ini_set('display_errors', '0');

// Explicit standalone adapter: requires private configuration and storage; never creates a default account.
$autoload = dirname(__DIR__) . '/vendor/autoload.php';
if (!is_file($autoload)) { $autoload = dirname(__DIR__, 3) . '/autoload.php'; }
require $autoload;

use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\LoginResult;
use SoSecurity\Auth\DeviceRiskDecision;
use SoSecurity\Auth\DeviceRiskPolicy;
use SoSecurity\Auth\PasswordIdentityProvider;
use SoSecurity\Auth\PasswordRecord;
use SoSecurity\Auth\RememberedLogin;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Auth\TotpSecondFactor;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Http\ClientIp;
use SoSecurity\Output\Escaper;
use SoSecurity\Session\SessionSecurity;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\SessionStore;

function configuration(): array
{
    $path = getenv('SOSECURITY_AUTH_EXAMPLE_CONFIG'); $real = $path ? realpath($path) : false;
    $web = realpath($_SERVER['DOCUMENT_ROOT'] ?? __DIR__);
    if ($real === false || !is_file($real) || $web === false || $real === $web || strpos($real, rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0) {
        throw new \RuntimeException('Configure a private account source outside the web root.');
    }
    $raw = file_get_contents($real, false, null, 0, 16385);
    $entry = is_string($raw) && strlen($raw) <= 16384 ? json_decode($raw, true, 8) : null;
    if (!is_array($entry) || array_diff(array_keys($entry), ['username', 'subject', 'hash', 'version', 'enabled', 'roles', 'mfa_required'])
        || !isset($entry['username'], $entry['subject'], $entry['hash'], $entry['version'])) {
        throw new \RuntimeException('Invalid private account configuration.');
    }
    foreach (['username', 'subject', 'hash', 'version'] as $field) {
        if (!is_string($entry[$field]) || $entry[$field] === '') { throw new \RuntimeException('Invalid private account field.'); }
    }
    foreach (['enabled', 'mfa_required'] as $field) {
        if (array_key_exists($field, $entry) && !is_bool($entry[$field])) { throw new \RuntimeException('Account policies must be explicit booleans.'); }
    }
    if (array_key_exists('roles', $entry) && !is_array($entry['roles'])) { throw new \RuntimeException('Account roles must be an array.'); }
    return $entry;
}

function record(?array $entry = null): PasswordRecord
{
    $entry = $entry ?? configuration();
    return new PasswordRecord(new Account('example', $entry['subject'], $entry['version'], $entry['enabled'] ?? true,
        $entry['roles'] ?? [], $entry['mfa_required'] ?? false), $entry['hash']);
}

function response(int $status, array $data): void
{
    http_response_code($status); header('Cache-Control: no-store'); header('Referrer-Policy: no-referrer');
    if (session_status() === PHP_SESSION_ACTIVE) {
        header('Set-Cookie: ' . SessionSecurity::cookieHeader(getenv('SOSECURITY_AUTH_EXAMPLE_HTTPS') !== '0'), false);
    }
    if (strpos($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') !== false) {
        header('Content-Type: application/json; charset=utf-8'); echo json_encode($data); return;
    }
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>认证与会话示例</title>'
        . '<style>body{font:16px/1.6 system-ui;max-width:42rem;margin:2rem auto;padding:0 1rem}form{display:flex;flex-wrap:wrap;gap:.75rem;margin:1rem 0}label{display:grid;max-width:100%}input,select,button,textarea{font:inherit;max-width:100%;box-sizing:border-box}button{white-space:nowrap;align-self:end;padding:.3rem .6rem}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><main><h1>认证与会话示例</h1>';
    if (isset($data['csrf'])) {
        $form = '<form method="post"><input type="hidden" name="_csrf" value="' . Escaper::html($data['csrf']) . '">';
        if ($data['stage'] === 'mfa_required') {
            echo $form . '<label>验证码或恢复码<input name="proof" autocomplete="one-time-code" maxlength="35"></label><label>类型<select name="type"><option value="totp">TOTP</option><option value="recovery">恢复码</option></select></label><button name="action" value="mfa">完成验证</button></form>';
        } else {
            echo $form . '<label>账号<input name="username" autocomplete="username" maxlength="256"></label><label>密码<input type="password" name="password" autocomplete="current-password" maxlength="4096"></label><button name="action" value="login">登录</button>'
                . ($data['stage'] === 'authenticated' ? '<button name="action" value="reauthenticate">重新认证</button>' : '') . '</form>';
        }
        if ($data['stage'] === 'authenticated') {
            echo $form . '<p>撤销指定会话或全部退出需要在 5 分钟内完成认证；记住登录恢复后请先重新认证。普通退出始终可用。</p><label>会话管理编号<input name="session_id" maxlength="32"></label><button name="action" value="list">查询会话</button><button name="action" value="revoke">撤销指定会话</button><button name="action" value="sensitive">检查近期认证</button><button name="action" value="logout">退出</button><button name="action" value="logout_all">全部退出</button></form>';
        }
        if (($data['documents_available'] ?? false) && $data['stage'] === 'authenticated') {
            echo '<h2>对象、字段与批量授权</h2>' . $form . '<label>文档编号<input name="document_id" maxlength="64"></label><label>读取字段<input name="fields" value="id,version,title" maxlength="512"></label><button name="action" value="document_read">读取公开字段</button><button name="action" value="document_private">读取管理字段</button></form>';
            echo $form . '<label>更新JSON（最多20项）<textarea name="operations" rows="4" maxlength="16384" placeholder="[{&quot;id&quot;:&quot;a&quot;,&quot;version&quot;:1,&quot;changes&quot;:{&quot;title&quot;:&quot;新标题&quot;}}]"></textarea></label><button name="action" value="document_batch">授权后更新整批</button></form>';
        }
        if ($data['remember_available'] ?? false) {
            if ($data['stage'] === 'authenticated') {
                echo $form . '<button name="action" value="remember">记住此设备（30天）</button><button name="action" value="remember_list">查询持久授权</button><label>授权管理编号<input name="selector" maxlength="32"></label><button name="action" value="remember_revoke">撤销持久授权</button></form>';
            } elseif (($data['stage'] === 'anonymous') && ($data['remember_present'] ?? false)) {
                echo $form . '<button name="action" value="restore">恢复记住的登录</button><button name="action" value="forget">忘记此设备</button></form>';
            }
        }
    }
    $display = $data; unset($display['csrf']);
    echo '<pre>' . Escaper::html(json_encode($display, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) . '</pre></main></html>';
}

try {
    $directory = getenv('SOSECURITY_AUTH_EXAMPLE_STORAGE'); $dummy = getenv('SOSECURITY_AUTH_EXAMPLE_DUMMY_HASH');
    if (!$directory || !$dummy) { throw new \RuntimeException('Configure shared storage and the dummy password hash.'); }
    configuration();
    $store = new FileStore($directory, 'auth-example');
    $rate = new \SoSecurity\RateLimit\RateLimiter($store, new \SoSecurity\RateLimit\Policy(100, 60, [10], 120));
    $ip = (new ClientIp())->resolve($_SERVER);
    if (!$rate->consume('entry', $ip)->allowed) { response(429, ['error' => 'auth.rate']); return; }
    $secure = getenv('SOSECURITY_AUTH_EXAMPLE_HTTPS') !== '0';
    SessionSecurity::configure($secure); session_name('SoSecurityAuthExample');
    if (!session_start()) { throw new \RuntimeException('Cannot start the host session.'); }
    $lifecycle = new SessionSecurity(); $csrf = new CsrfTokens(new SessionStore('auth-example-controls'));
    if (!isset($_SESSION['auth_example_binding'])) { $_SESSION['auth_example_binding'] = bin2hex(random_bytes(32)); }
    $binding = $_SESSION['auth_example_binding'];
    $provider = new PasswordIdentityProvider(
        function (string $scope, string $identifier): ?PasswordRecord {
            $entry = configuration();
            return $scope === 'example' && hash_equals($entry['username'], $identifier) ? record($entry) : null;
        },
        function (string $scope, string $subject): ?PasswordRecord { $entry = record(); return $scope === 'example' && $entry->account()->subject() === $subject ? $entry : null; },
        new \SoSecurity\Password\PasswordHasher(), $dummy);
    $factor = null; $encodedKey = getenv('SOSECURITY_AUTH_EXAMPLE_KEY');
    if ($encodedKey !== false && $encodedKey !== '') {
        $key = base64_decode($encodedKey, true);
        if (!is_string($key) || strlen($key) !== 32) { throw new \RuntimeException('Invalid private MFA key.'); }
        $factor = new TotpSecondFactor(new \SoSecurity\Mfa\TotpFactors($store,
            new \SoSecurity\Crypto\Cipher('current', ['current' => $key], 'auth-example:mfa'), 'Auth example'));
    }
    $guard = function () use ($csrf, $binding, $store, $ip): bool {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !$csrf->verify('controls', $binding, $_POST['_csrf'] ?? null)) { return false; }
        $decision = (new \SoSecurity\RateLimit\RateLimiter($store, new \SoSecurity\RateLimit\Policy(40, 60, [10], 120)))->consume('actions', $ip);
        if (!$decision->allowed) { header('Retry-After: ' . $decision->retryAfter); throw new \SoSecurity\Exception\SecurityException('Request budget exhausted.', 'auth.rate'); }
        return true;
    };
    $sessions = new SessionRegistry($store, $provider, $factor, null, 60, 300);
    $flow = new AuthenticationFlow($store, $provider, $sessions, $guard, $factor);
    $documents = null; $database = getenv('SOSECURITY_AUTH_EXAMPLE_DATABASE');
    if ($database !== false && $database !== '') {
        $real = realpath($database); $web = realpath($_SERVER['DOCUMENT_ROOT'] ?? __DIR__);
        if ($real === false || !is_file($real) || $web === false || ($real === $web || strpos($real, rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0)
            || (fileperms($real) & 0077) !== 0) { throw new \RuntimeException('Configure an existing private documents database outside the web root.'); }
        require_once __DIR__ . '/authorization.php';
        $documents = new \PDO('sqlite:' . $real, null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION, \PDO::ATTR_TIMEOUT => 1]);
    }
    $remember = null; $rememberName = $secure ? '__Host-SoSecurityRemember' : 'SoSecurityRememberLocal';
    $encodedRemember = getenv('SOSECURITY_AUTH_EXAMPLE_REMEMBER_KEY');
    if ($encodedRemember !== false && $encodedRemember !== '') {
        $rememberKey = base64_decode($encodedRemember, true);
        if (!is_string($rememberKey) || strlen($rememberKey) !== 32) { throw new \RuntimeException('Invalid private persistent-login key.'); }
        $riskGuard = null;
        $riskSignals = getenv('SOSECURITY_AUTH_EXAMPLE_RISK_SIGNALS');
        if ($riskSignals !== false && $riskSignals !== '') {
            if (strlen($riskSignals) > 128) { throw new \RuntimeException('Invalid private risk signals.'); }
            $signals = json_decode($riskSignals, true, 2);
            if (!is_array($signals)) { throw new \RuntimeException('Invalid private risk signals.'); }
            $decision = (new DeviceRiskPolicy())->decide($signals);
            // A fixed server-side demonstration snapshot. Real hosts must use a current trusted source.
            $riskGuard = static function (string $scope, string $subject, string $selector) use ($decision): DeviceRiskDecision {
                return $decision;
            };
        }
        $remember = new RememberedLogin($store, $provider, $sessions,
            new \SoSecurity\Support\HmacKeys('current', ['current' => $rememberKey]), $guard, $factor,
            null, 2592000, 8, 300, 5, $riskGuard);
    }
    $clearRemember = function () use ($remember, $rememberName, $secure): void {
        if ($remember !== null) { header('Set-Cookie: ' . $remember->clearCookieHeader($rememberName, $secure), false); }
        unset($_COOKIE[$rememberName]);
    };
    $accept = function (LoginResult $result) use ($lifecycle, $sessions, $csrf, &$binding): void {
        if ($result->status() === 'mfa_required') { $_SESSION['auth_example_pending'] = $result->challenge(); return; }
        if ($result->status() !== 'authenticated') { return; }
        $credential = $result->credential(); $account = $result->account();
        try { $lifecycle->rotate(); }
        catch (\Throwable $e) { $sessions->revoke($account->scope(), $account->subject(), $credential->id()); throw $e; }
        $csrf->revoke('controls', $binding); $binding = bin2hex(random_bytes(32));
        $_SESSION['auth_example_binding'] = $binding; $_SESSION['auth_example_subject'] = $account->subject();
        $_SESSION['auth_example_token'] = $credential->token(); unset($_SESSION['auth_example_pending']);
    };
    $status = 200; $extra = []; $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $verified = isset($_SESSION['auth_example_subject'], $_SESSION['auth_example_token'])
        ? $sessions->verify('example', $_SESSION['auth_example_subject'], $_SESSION['auth_example_token']) : null;
    if ($verified === null) { unset($_SESSION['auth_example_subject'], $_SESSION['auth_example_token']); }
    if ($method === 'POST') {
        $action = $_POST['action'] ?? null;
        if ($action === 'login' || $action === 'reauthenticate') {
            if ($action === 'reauthenticate' && $verified === null) { $status = 401; $extra = ['error' => 'auth.denied']; }
            else {
                $result = $flow->password('example', $binding, $_POST['username'] ?? null, $_POST['password'] ?? null, 'Example browser',
                    $action === 'reauthenticate' ? $_SESSION['auth_example_token'] : null);
                $accept($result);
                if (in_array($result->status(), ['denied', 'enrollment_required'], true)) { $status = 401; $extra = ['error' => 'auth.denied']; }
            }
        } elseif ($action === 'mfa') {
            $result = $flow->secondFactor('example', $binding, $_SESSION['auth_example_pending'] ?? null,
                ['type' => $_POST['type'] ?? null, 'code' => $_POST['proof'] ?? null]);
            $accept($result); if ($result->status() === 'denied') { $status = 401; $extra = ['error' => 'auth.denied']; }
        } elseif (in_array($action, ['remember', 'restore', 'forget', 'remember_list', 'remember_revoke'], true)) {
            if ($remember === null) { $status = 400; $extra = ['error' => 'auth.remember_unavailable']; }
            elseif ($action === 'restore' && $verified !== null) { $status = 409; $extra = ['error' => 'auth.already_authenticated']; }
            elseif ($action === 'restore') {
                $result = $remember->resume('example', $_COOKIE[$rememberName] ?? null);
                if ($result->status() === 'authenticated') {
                    $accept(new LoginResult('authenticated', null, null, $result->session(), $result->account()));
                    header('Set-Cookie: ' . $remember->cookieHeader($result->nextCredential(), $rememberName, $secure), false);
                } elseif ($result->status() === 'retry') {
                    // Do not overwrite/delete the winning parallel request's new cookie.
                    $status = 409; $extra = ['error' => 'auth.remember_retry'];
                } elseif ($result->status() === 'step_up') {
                    // The grant was revoked atomically; a fresh full login can issue a new grant by consent.
                    $clearRemember();
                    $status = 403; $extra = ['error' => 'auth.reauthentication_required'];
                } elseif ($result->status() === 'blocked') {
                    $clearRemember(); $status = 401; $extra = ['error' => 'auth.denied'];
                } else { $clearRemember(); $status = 401; $extra = ['error' => 'auth.denied']; }
            } elseif ($action === 'forget') {
                $remember->forget('example', $_COOKIE[$rememberName] ?? null); $clearRemember();
            } else {
                if ($verified === null) {
                    if (!$guard()) { throw new \SoSecurity\Exception\SecurityException('Request protection failed.', 'auth.request_denied'); }
                    $status = 401; $extra = ['error' => 'auth.denied'];
                }
                elseif ($action === 'remember') {
                    $credential = $remember->issue('example', $verified->account()->subject(), $_SESSION['auth_example_token'], 'Example browser');
                    if ($credential === null) { $status = 403; $extra = ['error' => 'auth.reauthentication_required']; }
                    else { header('Set-Cookie: ' . $remember->cookieHeader($credential, $rememberName, $secure), false); $extra = ['remembered' => true, 'remember_expires_at' => $credential->expiresAt()]; }
                } elseif ($action === 'remember_list') { $extra = ['grants' => $remember->all('example', $verified->account()->subject())]; }
                elseif (!is_string($_POST['selector'] ?? null)) { $status = 400; $extra = ['error' => 'auth.input']; }
                else { $extra = ['revoked' => $remember->revoke('example', $verified->account()->subject(), $_POST['selector'])]; }
            }
        } elseif (in_array($action, ['document_read', 'document_private', 'document_batch'], true)) {
            if (!$guard()) { throw new \SoSecurity\Exception\SecurityException('Request protection failed.', 'auth.request_denied'); }
            if ($verified === null) { $status = 401; $extra = ['error' => 'auth.denied']; }
            elseif ($documents === null) { $status = 503; $extra = ['error' => 'authorization.not_configured']; }
            else {
                try {
                    $authorizer = new \SoSecurity\Authorization\Authorizer($provider, \SoSecurity\Examples\Authorization\policy());
                    if ($action === 'document_batch') {
                        $raw = $_POST['operations'] ?? null;
                        if (!is_string($raw) || strlen($raw) > 16384) { throw new \SoSecurity\Exception\ValidationException('Invalid batch.', 'authorization.input'); }
                        $operations = json_decode($raw, true, 8);
                        if (!is_array($operations)) { throw new \SoSecurity\Exception\ValidationException('Invalid batch.', 'authorization.input'); }
                        $documents->beginTransaction();
                        try {
                            $updated = \SoSecurity\Examples\Authorization\update($documents, $authorizer, $verified->account(), 'example', $operations);
                            $documents->commit(); $extra = ['updated' => $updated];
                        } catch (\Throwable $e) { if ($documents->inTransaction()) { $documents->rollBack(); } throw $e; }
                    } else {
                        $id = $_POST['document_id'] ?? null; $fields = $_POST['fields'] ?? 'id,version,title';
                        if (!is_string($id) || !is_string($fields) || strlen($fields) > 512) { throw new \SoSecurity\Exception\ValidationException('Invalid document query.', 'authorization.input'); }
                        $extra = ['document' => \SoSecurity\Examples\Authorization\read($documents, $authorizer, $verified->account(), 'example', $id, explode(',', $fields), $action === 'document_private')];
                    }
                } catch (\SoSecurity\Exception\ValidationException $e) { $status = 400; $extra = ['error' => $e->reason()]; }
                catch (\SoSecurity\Exception\SecurityException $e) {
                    $status = $e->reason() === 'authorization.denied' ? 403 : ($e->reason() === 'authorization.conflict' ? 409 : 503);
                    $extra = ['error' => $e->reason()];
                }
            }
        } elseif (in_array($action, ['logout', 'logout_all', 'list', 'revoke', 'sensitive'], true)) {
            if (!$guard()) { throw new \SoSecurity\Exception\SecurityException('Request protection failed.', 'auth.request_denied'); }
            if ($verified === null) { $status = 401; $extra = ['error' => 'auth.denied']; }
            elseif ($action === 'list') { $extra = ['sessions' => $sessions->all('example', $verified->account()->subject())]; }
            elseif (in_array($action, ['revoke', 'logout_all'], true) && !$verified->recent(300, time(), 1)) {
                $status = 403; $extra = ['error' => 'auth.reauthentication_required'];
            }
            elseif ($action === 'sensitive') {
                $minimum = $verified->account()->mfaRequired() || ($factor !== null && $factor->binding('example', $verified->account()->subject()) !== null) ? 2 : 1;
                if (!$verified->recent(5, time(), $minimum)) { $status = 403; $extra = ['error' => 'auth.reauthentication_required']; }
                else { $extra = ['allowed' => true]; }
            } elseif ($action === 'revoke') {
                if (!is_string($_POST['session_id'] ?? null)) { $status = 400; $extra = ['error' => 'auth.input']; }
                else { $extra = ['revoked' => $sessions->revoke('example', $verified->account()->subject(), $_POST['session_id'])]; }
            } else {
                if ($action === 'logout_all') { $sessions->revokeAll('example', $verified->account()->subject()); }
                else { $sessions->revoke('example', $verified->account()->subject(), $verified->id()); }
                $clearRemember();
                $flow->cancel('example', $binding); $csrf->revoke('controls', $binding); $lifecycle->rotate();
                $binding = bin2hex(random_bytes(32)); $_SESSION['auth_example_binding'] = $binding;
                unset($_SESSION['auth_example_subject'], $_SESSION['auth_example_token'], $_SESSION['auth_example_pending']);
            }
        } else { $status = 400; $extra = ['error' => 'auth.input']; }
    } elseif ($method !== 'GET') { header('Allow: GET, POST'); $status = 405; $extra = ['error' => 'auth.method']; }
    $verified = isset($_SESSION['auth_example_subject'], $_SESSION['auth_example_token'])
        ? $sessions->verify('example', $_SESSION['auth_example_subject'], $_SESSION['auth_example_token']) : null;
    if ($verified === null) { unset($_SESSION['auth_example_subject'], $_SESSION['auth_example_token']); }
    $stage = isset($_SESSION['auth_example_pending']) ? 'mfa_required' : ($verified === null ? 'anonymous' : 'authenticated');
    response($status, $extra + ['stage' => $stage, 'csrf' => $csrf->issue('controls', $binding),
        'documents_available' => $documents !== null, 'remember_available' => $remember !== null, 'remember_present' => isset($_COOKIE[$rememberName]), 'session' => $verified === null ? null : [
        'id' => $verified->id(), 'subject' => $verified->account()->subject(), 'method' => $verified->method(), 'strength' => $verified->strength(), 'resumed' => $verified->resumed(), 'expires_at' => $verified->expiresAt()]]);
} catch (\SoSecurity\Exception\SecurityException $e) {
    $status = $e->reason() === 'auth.request_denied' ? 403 : ($e->reason() === 'auth.rate' ? 429 : ($e->reason() === 'auth.session_capacity' ? 409 : 503));
    response($status, ['error' => $e->reason()]);
} catch (\Throwable $e) { response(503, ['error' => 'auth.unavailable']); }
