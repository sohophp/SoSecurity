<?php
declare(strict_types=1);
namespace SoSecurity\Examples\QuarantineHttp;

ini_set('display_errors', '0');
$autoload = dirname(__DIR__) . '/vendor/autoload.php';
if (!is_file($autoload)) { $autoload = dirname(__DIR__, 3) . '/autoload.php'; }
require $autoload;
require __DIR__ . '/upload-quarantine-business.php';

use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Output\Escaper;
use SoSecurity\RateLimit\Policy;
use SoSecurity\RateLimit\RateLimiter;
use SoSecurity\Session\SessionSecurity;
use SoSecurity\Storage\SessionStore;

function headers(): void
{
    header('Cache-Control: no-store, private'); header('Referrer-Policy: same-origin'); header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY'); header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
}
function response(int $status, array $data, ?array $config = null): void
{
    http_response_code($status); headers();
    if (session_status() === PHP_SESSION_ACTIVE && $config !== null) {
        header('Set-Cookie: ' . SessionSecurity::cookieHeader($config['secure']), false);
        if (isset($_SESSION['quarantine_binding']) && is_string($_SESSION['quarantine_binding'])) {
            $data['csrf'] = (new CsrfTokens(new SessionStore('quarantine-controls'), 1800, 16))->issue('controls', $_SESSION['quarantine_binding']);
        }
    }
    if (strpos($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') !== false) { header('Content-Type: application/json; charset=utf-8'); echo json_encode($data); return; }
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>文件隔离</title><style>body{font:16px/1.6 system-ui;max-width:44rem;margin:2rem auto;padding:0 1rem}form{display:flex;flex-wrap:wrap;gap:.7rem;margin:1rem 0}label{display:grid;max-width:100%}input,button{font:inherit;max-width:100%;box-sizing:border-box}pre,section{overflow-wrap:anywhere;white-space:pre-wrap}section{border-top:1px solid #ddd;padding-top:1rem}button{align-self:end}</style><main><h1>文件隔离</h1>';
    $csrf = isset($data['csrf']) ? '<input type="hidden" name="_csrf" value="' . Escaper::html($data['csrf']) . '">' : '';
    if (isset($data['error'])) { echo '<p role="alert">操作未完成，请刷新后重试或联系管理员。</p><a href="?">返回文件列表</a>'; }
    elseif (($data['stage'] ?? '') === 'authenticated') {
        echo '<p>新文件先等待扫描，通过后才可下载。</p>';
        if (!empty($data['can_upload'])) { echo '<form method="post" enctype="multipart/form-data">' . $csrf . '<label>选择文件<input type="file" name="file" required></label><button name="action" value="upload">上传文件</button></form>'; }
        echo '<form method="get"><button>刷新状态</button></form><form method="post">' . $csrf . '<button name="action" value="logout">退出</button></form>';
        if (!empty($data['admin'])) {
            echo '<p>重扫、拒绝和删除需要在五分钟内完成认证。</p><form method="post">' . $csrf . '<label>账号<input name="username" autocomplete="username" required></label><label>密码<input type="password" name="password" autocomplete="current-password" required></label><button name="action" value="reauthenticate">重新认证</button></form>';
        }
        $labels = ['staging' => '尚未完成上传', 'pending' => '等待扫描', 'scanning' => '正在扫描', 'retry' => '暂时失败，等待重试', 'available' => '可以下载', 'rejected' => '已拒绝', 'failed' => '扫描未完成', 'deleting' => '正在删除', 'expired' => '已过期'];
        foreach ($data['files'] ?? [] as $file) {
            $id = Escaper::html($file['id']); echo '<section data-file-id="' . $id . '"><p>文件 ' . $id . '：<span data-state>' . Escaper::html($labels[$file['state']]) . '</span></p>';
            if ($file['download'] && $file['state'] === 'available') { echo '<a data-download href="?download=' . $id . '">下载文件</a>'; }
            if ($file['manage']) {
                echo '<form method="post">' . $csrf . '<input type="hidden" name="id" value="' . $id . '">';
                if (!in_array($file['state'], ['staging', 'deleting', 'expired'], true)) { echo '<button name="action" value="rescan">重新扫描</button>'; }
                if (!in_array($file['state'], ['deleting', 'expired'], true)) { echo '<button name="action" value="reject">拒绝文件</button>'; }
                if (in_array($file['state'], ['staging', 'rejected', 'failed', 'deleting', 'expired'], true)) { echo '<button name="action" value="remove">删除文件</button>'; }
                echo '</form>';
            }
            echo '</section>';
        }
    } else {
        echo '<form method="post">' . $csrf . '<label>账号<input name="username" autocomplete="username" maxlength="64" required></label><label>密码<input type="password" name="password" autocomplete="current-password" maxlength="4096" required></label><button name="action" value="login">登录</button></form>';
    }
    unset($data['csrf']); echo '<pre data-quarantine-state>' . Escaper::html(json_encode($data, JSON_UNESCAPED_UNICODE)) . '</pre></main></html>';
}
$config = null;
try {
    $config = configuration((string) getenv('SOSECURITY_QUARANTINE_EXAMPLE_CONFIG'), $_SERVER['DOCUMENT_ROOT'] ?? null);
    if ($config['secure'] && !in_array($_SERVER['HTTPS'] ?? '', ['on', '1'], true)) { throw new SecurityException('HTTPS required.', 'quarantine.transport'); }
    $method = $_SERVER['REQUEST_METHOD'] ?? '';
    if (!in_array($method, ['GET', 'HEAD', 'POST'], true)) { header('Allow: GET, HEAD, POST'); response(405, ['error' => 'quarantine.method'], $config); return; }
    $services = services($config);
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false) { throw new SecurityException('Direct client address required.', 'quarantine.denied'); }
    $limit = (new RateLimiter($services['store'], new Policy(240, 60, [60], 120)))->consume('native-http', $ip);
    if (!$limit->allowed) { header('Retry-After: ' . $limit->retryAfter); response(429, ['error' => 'quarantine.rate'], $config); return; }
    if (session_module_name() !== 'files') { throw new SecurityException('Configure native file session locking.', 'quarantine.unavailable'); }
    privatePath((string) ini_get('session.save_path'), $config['document_root'], true);
    if (session_status() !== PHP_SESSION_ACTIVE && !session_start(['use_strict_mode' => 1, 'use_only_cookies' => 1, 'use_trans_sid' => 0, 'cookie_secure' => $config['secure'], 'cookie_httponly' => true, 'cookie_path' => '/'])) { throw new SecurityException('Session unavailable.', 'quarantine.unavailable'); }
    if (!isset($_SESSION['quarantine_binding'])) { $_SESSION['quarantine_binding'] = bin2hex(random_bytes(32)); }
    $binding = $_SESSION['quarantine_binding'];
    if (!is_string($binding) || !preg_match('/\A[a-f0-9]{64}\z/D', $binding)) { throw new SecurityException('Session unavailable.', 'quarantine.unavailable'); }
    $csrf = new CsrfTokens(new SessionStore('quarantine-controls'), 1800, 16);
    if (isset($_GET['download'])) {
        $id = fileId($_GET['download']);
        if (!in_array($method, ['GET', 'HEAD'], true) || ($_SERVER['QUERY_STRING'] ?? '') !== 'download=' . $id || isset($_SERVER['HTTP_RANGE'])) { throw new ValidationException('Unsupported download request.', 'quarantine.input'); }
        $identity = current($services, $config); $row = resource($services['pdo'], $config['site'], $id);
        if (!permitted($identity, $row)) { throw new SecurityException('Current ownership required.', 'quarantine.denied'); }
        $snapshot = $services['queue']->readAvailable($id);
        $again = current($services, $config); $row = resource($services['pdo'], $config['site'], $id);
        if (!permitted($again, $row) || $again->account()->fingerprint() !== $identity->account()->fingerprint()) { throw new SecurityException('Current ownership required.', 'quarantine.denied'); }
        headers(); header('Set-Cookie: ' . SessionSecurity::cookieHeader($config['secure']), false); header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="upload.' . $snapshot->extension() . '"'); header('Content-Length: ' . $snapshot->bytes());
        session_write_close(); if ($method !== 'HEAD') { echo $snapshot->contents(); } return;
    }
    if (($_SERVER['QUERY_STRING'] ?? '') !== '' || $method === 'HEAD') { throw new ValidationException('Unexpected query or method.', 'quarantine.input'); }
    $status = 200;
    if ($method === 'POST') {
        if (($_SERVER['HTTP_ORIGIN'] ?? '') !== $config['origin'] || !$csrf->verify('controls', $binding, $_POST['_csrf'] ?? null, true)) { throw new SecurityException('Protected same-origin request required.', 'quarantine.denied'); }
        $action = $_POST['action'] ?? null; $fields = ['login' => ['username', 'password'], 'reauthenticate' => ['username', 'password'], 'logout' => [], 'upload' => [], 'rescan' => ['id'], 'reject' => ['id'], 'remove' => ['id']];
        if (!is_string($action) || !isset($fields[$action]) || array_diff(array_keys($_POST), array_merge(['action', '_csrf'], $fields[$action])) || ($action !== 'upload' && $_FILES)) { throw new ValidationException('Unexpected fields.', 'quarantine.input'); }
        $identity = current($services, $config);
        if ($action === 'login' || $action === 'reauthenticate') {
            if (($action === 'login' && $identity !== null) || ($action === 'reauthenticate' && $identity === null)) { throw new SecurityException('Invalid authentication stage.', 'quarantine.denied'); }
            $flow = new AuthenticationFlow($services['store'], $services['provider'], $services['sessions'], static function (): bool { return true; });
            $result = $flow->password($config['site'], $binding, $_POST['username'] ?? null, $_POST['password'] ?? null, '文件隔离会话', $action === 'reauthenticate' ? $_SESSION['quarantine_token'] : null);
            if ($result->status() !== 'authenticated') { $status = 401; }
            else {
                $credential = $result->credential();
                try { (new SessionSecurity())->rotate(); }
                catch (\Throwable $error) { $services['sessions']->revoke($config['site'], $result->account()->subject(), $credential->id()); throw $error; }
                $_SESSION['quarantine_subject'] = $result->account()->subject(); $_SESSION['quarantine_token'] = $credential->token();
                $csrf->revoke('controls', $binding); $_SESSION['quarantine_binding'] = bin2hex(random_bytes(32));
            }
        } elseif ($action === 'logout') {
            if ($identity !== null) { $services['sessions']->revoke($config['site'], $identity->account()->subject(), $identity->id()); }
            unset($_SESSION['quarantine_subject'], $_SESSION['quarantine_token']); $csrf->revoke('controls', $binding);
            (new SessionSecurity())->rotate(); $_SESSION['quarantine_binding'] = bin2hex(random_bytes(32));
        } elseif ($identity === null) { throw new SecurityException('Current authentication required.', 'quarantine.denied'); }
        elseif ($action === 'upload') {
            if (!in_array('uploader', $identity->account()->roles(), true) || array_keys($_FILES) !== ['file']) { throw new SecurityException('Upload permission required.', 'quarantine.denied'); }
            $services['pdo']->exec('BEGIN IMMEDIATE'); $pending = null;
            try {
                $identity = current($services, $config);
                if ($identity === null || !in_array('uploader', $identity->account()->roles(), true)) { throw new SecurityException('Current upload permission required.', 'quarantine.denied'); }
                $projection = \SoSecurity\Support\SqlSchema::boundedProjection('sqlite', ['id' => 'id']);
                $query = $services['pdo']->prepare('SELECT ' . $projection . ' FROM quarantine_example_files WHERE site=:site AND owner=:owner LIMIT 8');
                $query->execute(['site' => $config['site'], 'owner' => $identity->account()->subject()]); $count = count($query->fetchAll(\PDO::FETCH_COLUMN)); $query->closeCursor();
                if ($count >= 8) { throw new SecurityException('Upload quota exhausted.', 'quarantine.rate'); }
                $pending = $services['queue']->enqueueUpload($_FILES['file']);
                $query = $services['pdo']->prepare('INSERT INTO quarantine_example_files(site,id,owner,created_at) VALUES(:site,:id,:owner,:created)');
                $query->execute(['site' => $config['site'], 'id' => $pending->id(), 'owner' => $identity->account()->subject(), 'created' => time()]);
                $services['pdo']->exec('COMMIT');
            } catch (\Throwable $error) {
                try { $services['pdo']->exec('ROLLBACK'); } catch (\Throwable $rollback) { /* An uncertain commit still must not expose the private content. */ }
                if ($pending !== null) { $services['queue']->reject($pending->id()); $services['queue']->remove($pending->id()); }
                throw $error;
            }
        } else {
            $id = fileId($_POST['id'] ?? null); $row = resource($services['pdo'], $config['site'], $id); $identity = current($services, $config);
            if (!permitted($identity, $row, true)) { throw new SecurityException('Current recent administrator required.', 'quarantine.denied'); }
            if ($action === 'rescan') { $services['queue']->rescan($id); }
            elseif ($action === 'reject') { $services['queue']->reject($id); }
            else {
                $services['queue']->remove($id);
                $query = $services['pdo']->prepare('DELETE FROM quarantine_example_files WHERE site=:site AND id=:id'); $query->execute(['site' => $config['site'], 'id' => $id]);
            }
        }
    }
    if ($method === 'POST' && $status === 200 && strpos($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') === false) {
        headers(); header('Set-Cookie: ' . SessionSecurity::cookieHeader($config['secure']), false);
        header('Location: ?', true, 303); return;
    }
    $identity = current($services, $config);
    response($status, ['stage' => $identity === null ? 'anonymous' : 'authenticated', 'admin' => $identity !== null && in_array('upload-admin', $identity->account()->roles(), true),
        'can_upload' => $identity !== null && in_array('uploader', $identity->account()->roles(), true),
        'files' => $identity === null ? [] : files($services, $config, $identity)], $config);
} catch (ValidationException $error) { response(400, ['error' => 'quarantine.input'], $config); }
catch (SecurityException $error) {
    $reason = $error->reason(); $status = $reason === 'quarantine.denied' ? 403 : ($reason === 'quarantine.rate' ? 429 : (in_array($reason, ['upload.quarantine_unavailable', 'upload.quarantine_state'], true) ? 409 : 503));
    if ($status === 429) { header('Retry-After: 60'); }
    response($status, ['error' => $status === 403 ? 'quarantine.denied' : ($status === 409 ? ($reason === 'upload.quarantine_state' ? 'quarantine.state' : 'quarantine.pending') : ($status === 429 ? 'quarantine.rate' : 'quarantine.unavailable'))], $config);
} catch (\Throwable $error) { response(503, ['error' => 'quarantine.unavailable'], $config); }
