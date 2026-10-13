<?php
declare(strict_types=1);

namespace SoSecurityDemo;

use SoSecurity\Audit\AuditLogger;
use SoSecurity\Captcha\Captcha;
use SoSecurity\Captcha\Turnstile;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Http\ClientIp;
use SoSecurity\Http\Cookie;
use SoSecurity\Http\IpRules;
use SoSecurity\Http\SecurityHeaders;
use SoSecurity\Output\Escaper;
use SoSecurity\Password\PasswordHasher;
use SoSecurity\Password\PasswordPolicy;
use SoSecurity\Password\ResetTokens;
use SoSecurity\RateLimit\Policy;
use SoSecurity\RateLimit\RateLimiter;
use SoSecurity\Session\SessionSecurity;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\RedisStore;
use SoSecurity\Storage\SessionStore;
use SoSecurity\Support\Clock;

require __DIR__ . '/uploads.php';
require __DIR__ . '/network.php';
require __DIR__ . '/api.php';
require __DIR__ . '/stateless.php';
require __DIR__ . '/html.php';

/** Only advances this visitor's demonstration time; never changes system time. */
final class DemoClock implements Clock
{
    private $module;
    public function __construct(string $module) { $this->module = $module; }
    public function now(): int { return time() + ($_SESSION['demo_offsets'][$this->module] ?? 0); }
    public function advance(int $seconds): void
    {
        $_SESSION['demo_offsets'][$this->module] = ($_SESSION['demo_offsets'][$this->module] ?? 0) + $seconds;
    }
}

final class DemoApp
{
    private const MODULES = [
        'home' => '功能总览', 'configuration' => '配置与诊断', 'captcha' => '验证码', 'csrf' => 'CSRF 防护', 'stateless'=>'无状态 CSRF', 'rate' => '限流与封禁',
        'upload' => '上传安全', 'validation' => '输入验证', 'password' => '密码安全', 'reset' => '重置令牌', 'session' => '会话安全',
        'api' => 'API 凭据与签名', 'network' => '受限外部请求', 'http' => 'HTTP 与代理', 'html'=>'富文本 HTML 清理', 'output' => '输出编码', 'audit' => '审计日志', 'storage' => '存储与隔离',
    ];
    private const TEST_PASSWORD = 'Demo-only-7.2!';
    private $module;
    private $base;
    private $secure;
    private $store;
    private $ui;
    private $binding;
    private $status = 200;
    private $result = null;
    private $directory;

    public function run(): void
    {
        $module = $_GET['module'] ?? 'home';
        if (!is_string($module) || !isset(self::MODULES[$module])) {
            http_response_code(404); echo '演示页面不存在。'; return;
        }
        $this->module = $module;
        $this->base = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/index.php')), '/.') . '/';
        $this->secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
        $directory = getenv('SOSECURITY_DEMO_STORAGE') ?: '/var/lib/sosecurity-demo';
        $this->directory = $directory;
        $this->store = new FileStore($directory, 'sosecurity-demo');
        $ip = (new ClientIp())->resolve($_SERVER);
        $budget = (new RateLimiter($this->store, new Policy(100, 60, [10], 120)))->consume('demo-http', $ip);
        if (!$budget->allowed) {
            http_response_code(429); header('Retry-After: ' . $budget->retryAfter);
            echo '演示请求过于频繁，请稍后重试。'; return;
        }
        SessionSecurity::configure($this->secure);
        session_name('SoSecurityDemo');
        ini_set('session.cookie_path', $this->base);
        if (!session_start()) { throw new \RuntimeException('Cannot start demo session.'); }
        if (!isset($_SESSION['demo_binding'])) {
            $_SESSION['demo_binding'] = bin2hex(random_bytes(32));
            $_SESSION['demo_audit_key'] = random_bytes(32);
            $_SESSION['demo_events'] = [];
        }
        $this->binding = $_SESSION['demo_binding'];
        $this->ui = new CsrfTokens(new SessionStore('demo-controls'), 3600, 32);
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        if ($method === 'POST') {
            if (!$this->ui->verify('controls', $this->binding, $_POST['_csrf'] ?? null)) {
                $this->status = 403; $this->result = ['message' => '操作表单已失效，请刷新后重试。'];
            } else {
                $action = $_POST['action'] ?? '';
                $allowed = [
                    'captcha' => ['math', 'image', 'verify', 'refresh', 'expire', 'turnstile'],
                    'csrf' => ['issue', 'verify', 'tamper', 'cross_scope', 'once', 'replay', 'expire', 'revoke'],
                    'stateless'=>['issue','verify','reuse','tamper','cross_scope','cross_binding','double','cookie_mismatch','expire','rotate_keep','rotate_drop','binding_change','policy','bad_key'],
                    'html'=>['clean','links','normal','attack','size_limit','tree_limit','provider_failure'],
                    'rate' => ['consume', 'ban', 'permanent', 'reset'],
                    'password' => ['hash', 'verify', 'policy', 'legacy'],
                    'reset' => ['issue', 'consume', 'replay', 'change_version'],
                    'session' => ['touch', 'idle', 'absolute', 'rotate', 'invalidate'],
                    'network' => ['fetch', 'private', 'redirect_private', 'rebind', 'peer', 'oversize'],
                    'api' => ['issue_key','check_key','scope_key','rotate_key','revoke_key','sign','verify','replay','tamper','expire','store_failure'],
                    'http' => ['resolve', 'headers', 'redirect', 'cors', 'permissions'], 'output' => ['encode'], 'audit' => ['record', 'clear'],
                    'storage' => ['increment', 'read', 'isolation'],
                    'upload' => ['upload', 'normal_sample', 'fake_sample', 'size_sample', 'path_sample', 'budget_sample', 'scanner_reject', 'scanner_fail', 'store_fail', 'clear'],
                    'validation' => ['validate', 'valid_sample', 'invalid_sample', 'unknown_sample'],
                    'configuration' => ['construct', 'diagnose', 'bad_option', 'immutable', 'store_failure', 'lock_timeout'],
                ];
                if (!is_string($action) || strlen($action) > 64 || !in_array($action, $allowed[$module] ?? [], true)) {
                    $this->status = 400; $this->result = ['message' => '不支持的演示操作。'];
                } else {
                    try { $this->dispatch($action); }
                    catch (\SoSecurity\Exception\ConfigurationException $e) {
                        $this->status = 400; $this->result = ['reason' => $e->reason(), 'message' => '配置被拒绝，请检查字段与策略。'];
                    }
                    catch (\SoSecurity\Storage\StorageException $e) {
                        $this->status = 503; $this->result = ['reason' => $e->reason(), 'message' => '存储不可用，敏感操作没有放行。'];
                    }
                    catch (\SoSecurity\Exception\ValidationException $e) {
                        $this->status = in_array($module,['upload','html'],true) ? 422 : 400; $this->result = ['reason' => $e->reason(), 'message' => $module === 'upload' ? '上传被拒绝，请检查格式、大小或演示额度。' : '输入未通过验证，请检查字段。'];
                    }
                    catch (\SoSecurity\Exception\SecurityException $e) {
                        $this->status = 503; $this->result = ['reason' => $e->reason(), 'message' => $module === 'upload' ? '处理依赖发生故障，上传没有放行。' : '处理依赖发生故障，本次操作已拒绝。'];
                    }
                    catch (\InvalidArgumentException $e) {
                        $this->status = 400; $this->result = ['message' => '输入格式或演示配置不正确，请检查字段。'];
                    }
                    $this->record($module . '.' . $action, $this->status < 400);
                }
            }
        } elseif ($method !== 'GET') {
            header('Allow: GET, POST'); $this->status = 405; $this->result = ['message' => '仅支持 GET 和 POST。'];
        }
        header('Set-Cookie: ' . Cookie::header(session_name(), session_id(), $this->base, $this->secure), false);
        header('Cache-Control: no-store');
        $csp = "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; style-src 'self'; img-src 'self' data:; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
        foreach (SecurityHeaders::build($csp, false) as $name => $value) { header($name . ': ' . $value); }
        http_response_code($this->status);
        $state = $this->state();
        if (strpos($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') !== false) {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['module' => $module, 'result' => $this->result,
                'controls_token' => $this->ui->issue('controls', $this->binding), 'state' => $state]);
            return;
        }
        header('Content-Type: text/html; charset=utf-8');
        $this->render($state);
    }

    private function input(string $name, int $maximum = 1024): string
    {
        $value = $_POST[$name] ?? '';
        if (!is_string($value) || strlen($value) > $maximum || !preg_match('//u', $value)) {
            throw new \InvalidArgumentException('Invalid input.');
        }
        return $value;
    }

    private function csrf(): CsrfTokens
    {
        $clock = new DemoClock('csrf');
        return new CsrfTokens(new SessionStore('demo-csrf', $clock), 30, 16, $clock);
    }
    private function captcha(): Captcha
    {
        $clock = new DemoClock('captcha');
        return new Captcha(new SessionStore('demo-captcha', $clock), 30, 3, 4, $clock);
    }
    private function limiter(): RateLimiter
    {
        // Visitor-owned playground bans stay in Session; abandoned permanent bans cannot fill disk.
        // The entry's separate IP budget uses shared FileStore before a session is created.
        return new RateLimiter(new SessionStore('demo-rate'), new Policy(3, 10, [5, 15], 60));
    }
    private function resetTokens(): ResetTokens { return new ResetTokens(new SessionStore('demo-reset'), 120); }
    private function resetBinding(): string { return $this->binding . ':' . ($_SESSION['demo_password_version'] ?? 1); }
    private function session(): SessionSecurity { return new SessionSecurity(10, 30, 'demo-playground', new DemoClock('session')); }

    private function storageBackend(string $backend, bool $other = false): AtomicStore
    {
        $namespace = $other ? 'demo-storage-other' : 'demo-storage';
        if ($backend === 'session') { return new SessionStore($namespace); }
        if ($backend === 'file') { return new FileStore($this->directory, $namespace); }
        if ($backend === 'memory') { return new MemoryStore(); }
        if ($backend === 'mysql') {
            $file = $this->directory . '/mysql.php';
            if (!extension_loaded('pdo_mysql') || !is_file($file)) { throw new \SoSecurity\Storage\StorageException('Demo MySQL not configured.', 'storage.not_configured'); }
            if (is_link($file) || (fileperms($file) & 0077) !== 0) { throw new \SoSecurity\Storage\StorageException('Private MySQL configuration required.', 'storage.configuration'); }
            $options = require $file;
            if (!is_array($options) || !isset($options['dsn'], $options['user'], $options['password'])
                || !is_string($options['dsn']) || strpos($options['dsn'], 'mysql:unix_socket=') !== 0) {
                throw new \SoSecurity\Storage\StorageException('Private local MySQL configuration required.', 'storage.configuration');
            }
            try {
                $pdo = new \PDO($options['dsn'], $options['user'], $options['password'], [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION, \PDO::ATTR_TIMEOUT => 2]);
                $store = new \SoSecurity\Storage\MySqlStore($pdo, $namespace);
                $store->prune(100);
                return $store;
            } catch (\PDOException $e) { throw new \SoSecurity\Storage\StorageException('Private MySQL unavailable.', 'storage.connection', $e); }
        }
        if ($backend === 'redis') {
            $socket = getenv('SOSECURITY_DEMO_REDIS_SOCKET');
            if (!$socket || !extension_loaded('redis')) { throw new \InvalidArgumentException('Demo Redis is not configured.'); }
            $redis = new \Redis();
            if (!$redis->connect($socket, 0, 2.0)) { throw new \RuntimeException('Demo Redis unavailable.'); }
            return new RedisStore($redis, $namespace);
        }
        throw new \InvalidArgumentException('Unsupported backend.');
    }
    private function checked(bool $valid, string $success = '验证通过。', string $failure = '验证被拒绝。'): void
    {
        $this->status = $valid ? 200 : 403;
        $this->result = ['valid' => $valid, 'message' => $valid ? $success : $failure];
    }
    private function record(string $event, bool $allowed): void
    {
        $logger = new AuditLogger(function (array $entry) {
            $_SESSION['demo_events'][] = $entry;
            $_SESSION['demo_events'] = array_slice($_SESSION['demo_events'], -20);
        }, $_SESSION['demo_audit_key']);
        $logger->record($event, 'demo', 'demo-visitor', ['allowed' => $allowed, 'status' => $this->status]);
    }

    private function dispatch(string $action): void
    {
        switch ($this->module) {
            case 'configuration':
                $config = ['site' => 'demo-factory', 'storage' => ['driver' => 'file', 'directory' => $this->directory]];
                if ($action === 'bad_option') { $config['csrf'] = ['ttll' => 30]; }
                $before = session_id();
                $factory = \SoSecurity\Security::fromArray($config);
                if ($action === 'construct') {
                    $token = $factory->csrf()->issue('form', $this->binding);
                    $this->result = ['configuration_valid' => true, 'session_unchanged' => $before === session_id(),
                        'csrf_valid' => $factory->csrf()->verify('form', $this->binding, $token)];
                } elseif ($action === 'diagnose') {
                    $this->result = ['checks' => $factory->diagnose($_SERVER['DOCUMENT_ROOT'] ?? null)];
                } elseif ($action === 'immutable') {
                    $factory->config()->policy('default')->limit = 0;
                } elseif ($action === 'store_failure') {
                    $broken = new class implements AtomicStore {
                        public function transact(string $key, callable $callback) {
                            throw new \SoSecurity\Storage\StorageException('Isolated demonstration outage.', 'storage.unavailable');
                        }
                    };
                    \SoSecurity\Security::fromArray(['site' => 'demo-fault', 'token_storage' => ['driver' => 'provided', 'connection' => 'fault']],
                        ['fault' => $broken])->csrf()->issue('form', $this->binding);
                } elseif ($action === 'lock_timeout') {
                    $path = $this->directory . '/isolated-' . bin2hex(random_bytes(8));
                    if (!mkdir($path, 0700)) { throw new \RuntimeException('Cannot allocate isolated demonstration.'); }
                    $handle = null;
                    try {
                        $store = new FileStore($path, 'fault', null, 20);
                        $hash = hash('sha256', "fault\0key");
                        $handle = fopen($path . '/lock-' . (hexdec(substr($hash, 0, 2)) % 64), 'c');
                        if ($handle === false || !flock($handle, LOCK_EX)) { throw new \RuntimeException('Cannot hold isolated lock.'); }
                        $store->transact('key', function () { return new Change(['n' => 1], 0, true); });
                    } finally {
                        if (is_resource($handle)) { flock($handle, LOCK_UN); fclose($handle); }
                        foreach (new \DirectoryIterator($path) as $entry) { if (!$entry->isDot()) { unlink($entry->getPathname()); } }
                        rmdir($path);
                    }
                }
                break;
            case 'upload':
                $sandbox = new UploadSandbox($this->directory, $_SERVER['DOCUMENT_ROOT'] ?? dirname(__DIR__) . '/demo/public');
                $this->result = $sandbox->perform($action, isset($_FILES['upload']) && is_array($_FILES['upload']) ? $_FILES['upload'] : []);
                break;
            case 'validation':
                $input = ['profile' => ['name' => '张小明', 'age' => 20, 'email' => 'demo@example.test', 'kind' => 'member']];
                if ($action === 'validate') {
                    $text = $this->input('json', 8192);
                    $input = json_decode($text, true, 16);
                    if (json_last_error() !== JSON_ERROR_NONE || !is_array($input)) { throw new \InvalidArgumentException('JSON object required.'); }
                } elseif ($action === 'invalid_sample') {
                    $input['profile']['age'] = '20'; $input['profile']['name'] = '中'; $input['profile']['email'] = 'bad';
                } elseif ($action === 'unknown_sample') { $input['profile']['admin'] = true; }
                $validator = new \SoSecurity\Validation\Validator(['profile' => ['type' => 'object', 'fields' => [
                    'name' => ['type' => 'string', 'min' => 2, 'max' => 20],
                    'age' => ['type' => 'integer', 'min' => 18, 'max' => 120],
                    'email' => ['type' => 'string', 'format' => 'email'],
                    'kind' => ['type' => 'string', 'enum' => ['member', 'guest']],
                ]]], 8192);
                $result = $validator->validate($input);
                $this->status = $result->valid() ? 200 : 422;
                $labels = ['validation.type' => '类型不正确，数字字符串不会自动转换。', 'validation.min' => '未达到最小长度或数值。',
                    'validation.max' => '超过最大长度或数值。', 'validation.format' => '格式不正确。', 'validation.unknown' => '未声明的字段被拒绝。',
                    'validation.required' => '缺少必填字段。', 'validation.enum' => '值不在允许列表中。'];
                $errors = [];
                foreach ($result->errors() as $error) { $error['message'] = $labels[$error['code']] ?? '字段未通过验证。'; $errors[] = $error; }
                $this->result = ['valid' => $result->valid(), 'errors' => $errors];
                if ($result->valid()) { $this->result['data'] = $result->data(); }
                break;
            case 'captcha':
                if (in_array($action, ['math', 'image', 'refresh'], true)) {
                    if ($action === 'refresh') { $this->captcha()->revoke('playground', $this->binding); }
                    $challenge = $action === 'image' ? $this->captcha()->image('playground', $this->binding)
                        : $this->captcha()->arithmetic('playground', $this->binding);
                    $_SESSION['demo_challenge'] = ['id' => $challenge->id, 'prompt' => $challenge->prompt,
                        'image' => $challenge->image === null ? null : 'data:image/png;base64,' . base64_encode($challenge->image),
                        'expires_at' => $challenge->expiresAt];
                    $this->result = ['message' => '已生成挑战；成功验证后不能重复使用。'];
                } elseif ($action === 'expire') {
                    (new DemoClock('captcha'))->advance(31);
                    $this->result = ['message' => '仅将当前访客验证码的演示时钟推进 31 秒；现在提交会被拒绝。'];
                } elseif ($action === 'turnstile') {
                    $secret = getenv('SOSECURITY_DEMO_TURNSTILE_SECRET');
                    $siteKey = getenv('SOSECURITY_DEMO_TURNSTILE_SITE_KEY');
                    if (!$secret || !$siteKey) {
                        $this->status = 503; $this->result = ['message' => 'Turnstile 尚未配置，未执行外部服务验证。'];
                    } else {
                        $provider = new Turnstile($secret, getenv('SOSECURITY_DEMO_TURNSTILE_HOST') ?: '72.rocky.wsl', 'demo');
                        $this->checked($provider->verify($_POST['cf-turnstile-response'] ?? null));
                    }
                } else {
                    $this->checked($this->captcha()->verify('playground', $this->binding,
                        $this->input('challenge_id', 32), $this->input('answer', 32)), '验证码通过，已失效。', '验证码错误、已过期、已使用或次数耗尽。');
                }
                break;
            case 'csrf':
                if ($action === 'issue') {
                    $_SESSION['demo_csrf_token'] = $this->csrf()->issue('playground', $this->binding);
                    $this->result = ['message' => '已生成有效期 30 秒的演示令牌。'];
                } elseif ($action === 'expire') {
                    (new DemoClock('csrf'))->advance(31); $this->result = ['message' => '演示时钟已推进 31 秒，请再次验证。'];
                } elseif ($action === 'revoke') {
                    $this->csrf()->revoke('playground', $this->binding); $this->result = ['message' => '当前场景令牌已撤销。'];
                } else {
                    $token = $action === 'replay' ? ($_SESSION['demo_csrf_used'] ?? '') : $this->input('token', 64);
                    if ($action === 'tamper' && strlen($token) === 64) { $token[0] = $token[0] === 'a' ? 'b' : 'a'; }
                    if ($action === 'once') { $_SESSION['demo_csrf_used'] = $token; }
                    $this->checked($this->csrf()->verify($action === 'cross_scope' ? 'other' : 'playground',
                        $this->binding, $token, in_array($action, ['once', 'replay'], true)));
                }
                break;
            case 'rate':
                if ($action === 'reset') {
                    $this->limiter()->reset('playground', $this->binding); $this->result = ['message' => '仅重置当前访客的演示额度。'];
                } elseif ($action === 'ban' || $action === 'permanent') {
                    $this->limiter()->ban('playground', $this->binding, $action === 'ban' ? 5 : null);
                    $this->result = ['message' => $action === 'ban' ? '已临时封禁 5 秒。' : '已人工永久封禁，可使用重置按钮解除。'];
                } else {
                    $decision = $this->limiter()->consume('playground', $this->binding);
                    $this->status = $decision->allowed ? 200 : ($decision->permanent ? 403 : 429);
                    if (!$decision->allowed && !$decision->permanent) { header('Retry-After: ' . $decision->retryAfter); }
                    $this->result = ['allowed' => $decision->allowed, 'remaining' => $decision->remaining,
                        'retry_after' => $decision->retryAfter, 'permanent' => $decision->permanent];
                }
                break;
            case 'password':
                $hasher = new PasswordHasher('bcrypt', ['cost' => 10]);
                $password = $this->input('password', 72);
                if ($action === 'hash') {
                    $_SESSION['demo_hash'] = $hasher->hash($password); $this->result = ['message' => '哈希已生成；明文不会保存或回填。', 'hash' => $_SESSION['demo_hash']];
                } elseif ($action === 'verify') {
                    $this->checked($hasher->verify($password, $_SESSION['demo_hash'] ?? ''));
                } elseif ($action === 'policy') {
                    $errors = (new PasswordPolicy())->errors($password);
                    $this->status = $errors ? 400 : 200; $this->result = ['errors' => $errors, 'valid' => !$errors];
                } else {
                    $upgrade = $hasher->verifyAndUpgrade($password, md5(self::TEST_PASSWORD), function ($plain, $stored) {
                        return hash_equals($stored, md5($plain));
                    });
                    $this->checked($upgrade->valid);
                    if ($upgrade->replacementHash !== null) { $this->result['replacement_hash'] = $upgrade->replacementHash; }
                }
                break;
            case 'reset':
                if ($action === 'issue') {
                    $_SESSION['demo_reset_token'] = $this->resetTokens()->issue($this->resetBinding());
                    $this->result = ['message' => '已生成演示重置令牌，有效期 120 秒。'];
                } elseif ($action === 'change_version') {
                    $this->resetTokens()->revoke($this->resetBinding());
                    $_SESSION['demo_password_version'] = ($_SESSION['demo_password_version'] ?? 1) + 1;
                    $this->result = ['message' => '演示账号版本已更新，旧令牌不能再使用。'];
                } else {
                    $token = $action === 'replay' ? ($_SESSION['demo_reset_used'] ?? '') : $this->input('token', 64);
                    if ($action === 'consume') { $_SESSION['demo_reset_used'] = $token; }
                    $this->checked($this->resetTokens()->consume($this->resetBinding(), $token));
                }
                break;
            case 'session':
                if ($action === 'rotate') { $this->session()->rotate(); $this->result = ['message' => 'Session ID 已更新，演示页面只显示摘要指纹。']; }
                elseif ($action === 'invalidate') { $this->session()->invalidate(); $this->checked($this->session()->touch()); }
                else {
                    if ($action === 'idle') { (new DemoClock('session'))->advance(11); }
                    if ($action === 'absolute') { (new DemoClock('session'))->advance(31); }
                    $this->checked($this->session()->touch(), '会话检查通过。', '会话已失效，需要重新建立演示会话基线。');
                }
                break;
            case 'network':
                if ($action !== 'fetch') { $this->result = NetworkSamples::run($action); break; }
                $budget = (new RateLimiter($this->store,new Policy(8,60,[60],120)))->consume('demo-outbound','fixed-target');
                if (!$budget->allowed) { $this->status=429; $this->result=['message'=>'受控外部演示额度已用完，请稍后重试。']; header('Retry-After: '.$budget->retryAfter); break; }
                $client = \SoSecurity\Security::fromArray(['site'=>'demo-outbound','outbound'=>['hosts'=>['www.php.net'],'response_bytes'=>16384,'budget_ms'=>3000]])->outbound();
                $response = $client->request('GET','https://www.php.net/robots.txt');
                $this->result=['target'=>'https://www.php.net/robots.txt','status'=>$response->status(),'bytes'=>strlen($response->body()),
                    'sha256'=>hash('sha256',$response->body()),'message'=>'真实HTTPS请求完成；不提供任意URL代理，不显示响应正文或敏感头。'];
                break;
            case 'api':
                if (in_array($action,['issue_key','rotate_key','sign','verify','replay'],true)) {
                    $budget=(new RateLimiter($this->store,new Policy(30,60,[10],120)))->consume('demo-api-allocation','global');
                    if (!$budget->allowed) { $this->status=429; $this->result=['message'=>'API 演示操作额度已用完，请稍后重试。']; header('Retry-After: '.$budget->retryAfter); break; }
                }
                $this->result=(new ApiSamples($this->store,$this->binding))->run($action,$this->input('api_token',128));
                if (isset($this->result['valid']) && !$this->result['valid']) { $this->status=403; }
                break;
            case 'stateless':
                $this->result=(new SignedCsrfSamples($this->binding,$this->base,$this->secure))->run($action,$this->input('token',256),$this->input('method',32),$this->input('path',2048));
                if (isset($this->result['valid']) && !$this->result['valid']) { $this->status=403; }
                break;
            case 'html':
                $this->result=HtmlSamples::run($action,$this->input('html',8192));
                break;
            case 'http':
                if ($action === 'resolve') {
                    $rules = preg_split('/\s*,\s*/', trim($this->input('trusted', 1024)), -1, PREG_SPLIT_NO_EMPTY);
                    $resolved = (new ClientIp(new IpRules($rules)))->resolve([
                        'REMOTE_ADDR' => $this->input('remote', 64), 'HTTP_X_FORWARDED_FOR' => $this->input('forwarded', 2048)]);
                    $this->result = ['resolved_ip' => $resolved, 'message' => '这是隔离的代理输入演示，不会改变实际请求信任配置。'];
                } elseif ($action === 'redirect') {
                    $this->result=['location'=>(new \SoSecurity\Http\Redirects('http://72.rocky.wsl',['https://www.php.net']))->target($this->input('target',2048)),
                        'message'=>'只显示审核后的Location，不让页面输入直接改变当前跳转。'];
                } elseif ($action === 'cors') {
                    $origin=getenv('SOSECURITY_DEMO_CORS_ORIGIN') ?: 'http://72.rocky.wsl:3000';
                    $decision=(new \SoSecurity\Http\Cors([$origin],['GET'],['x-demo-token']))->evaluate('OPTIONS',$this->input('origin',256),
                        $this->input('method',16),$this->input('request_headers',256));
                    $this->status=$decision->allowed()?200:403;
                    $this->result=['allowed'=>$decision->allowed(),'preflight_status'=>$decision->status(),'headers'=>$decision->headers(),'reason'=>$decision->reason(),
                        'message'=>'这是输入策略演示。cors.php只用服务端固定Origin，提供无会话的公开测试数据。'];
                } elseif ($action === 'permissions') {
                    $this->result=['Permissions-Policy'=>\SoSecurity\Http\PermissionsPolicy::build(['camera'=>[],'microphone'=>[],'geolocation'=>['self']])];
                } else {
                    $this->result = ['headers' => SecurityHeaders::build($this->input('csp', 2048), true),
                        'cookie_example' => Cookie::header('demo_token', 'example', '/', true, true, 'Lax', 300),
                        'message' => '仅展示建议值，不将输入的 CSP 或 Cookie 应用到站点。'];
                }
                break;
            case 'output':
                $input = $this->input('text', 4096);
                $this->result = ['html' => Escaper::html($input), 'javascript_json' => Escaper::json($input),
                    'url_component' => Escaper::urlComponent($input)];
                break;
            case 'audit':
                if ($action === 'clear') { $_SESSION['demo_events'] = []; $this->result = ['message' => '已清除此前日志，并保留本次清空操作记录。']; }
                else {
                    $logger = new AuditLogger(function ($entry) { $_SESSION['demo_events'][] = $entry; }, $_SESSION['demo_audit_key']);
                    $logger->record('login.failed', 'demo', 'sample-account',
                        ['password' => 'DEMO-SENSITIVE-VALUE', 'token' => 'DEMO-TOKEN', 'allowed' => false, 'status' => 401]);
                    $this->result = ['message' => '演示敏感字段未写入日志，主体使用独立密钥假名化。'];
                }
                break;
            case 'storage':
                $backend = $this->input('backend', 16);
                $key = 'demo-counter:' . hash('sha256', $this->binding);
                $operation = function ($value) use ($action) {
                    $count = $value['count'] ?? 0;
                    if ($action === 'increment') { ++$count; }
                    return new Change($count > 0 ? ['count' => $count] : null, time() + 60, $count);
                };
                $count = $this->storageBackend($backend)->transact($key, $operation);
                $this->result = ['backend' => $backend, 'count' => $count];
                if ($action === 'isolation') {
                    $this->result['other_namespace_count'] = $this->storageBackend($backend, true)->transact($key, $operation);
                }
                $_SESSION['demo_storage_result'] = $this->result;
                break;
        }
    }

    private function state(): array
    {
        switch ($this->module) {
            case 'html': return HtmlSamples::state();
            case 'stateless': return (new SignedCsrfSamples($this->binding,$this->base,$this->secure))->state();
            case 'api': return (new ApiSamples($this->store,$this->binding))->state();
            case 'network': return ['target'=>'https://www.php.net/robots.txt','resolver'=>'Google JSON DoH，固定TLS端点和bootstrap IP',
                'transport'=>extension_loaded('curl')?'已安装cURL，实际请求时验证网络/证书/地址与预算':'未安装cURL，真实请求未执行'];
            case 'upload': return ['files' => (new UploadSandbox($this->directory, $_SERVER['DOCUMENT_ROOT'] ?? dirname(__DIR__) . '/demo/public'))->files(),
                'maximum_bytes' => 1048576, 'maximum_files' => 3, 'retention_seconds' => 600, 'scanner' => '未配置真实扫描服务，故障按钮只使用隔离测试实现'];
            case 'captcha': return ['challenge' => $_SESSION['demo_challenge'] ?? null,
                'turnstile_configured' => (bool) (getenv('SOSECURITY_DEMO_TURNSTILE_SECRET') && getenv('SOSECURITY_DEMO_TURNSTILE_SITE_KEY'))];
            case 'csrf': return ['token' => $_SESSION['demo_csrf_token'] ?? null];
            case 'rate': $decision = $this->limiter()->inspect('playground', $this->binding);
                return ['allowed' => $decision->allowed, 'remaining' => $decision->remaining, 'retry_after' => $decision->retryAfter, 'permanent' => $decision->permanent];
            case 'password': return ['hash' => $_SESSION['demo_hash'] ?? null];
            case 'reset': return ['token' => $_SESSION['demo_reset_token'] ?? null, 'version' => $_SESSION['demo_password_version'] ?? 1];
            case 'session': $valid = $this->session()->touch();
                return ['valid' => $valid, 'fingerprint' => substr(hash('sha256', session_id()), 0, 12), 'idle_seconds' => 10, 'absolute_seconds' => 30];
            case 'audit': return ['events' => array_slice($_SESSION['demo_events'], -20)];
            case 'storage': return ['last_operation' => $_SESSION['demo_storage_result'] ?? null,
                'mysql_configuration' => extension_loaded('pdo_mysql') && is_file($this->directory . '/mysql.php') ? '已配置，操作时检查真实数据库' : '未配置，未执行 MySQL 演示',
                'redis_configuration' => getenv('SOSECURITY_DEMO_REDIS_SOCKET') ? '已配置，操作时检查连接' : '未配置，未执行 Redis 演示'];
            default: return [];
        }
    }

    private function form(string $content, bool $multipart = false): void
    {
        echo '<form method="post" data-demo-form' . ($multipart ? ' enctype="multipart/form-data"' : '') . '><input type="hidden" name="_csrf" value="'
            . Escaper::html($this->ui->issue('controls', $this->binding)) . '">' . $content
            . '<button class="secondary" type="button" data-ajax>AJAX 提交所选操作</button><output class="ajax-output" aria-live="polite"></output></form>';
    }
    private function button(string $action, string $label): string
    {
        return '<button type="submit" name="action" value="' . $action . '">' . $label . '</button>';
    }
    private function render(array $state): void
    {
        echo '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<title>' . self::MODULES[$this->module] . ' · SoSecurity</title><link rel="stylesheet" href="styles.css"><script src="app.js" defer></script></head><body>'
            . '<aside><a class="brand" href="?module=home">SoSecurity<span>PHP 安全组件演示</span></a><nav>';
        foreach (self::MODULES as $id => $label) {
            echo '<a href="?module=' . $id . '"' . ($id === $this->module ? ' aria-current="page"' : '') . '>' . $label . '</a>';
        }
        echo '</nav><p class="aside-note">开发候选<br>PHP ' . Escaper::html(PHP_VERSION) . '<br>无需框架</p></aside><main><header><span class="eyebrow">可操作的功能演示</span><h1>'
            . self::MODULES[$this->module] . '</h1><p>使用测试数据体验实际组件。每位访客的令牌、操作状态和日志独立保存。</p></header>';
        if ($this->result !== null) {
            echo '<section class="result" role="status"><h2>本次结果 · HTTP ' . $this->status . '</h2><pre>'
                . Escaper::html(json_encode($this->result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) . '</pre></section>';
        }
        echo '<section class="panel">';
        switch ($this->module) {
            case 'home':
                echo '<p>SoSecurity 是按需使用的 PHP 安全加固组件库，可逐项替换旧代码。自动封禁属于请求限流体系，不需要系统 Fail2ban。</p><div class="cards">';
                $descriptions = ['html'=>'成熟清理库、基础标签允许列表、资源预算和故障拒绝','stateless'=>'绑定登录的签名令牌、Cookie双重提交与精确豁免策略','api'=>'测试凭据签发、轮换、撤销；HMAC 篡改和原子重放拒绝', 'network'=>'固定公网目标、DNS/重定向逐跳检查与故障拒绝', 'upload' => '内容检测、图片重新编码、私有保存与故障拒绝', 'validation' => '严格类型、Unicode 长度、嵌套错误与字段白名单', 'configuration' => '简单初始化、只读诊断与故障拒绝', 'captcha' => '图片与算术、错误次数、刷新和单次使用', 'csrf' => '正常验证、篡改、跨场景、过期和重放',
                    'rate' => '请求预算、阶梯封禁、手动封禁与解除', 'password' => '哈希验证、基本策略和旧密码升级',
                    'reset' => '一次性令牌与密码版本绑定', 'session' => '标识更新、空闲超时与绝对超时',
                    'http' => '可信代理链、响应头和安全 Cookie', 'output' => 'HTML、JSON 数据与 URL 组件编码', 'audit' => '结构化记录、字段白名单和主体假名化', 'storage' => '原子计数、跨请求保存与命名空间隔离'];
                foreach ($descriptions as $id => $description) {
                    echo '<a class="card" href="?module=' . $id . '"><h2>' . self::MODULES[$id] . '</h2><p>' . $description . '</p><span>打开演示 →</span></a>';
                }
                echo '</div><p class="note">API 签名和受限请求已提供固定测试演示；MySQL 存储需要服务端配置后演示。Turnstile 需配置真实服务密钥后启用。演示不等于生产环境或独立安全审计验收。</p>';
                break;
            case 'configuration':
                echo '<h2>配置一次，按需使用</h2><p>工厂校验 PHP 数组配置，不自动启动 Session。诊断不修改存储；错误配置和故障演示只影响隔离的测试对象。</p>';
                $this->form($this->button('construct', '初始化并验证 CSRF') . $this->button('diagnose', '查看只读诊断')
                    . $this->button('bad_option', '模拟配置项拼错') . $this->button('immutable', '尝试修改策略')
                    . $this->button('store_failure', '模拟存储不可用') . $this->button('lock_timeout', '模拟文件锁超时'));
                break;
            case 'upload':
                echo '<h2>私有上传与内容验证</h2><p>仅上传测试用 JPEG/PNG，单文件最多 1 MiB、100 万像素，每位访客最多 3 个文件，保留 10 分钟。文件只保存到私有演示区，不提供下载或执行地址。</p>';
                $this->form('<label>测试图片<input type="file" name="upload" accept="image/png,image/jpeg"></label>' . $this->button('upload', '校验并私有保存') . $this->button('clear', '清理我的文件'), true);
                echo '<h2>正常、拒绝与故障测试样例</h2><p>以下按钮使用固定的私有测试数据；不能输入服务器路径或改变安全策略。</p>';
                $this->form($this->button('normal_sample', '正常 PNG 样例') . $this->button('fake_sample', '伪装成图片的脚本')
                    . $this->button('size_sample', '超出文件大小') . $this->button('path_sample', '路径穿越名称') . $this->button('budget_sample', '图片尺寸超预算')
                    . $this->button('scanner_reject', '模拟扫描拒绝') . $this->button('scanner_fail', '模拟扫描故障') . $this->button('store_fail', '模拟目录不合规'));
                echo '<p class="note">MIME 与重新编码不等于恶意文件扫描。当前没有连接真实扫描服务；图片会移除原始附加数据和元数据，JPEG会按配置质量重新压缩。</p>';
                break;
            case 'validation':
                echo '<h2>严格验证与字段错误定位</h2><p>JSON 数字和字符串按实际类型检查；中文长度按 Unicode 码点计算，不截断或删除输入。未声明字段被拒绝。错误代码由页面翻译，核心不绑定语言或框架。</p>';
                $this->form('<label>测试 JSON<textarea name="json" rows="7">' . Escaper::html('{"profile":{"name":"张小明","age":20,"email":"demo@example.test","kind":"member"}}') . '</textarea></label>'
                    . $this->button('validate', '验证输入') . $this->button('valid_sample', '正常测试样例')
                    . $this->button('invalid_sample', '类型与格式错误') . $this->button('unknown_sample', '尝试未声明字段'));
                break;
            case 'captcha':
                echo '<h2>生成与验证</h2><p>有效期 30 秒，最多错误 3 次；成功后再次提交会被拒绝。</p>';
                $this->form($this->button('math', '生成算术验证码') . $this->button('image', '生成图片验证码') . $this->button('refresh', '刷新并撤销旧挑战') . $this->button('expire', '模拟过期'));
                if ($state['challenge']) {
                    $challenge = $state['challenge'];
                    echo '<div class="challenge">' . ($challenge['image'] ? '<img alt="图片验证码" src="' . Escaper::html($challenge['image']) . '">' : '<strong>' . Escaper::html($challenge['prompt']) . '</strong>') . '</div>';
                    $this->form('<input type="hidden" name="challenge_id" value="' . Escaper::html($challenge['id']) . '"><label>答案<input name="answer" maxlength="32" autocomplete="off"></label>' . $this->button('verify', '验证答案'));
                }
                echo '<h2>Cloudflare Turnstile</h2>';
                if ($state['turnstile_configured']) {
                    echo '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" defer></script>';
                    $this->form('<div class="cf-turnstile" data-sitekey="' . Escaper::html(getenv('SOSECURITY_DEMO_TURNSTILE_SITE_KEY')) . '" data-action="demo"></div>' . $this->button('turnstile', '服务端验证'));
                } else { echo '<p class="note">尚未配置真实服务，外部验证未执行。算术与图片验证码可以直接体验。</p>'; }
                break;
            case 'csrf':
                echo '<h2>令牌生命周期</h2><p>普通验证允许重用；单次消费后的重放会被拒绝。篡改和跨场景按钮使用实际验证器。</p>';
                $this->form('<label>演示令牌<input name="token" maxlength="64" value="' . Escaper::html($state['token'] ?? '') . '"></label>'
                    . $this->button('issue', '生成令牌') . $this->button('verify', '正常验证') . $this->button('tamper', '篡改后验证')
                    . $this->button('cross_scope', '跨场景验证') . $this->button('once', '单次消费') . $this->button('replay', '重放已消费令牌')
                    . $this->button('expire', '模拟过期') . $this->button('revoke', '撤销令牌'));
                break;
            case 'stateless':
                echo '<h2>签名令牌与登录绑定</h2><p>核心不存储令牌。HMAC绑定站点、场景和当前登录标识；此页Session只用于演示控件及模拟身份。普通表单有效期内允许重用；需要单次消费请使用有状态CSRF方案。</p>';
                $this->form('<label>签名令牌<input name="token" maxlength="256" value="'.Escaper::html($state['token'] ?? '').'"></label>'
                    . $this->button('issue','签发或复用令牌') . $this->button('verify','正常验证') . $this->button('reuse','再次验证（允许重用）') . $this->button('tamper','篡改签名')
                    . $this->button('cross_scope','跨场景') . $this->button('cross_binding','跨登录绑定') . $this->button('double','实际Cookie双重提交') . $this->button('cookie_mismatch','Cookie不匹配')
                    . $this->button('expire','模拟过期') . $this->button('rotate_keep','轮换并保留上一密钥') . $this->button('rotate_drop','轮换并移除旧密钥')
                    . $this->button('binding_change','模拟新的登录绑定') . $this->button('bad_key','错误密钥配置样例'));
                echo '<h2>精确路由豁免策略</h2><p>固定示例仅豁免 POST /hooks/demo，真实路由仍须检查自己的认证。不会将此策略应用到演示站点。</p>';
                $this->form('<label>实际方法<input name="method" value="POST" maxlength="32"></label><label>完整路径<input name="path" value="/account/change" maxlength="2048"></label>' . $this->button('policy','查看是否需要Token'));
                echo '<p class="note">此HTTP开发入口使用独立、HttpOnly的演示Cookie，不能代表生产HTTPS及__Host- Cookie验收。密钥不交给浏览器；重新登录绑定变化或移除旧密钥会让旧令牌失效。</p>';
                break;
            case 'rate':
                echo '<h2>三次额度与封禁</h2><p>10 秒窗口允许 3 次请求，第 4 次触发 5 秒封禁；下一次越限封禁 15 秒。刷新页面查看恢复状态。</p><p class="note">此页仅限流当前访客的演示会话。实际跨会话 IP/账号限流需使用共享文件或 Redis；入口另有共享文件请求预算。</p>';
                $this->form($this->button('consume', '发送一次请求') . $this->button('ban', '临时封禁 5 秒')
                    . $this->button('permanent', '人工永久封禁') . $this->button('reset', '解除并重置'));
                break;
            case 'password':
                echo '<h2>原生哈希与验证</h2><p>仅输入测试密码，提交后不会回填明文。演示使用 bcrypt cost=10，组件默认 cost=12。</p>';
                $this->form('<label>测试密码<input type="password" name="password" maxlength="72" autocomplete="off"></label>'
                    . $this->button('hash', '生成哈希') . $this->button('verify', '验证当前哈希') . $this->button('policy', '检查密码策略') . $this->button('legacy', '旧 MD5 哈希升级'));
                echo '<p class="note">旧哈希升级仅演示已知格式的显式验证器。测试密码：<code>' . self::TEST_PASSWORD . '</code>。不建议新系统使用 MD5。</p>';
                break;
            case 'reset':
                echo '<h2>重置令牌</h2><p>有效期 120 秒，一次性消费；更新演示账号密码版本后，旧令牌会失效。这里不会修改真实账号或发送邮件。</p>';
                $this->form('<label>演示令牌<input name="token" maxlength="64" value="' . Escaper::html($state['token'] ?? '') . '"></label>'
                    . $this->button('issue', '生成令牌') . $this->button('consume', '消费令牌') . $this->button('replay', '重复消费') . $this->button('change_version', '更新密码版本'));
                break;
            case 'session':
                echo '<h2>会话状态</h2><p>演示空闲期限 10 秒、绝对期限 30 秒。过期模拟仅推进当前访客的演示时钟；更新标识会建立新的演示基线。</p>';
                $this->form($this->button('touch', '检查并更新活动时间') . $this->button('idle', '模拟空闲过期') . $this->button('absolute', '模拟绝对过期')
                    . $this->button('rotate', '更新 Session ID') . $this->button('invalidate', '标记失效'));
                break;
            case 'network':
                echo '<h2>固定目标的真实受限请求</h2><p>仅请求 https://www.php.net/robots.txt，通过有界 DoH 检查全部 A/AAAA、固定连接 IP、TLS 验证和逐跳目标检查。默认不读取代理或 Cookie，总预算 3 秒，响应最多 16 KiB，所有访客共用每分钟 8 次外部额度。</p>';
                $this->form($this->button('fetch','请求固定官方测试目标'));
                echo '<h2>隔离拒绝测试</h2><p>下面使用固定测试解析器/传输实现，展示真实安全检查的拒绝结果，不连接内网，也不把测试适配当公网验收。</p>';
                $this->form($this->button('private','内网地址拒绝') . $this->button('redirect_private','重定向到内网') . $this->button('rebind','DNS 地址变为内网')
                    . $this->button('peer','连接地址不匹配') . $this->button('oversize','响应超出预算'));
                break;
            case 'api':
                echo '<h2>短期 Bearer 测试凭据</h2><p>签发和轮换结果中的 token 只显示一次，请复制到下方验证。每位访客只保留一个有效测试凭据，120 秒到期；共享存储只保存摘要。网页操作仍需要 Session 和 CSRF。</p>';
                $this->form('<label>测试 token<input name="api_token" autocomplete="off" spellcheck="false" maxlength="128"></label>' . $this->button('issue_key','签发测试凭据') . $this->button('check_key','验证凭据与归属')
                    . $this->button('scope_key','尝试未授权范围') . $this->button('rotate_key','轮换测试凭据') . $this->button('revoke_key','撤销测试凭据'));
                echo '<h2>RFC 9421 有界签名配置档</h2><p>绑定方法、完整目标 URI、请求体摘要和 Content-Type；固定算法 HMAC-SHA256。密钥仅保留在服务器 Session，不显示给浏览器。此页在服务器内部调用组件，不连接示例目标。</p>';
                $this->form($this->button('sign','生成固定请求签名') . $this->button('tamper','篡改请求体') . $this->button('verify','验证并消费 Nonce') . $this->button('replay','再次验证同一签名')
                    . $this->button('expire','过期签名样例') . $this->button('store_failure','模拟 Nonce 存储故障'));
                echo '<p class="note">请先生成签名，再测试篡改、验证及重放。测试存储故障前请重新生成尚未消费的签名。真实业务仍须检查资源归属、权限和 TLS/代理边界；演示操作共用每分钟 30 次分配/消费额度。</p>';
                break;
            case 'http':
                echo '<h2>可信代理解析</h2><p>默认不信任转发头；下面的输入仅用于隔离模拟，不会配置网站的真实代理。</p>';
                $this->form('<label>直接连接地址<input name="remote" value="10.0.0.1"></label><label>可信代理 CIDR（逗号分隔）<input name="trusted" value="10.0.0.0/8"></label>'
                    . '<label>X-Forwarded-For<input name="forwarded" value="1.1.1.1, 203.0.113.2, 10.0.0.2"></label>' . $this->button('resolve', '解析客户端 IP'));
                echo '<h2>安全跳转目标</h2>';
                $this->form('<label>测试目标<input name="target" value="/SoSecurity/?module=home"></label>' . $this->button('redirect','检查跳转目标'));
                echo '<h2>CORS 预检与浏览器权限</h2><p>固定允许来源：http://72.rocky.wsl:3000。真实静态演示端点为 cors.php，不读会话或业务数据。</p>';
                $this->form('<label>Origin<input name="origin" value="http://72.rocky.wsl:3000"></label><label>方法<input name="method" value="GET"></label>'
                    . '<label>请求头<input name="request_headers" value="x-demo-token"></label>' . $this->button('cors','检查预检') . $this->button('permissions','生成权限策略示例'));
                echo '<h2>响应头示例</h2>';
                $this->form('<label>CSP 策略<input name="csp" value="default-src &#039;self&#039;"></label>' . $this->button('headers', '生成 Report-Only 与 Cookie 示例'));
                break;
            case 'output':
                echo '<h2>上下文编码</h2><p>结果以文本显示，输入不会被作为 HTML 或脚本执行。URL 组件编码不等于 URL 安全策略。</p>';
                $this->form('<label>测试文本<textarea name="text" rows="4">&lt;script&gt;alert("demo")&lt;/script&gt;</textarea></label>' . $this->button('encode', '查看编码结果'));
                break;
            case 'html':
                echo '<h2>经过允许列表清理的基础富文本</h2><p>默认演示只保留段落、强调、标题和列表等基础排版；脚本、样式、SVG/MathML、表单、图片及嵌入资源均移除。输入最多8 KiB，节点/属性合计256、解析深度24。</p>';
                if (!$state['dependency_ready']) { echo '<p class="note">可选HTML Purifier或DOM/ctype扩展未配置，真实清理未执行；请求会明确拒绝。</p>'; }
                $this->form('<label>测试HTML<textarea name="html" rows="6">'.Escaper::html('<p>中文<strong>粗体</strong><a href="https://example.com">链接</a></p>').'</textarea></label>'
                    . $this->button('clean','清理基础排版') . $this->button('links','清理并保留安全协议链接（源码）') . $this->button('normal','正常排版样例')
                    . $this->button('attack','脚本/资源攻击样例') . $this->button('size_limit','输入超限') . $this->button('tree_limit','嵌套超限') . $this->button('provider_failure','清理服务故障样例'));
                if ($state['last'] && $state['last']['preview']) {
                    // Only fixed-policy HTML Purifier output, never raw input or a custom provider, is previewed.
                    $preview='<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#039;none&#039;; base-uri &#039;none&#039;; form-action &#039;none&#039;"><body>'.$state['last']['output'].'</body></html>';
                    echo '<h2>清理后预览</h2><iframe class="html-preview" title="清理后的基础HTML预览" sandbox="" referrerpolicy="no-referrer" srcdoc="'.Escaper::html($preview).'"></iframe>';
                }
                echo '<p class="note">这是基础HTML正文片段，不保留任意样式、图片、脚本或编辑器扩展；输入验证和普通输出编码仍独立使用。链接版只显示源码，不加载资源。生产保留原始内容并预览迁移差异。</p>';
                break;
            case 'audit':
                echo '<h2>白名单与假名化</h2><p>日志仅保存在当前访客的演示 Session，最多显示 20 条；不连接生产日志系统。</p>';
                $this->form($this->button('record', '记录含模拟敏感字段的事件') . $this->button('clear', '清空演示日志'));
                break;
            case 'storage':
                echo '<h2>原子计数与隔离</h2><p>Session 与文件存储能跨请求保存计数，60 秒过期；内存存储只存在于本次请求。隔离检查读取另一个命名空间的同名键。</p>';
                $options = '<option value="session">Session</option><option value="file">本地文件</option><option value="memory">测试用内存</option>';
                if (extension_loaded('pdo_mysql') && is_file($this->directory . '/mysql.php')) { $options .= '<option value="mysql">MySQL（私有演示库）</option>'; }
                if (getenv('SOSECURITY_DEMO_REDIS_SOCKET')) { $options .= '<option value="redis">Redis</option>'; }
                $this->form('<label>存储后端<select name="backend">' . $options . '</select></label>'
                    . $this->button('increment', '原子递增') . $this->button('read', '读取计数') . $this->button('isolation', '检查隔离'));
                echo '<p class="note">MySQL 和 Redis 需要服务端配置独立连接；未配置时显示未执行。MySQL 仅使用私有演示表，记录 60 秒过期。内存存储不能用于生产请求限流。</p>';
                break;
        }
        echo '</section>';
        if ($state) {
            $display = $state;
            if (isset($display['challenge']['image']) && $display['challenge']['image'] !== null) {
                $display['challenge']['image'] = '[PNG 图片已在上方显示]';
            }
            echo '<section class="panel"><h2>当前状态</h2><pre data-demo-state>' . Escaper::html(json_encode($display, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) . '</pre></section>';
        }
        $examples = [
            'html'=>'$cleaner = $security->htmlCleaner();' . "\n" . '$fragment = $cleaner->clean($untrustedRichText);' . "\n" . '// 仅用于经过审查的HTML正文片段；普通文本继续Escaper/Twig自动转义。',
            'stateless'=>'$csrf = $security->signedCsrf();' . "\n" . '$token = $csrf->reuseOrIssue("orders:update", $verifiedLoginBinding, $existingCookie);' . "\n" . '$valid = $csrf->verifyDoubleSubmit("orders:update", $verifiedLoginBinding, $cookie, $submitted);' . "\n" . '// 私有密钥、已验证登录绑定和Cookie发送由宿主负责。',
            'api' => '$identity = $security->apiKeys()->fromAuthorization($authorization, "orders:read");' . "\n" . '$headers = $security->hmacSigner($signingKey)->sign("POST", $exactUri, $rawBody, "application/json");' . "\n" . '$identity = $security->hmacVerifier()->verify("POST", $exactUri, $rawBody, $headers, "orders:read");' . "\n" . '// 授权凭据管理、私有密钥、共享存储和资源归属由宿主提供。',
            'configuration' => '$security = SoSecurity\\Security::fromArray([' . "\n" . '    "site" => "my-site",' . "\n"
                . '    "storage" => ["driver" => "file", "directory" => "/private/site/security"],' . "\n" . ']);' . "\n" . '$csrf = $security->csrf();',
            'upload' => '$validator = new SoSecurity\\Upload\\Validator();' . "\n" . '$saver = new SoSecurity\\Upload\\Saver($validator, $privateDirectory, $actualDocumentRoot);' . "\n" . '$saved = $saver->saveUpload($_FILES["file"]);' . "\n" . '// 业务授权、CSRF、请求预算和保留清理由宿主提供。',
            'validation' => '$validator = new SoSecurity\\Validation\\Validator(["age" => ["type" => "integer", "min" => 18]]);' . "\n" . '$result = $validator->validate($input);' . "\n" . 'if ($result->valid()) { $data = $result->data(); }',
            'captcha' => '$captcha = new SoSecurity\\Captcha\\Captcha($store);' . "\n" . '$challenge = $captcha->arithmetic("login", $binding);' . "\n" . '$valid = $captcha->verify("login", $binding, $challengeId, $answer);',
            'csrf' => '$csrf = new SoSecurity\\Csrf\\CsrfTokens($store);' . "\n" . '$token = $csrf->issue("contact", $binding);' . "\n" . '$valid = $csrf->verify("contact", $binding, $submittedToken);',
            'rate' => '$limiter = new SoSecurity\\RateLimit\\RateLimiter($store);' . "\n" . '$decision = $limiter->consume("login", $ipAccountKey);' . "\n" . '// 拒绝时结束业务；验证密码前预占额度。',
            'password' => '$hasher = new SoSecurity\\Password\\PasswordHasher();' . "\n" . '$hash = $hasher->hash($password);' . "\n" . '$valid = $hasher->verify($password, $storedHash);',
            'reset' => '$tokens = new SoSecurity\\Password\\ResetTokens($store);' . "\n" . '$token = $tokens->issue($accountAndPasswordVersion);' . "\n" . '$valid = $tokens->consume($accountAndPasswordVersion, $submittedToken);',
            'session' => '$security = new SoSecurity\\Session\\SessionSecurity();' . "\n" . '$valid = $security->touch();' . "\n" . '// 宿主先启动 Session，检查失败后清除认证状态。',
            'network' => '$client = new SoSecurity\\Http\\Outbound\\Client(new SoSecurity\\Http\\Outbound\\Policy(["hosts" => ["api.example.com"]]));' . "\n" . '$response = $client->request("GET", $approvedUrl);',
            'http' => '$trusted = new SoSecurity\\Http\\IpRules(["10.0.0.10/32"]);' . "\n" . '$ip = (new SoSecurity\\Http\\ClientIp($trusted))->resolve($_SERVER);',
            'output' => '$text = SoSecurity\\Output\\Escaper::html($input);' . "\n" . '$data = SoSecurity\\Output\\Escaper::json($input);',
            'audit' => '$logger = new SoSecurity\\Audit\\AuditLogger($sink, $independentKey);' . "\n" . '$logger->record("login.failed", "login", $accountId, ["status" => 401]);',
            'storage' => '$store = new SoSecurity\\Storage\\SessionStore("my-site");' . "\n" . '// 验证码与 CSRF 可使用持锁 Session；跨 Session 限流选文件或 Redis。',
        ];
        if (isset($examples[$this->module])) {
            echo '<section class="panel"><details><summary>接入时的核心调用</summary><p>以下是 API 片段，存储、服务器侧绑定及业务变量由宿主初始化。</p><pre>'
                . Escaper::html($examples[$this->module]) . '</pre></details></section>';
        }
        echo '<footer>SoSecurity · 本地功能演示 · 数据不会写入真实业务账号</footer></main></body></html>';
    }
}
