<?php
declare(strict_types=1);
namespace SoSecurityDemo;

use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Auth\PasswordIdentityProvider;
use SoSecurity\Auth\PasswordRecord;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Password\PasswordHasher;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\SessionStore;

/** Visitor-owned fake account. Real multi-browser accounts and TOTP flows use examples/authentication.php. */
final class AuthSamples
{
    private $store;
    private $binding;
    private $clock;
    private const PASSWORD = 'Demo-only-7.2!';
    private const CHANGED = 'Changed-demo-7.2!';
    public function __construct(AtomicStore $store, string $binding)
    {
        $this->store = new class($store) implements AtomicStore {
            private $store;
            public function __construct(AtomicStore $store) { $this->store = $store; }
            public function transact(string $key, callable $callback)
            {
                $retention = time() + 600;
                return $this->store->transact($key, static function ($old) use ($callback, $retention) {
                    $change = $callback($old);
                    return new Change($change->value(), $change->expiresAt() === 0 ? $retention : min($retention, $change->expiresAt()), $change->result());
                });
            }
        };
        $this->binding = $binding; $this->clock = new DemoClock('auth');
    }
    private function entry(): array
    {
        if (!isset($_SESSION['demo_auth_entry'])) {
            $hasher = new PasswordHasher('bcrypt', ['cost' => 10]);
            $_SESSION['demo_auth_entry'] = ['hash' => $hasher->hash(self::PASSWORD), 'dummy' => $hasher->hash('Demo-dummy-only-password'), 'version' => 1, 'enabled' => true, 'roles' => ['member']];
        }
        return $_SESSION['demo_auth_entry'];
    }
    private function provider(): PasswordIdentityProvider
    {
        $lookup = function (string $scope, string $id, bool $username): ?PasswordRecord {
            if ($scope !== 'demo-auth' || $id !== ($username ? 'demo' : $this->binding)) { return null; }
            $entry = $this->entry();
            return new PasswordRecord(new Account('demo-auth', $this->binding, (string) $entry['version'], $entry['enabled'], $entry['roles']), $entry['hash']);
        };
        return new PasswordIdentityProvider(function (string $scope, string $id) use ($lookup) { return $lookup($scope, $id, true); },
            function (string $scope, string $id) use ($lookup) { return $lookup($scope, $id, false); }, new PasswordHasher('bcrypt', ['cost' => 10]), $this->entry()['dummy']);
    }
    private function guard(): bool
    {
        $csrf = new CsrfTokens(new SessionStore('demo-controls'), 3600, 32);
        return ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && $csrf->verify('controls', $this->binding, $_POST['_csrf'] ?? null);
    }
    private function sessions(): SessionRegistry { return new SessionRegistry($this->store, $this->provider(), null, $this->clock, 15, 120, 4); }
    public function run(string $action, string $password, string $id): array
    {
        if (!$this->guard()) { throw new \SoSecurity\Exception\SecurityException('Demo request protection failed.', 'auth.request_denied'); }
        $sessions = $this->sessions();
        if ($action === 'login' || $action === 'reauthenticate') {
            $flow = new AuthenticationFlow($this->store, $this->provider(), $sessions, function (): bool { return $this->guard(); }, null, $this->clock);
            $result = $flow->password('demo-auth', $this->binding, 'demo', $password, '当前访客测试会话',
                $action === 'reauthenticate' ? ($_SESSION['demo_auth_token'] ?? 'missing') : null);
            if ($result->status() === 'authenticated') {
                (new \SoSecurity\Session\SessionSecurity(1800, 28800, 'demo-auth'))->rotate();
                $_SESSION['demo_auth_token'] = $result->credential()->token();
            }
            return ['valid' => $result->status() === 'authenticated', 'outcome' => $result->status(), 'message' => $result->status() === 'authenticated' ? '测试身份已建立，原生 Session ID 已更新；注册凭据只保留在服务器。' : '账号状态、密码或重新认证目标未通过。'];
        }
        if ($action === 'source_failure') {
            $offline = new CallbackIdentityProvider(function () { throw new \SoSecurity\Exception\SecurityException('Fixed demo identity outage.', 'auth.source_unavailable'); },
                function () { throw new \SoSecurity\Exception\SecurityException('Fixed demo identity outage.', 'auth.source_unavailable'); });
            (new SessionRegistry($this->store, $offline, null, $this->clock))->epoch('demo-auth', $this->binding);
        }
        if ($action === 'password_change') {
            $entry = $this->entry(); $entry['hash'] = (new PasswordHasher('bcrypt', ['cost' => 10]))->hash(self::CHANGED);
            ++$entry['version']; $_SESSION['demo_auth_entry'] = $entry;
        } elseif ($action === 'roles_change' || $action === 'disable' || $action === 'enable') {
            $entry = $this->entry(); ++$entry['version'];
            if ($action === 'roles_change') { $entry['roles'] = $entry['roles'] === ['member'] ? ['reader'] : ['member']; }
            else { $entry['enabled'] = $action === 'enable'; }
            $_SESSION['demo_auth_entry'] = $entry;
        } elseif ($action === 'revoke_all' || $action === 'clear') {
            $sessions->revokeAll('demo-auth', $this->binding); unset($_SESSION['demo_auth_token']);
            if ($action === 'clear') {
                // Drop only this visitor's fake registry before resetting its simulated clock.
                $this->store->transact(\SoSecurity\Support\Guard::key('auth-sessions', 'demo-auth', $this->binding), function () { return new Change(null, 0, null); });
                unset($_SESSION['demo_auth_entry'], $_SESSION['demo_offsets']['auth']);
            }
        } elseif ($action === 'revoke') {
            return ['valid' => $sessions->revoke('demo-auth', $this->binding, $id), 'message' => '仅尝试撤销当前访客所拥有的管理编号。'];
        } elseif ($action === 'idle') { $this->clock->advance(15); }
        elseif ($action === 'recent') { $this->clock->advance(6); }
        elseif ($action === 'absolute') { $this->clock->advance(120); }
        elseif ($action !== 'verify') { throw new \SoSecurity\Exception\ConfigurationException('Unknown authentication demo action.'); }
        $current = $sessions->verify('demo-auth', $this->binding, $_SESSION['demo_auth_token'] ?? null);
        $check = in_array($action, ['verify', 'recent'], true);
        return ['valid' => $check ? $current !== null && ($action !== 'recent' || $current->recent(5, $this->clock->now(), 1)) : true,
            'message' => $current === null ? '当前没有有效测试身份；状态变化、撤销或期限会在服务端拒绝旧会话。' : '当前测试会话有效；高风险业务应另行检查近期认证和对象权限。'];
    }
    public function state(): array
    {
        $sessions = $this->sessions(); $verified = $sessions->verify('demo-auth', $this->binding, $_SESSION['demo_auth_token'] ?? null);
        if ($verified === null) { unset($_SESSION['demo_auth_token']); }
        return ['authenticated' => $verified !== null, 'current_id' => $verified === null ? null : $verified->id(),
            'recent_authentication' => $verified !== null && $verified->recent(5, $this->clock->now(), 1), 'enabled' => $this->entry()['enabled'],
            'roles' => $this->entry()['roles'], 'sessions' => $sessions->all('demo-auth', $this->binding),
            'limits' => '仅当前访客的假账号；最多四个测试会话，空闲 15 秒、绝对 120 秒；闲置 10 分钟清理测试状态。真实多浏览器／MFA 接入见独立认证示例。'];
    }
}
