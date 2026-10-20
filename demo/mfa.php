<?php
declare(strict_types=1);

namespace SoSecurityDemo;

use SoSecurity\Crypto\Cipher;
use SoSecurity\Mfa\TotpFactors;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;

/** Isolated visitor playground: no real accounts; secrets never enter GET/state/audit responses. */
final class MfaSamples
{
    private $store;
    private $binding;

    public function __construct(AtomicStore $store, string $binding)
    {
        // Bound all demo records, including enabled factors, to ten minutes after their last access.
        $this->store = new class($store) implements AtomicStore {
            private $store;
            public function __construct(AtomicStore $store) { $this->store = $store; }
            public function transact(string $key, callable $callback)
            {
                $retention = time() + 600;
                return $this->store->transact($key, static function ($state) use ($callback, $retention) {
                    $change = $callback($state);
                    return new Change($change->value(), $change->expiresAt() === 0 ? $retention : min($retention, $change->expiresAt()), $change->result());
                });
            }
        };
        $this->binding = $binding;
    }

    private function manager(?AtomicStore $store = null): TotpFactors
    {
        if (!isset($_SESSION['demo_mfa_keys'])) { $_SESSION['demo_mfa_keys'] = ['current' => 'first', 'keys' => ['first' => random_bytes(32)]]; }
        $keys = $_SESSION['demo_mfa_keys'];
        return new TotpFactors($store ?? $this->store, new Cipher($keys['current'], $keys['keys'], 'demo:mfa:' . $this->binding), 'SoSecurity Demo');
    }

    public function run(string $action, string $code): array
    {
        $mfa = $this->manager();
        if ($action === 'begin') {
            $pending = $mfa->begin('demo', $this->binding, 'demo-visitor');
            $_SESSION['demo_mfa_pending'] = $pending->id();
            return ['valid' => true, 'enrollment_id' => $pending->id(), 'provisioning_uri' => $pending->provisioningUri(),
                'expires_at' => $pending->expiresAt(), 'message' => '仅此响应展示设置 URI；请用测试验证器设置并输入验证码。演示不涉及真实账号。'];
        }
        if ($action === 'confirm') {
            $codes = $mfa->confirm('demo', $this->binding, $_SESSION['demo_mfa_pending'] ?? '', $code);
            if ($codes !== null) { unset($_SESSION['demo_mfa_pending']); }
            return ['valid' => $codes !== null, 'recovery_codes' => $codes, 'message' => $codes === null ? '确认未通过。' : '已绑定；恢复码只在本次响应显示，请使用测试凭据。'];
        }
        if ($action === 'regenerate') {
            $codes = $mfa->regenerateRecoveryCodes('demo', $this->binding, $code);
            return ['valid' => $codes !== null, 'recovery_codes' => $codes, 'message' => $codes === null ? '需要未使用过的有效验证码。' : '恢复码已替换，旧码失效。'];
        }
        if ($action === 'clear') {
            $mfa->revoke('demo', $this->binding); unset($_SESSION['demo_mfa_pending']);
            return ['valid' => true, 'message' => '仅当前访客的测试因子已清除。正式账号恢复须另行验证身份。'];
        }
        if ($action === 'rotate') {
            $current = $_SESSION['demo_mfa_keys'];
            // Two demo versions are enough; repeated rotation keeps both until re-encryption commits.
            $id = $current['current'] === 'first' ? 'second' : 'first';
            $keys = $current['keys']; $keys[$id] = random_bytes(32);
            $next = new TotpFactors($this->store, new Cipher($id, $keys, 'demo:mfa:' . $this->binding), 'SoSecurity Demo');
            $changed = $next->reencrypt('demo', $this->binding);
            if ($changed) { $_SESSION['demo_mfa_keys'] = ['current' => $id, 'keys' => [$id => $keys[$id]]]; }
            return ['valid' => $changed, 'message' => $changed ? '当前测试因子已重加密，演示会话已移除旧密钥。' : '没有可轮换的因子，或遇到并发修改。'];
        }
        if ($action === 'store_failure') {
            $broken = new class implements AtomicStore { public function transact(string $key, callable $callback) { throw new StorageException('Fixed MFA demo fault.', 'storage.unavailable'); } };
            $this->manager($broken)->verify('demo', $this->binding, $code);
        }
        if ($action === 'disable') { $valid = $mfa->disable('demo', $this->binding, $code); }
        elseif ($action === 'recovery') { $valid = $mfa->verifyRecovery('demo', $this->binding, $code); }
        elseif ($action === 'verify') { $valid = $mfa->verify('demo', $this->binding, $code); }
        else { throw new \SoSecurity\Exception\ConfigurationException('Unknown MFA demo operation.'); }
        return ['valid' => $valid, 'message' => $valid ? '测试证明已通过；验证码时间步或恢复码已消费。' : '证明、期限、重放或错误预算检查未通过。'];
    }

    public function state(): array
    {
        if (!extension_loaded('sodium')) { return ['available' => false, 'message' => '缺少 sodium 扩展，MFA 加密演示未执行。']; }
        return ['available' => true, 'factor' => $this->manager()->status('demo', $this->binding),
            'limits' => '绑定 300 秒；连续失败 5 次冷却 60 秒；测试状态闲置 10 分钟后过期；设置 URI 和恢复码只在生成结果显示。'];
    }
}
