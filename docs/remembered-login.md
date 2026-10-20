# 记住登录、轮换与撤销

`Auth\RememberedLogin` 是显式选择的持久授权。默认不开启，不启动 Session，也不发送 Cookie；宿主仍负责身份、HTTPS、POST／CSRF、请求预算、授权归属和用户同意。原生接入见 [authentication.php](../examples/authentication.php)。

## 接入与状态

```php
$security = SoSecurity\Security::fromArray([
    'site' => 'my-site',
    'storage' => ['driver' => 'file', 'directory' => '/private/security'],
    'authentication' => ['identity_provider' => 'users', 'request_guard' => 'protected_request'],
    'remember' => ['keys' => 'remember_keys'],
], [
    'users' => $identityProvider,
    'protected_request' => $requestGuard,
    'remember_keys' => new SoSecurity\Support\HmacKeys('current', $privateKeySnapshot),
]);
$remember = $security->rememberedLogin();
```

`requestGuard(phase, scope)` 仅严格 `true` 表示检查通过。阶段为 `remember_issue`、`remember_resume`、`remember_forget`、`remember_list`、`remember_revoke`。读取管理列表也需宿主授权，不采用提交的主体作为管理对象。工厂要求共享原子后端，拒绝 MemoryStore／SessionStore；直接构造需传同一存储、身份源、时钟和会话策略。

用户在近期完整登录后主动选择“记住此设备”，宿主才调用：

```php
$credential = $remember->issue($tenant, $trustedSubject, $currentSessionToken, '设备标签');
if ($credential !== null) {
    header('Set-Cookie: ' . $security->rememberCookieHeader($credential), false);
}
```

恢复通过受保护 POST 调用 `resume(scope, cookieToken)`。先建立匿名 Session 和 CSRF，再请求恢复；GET 不产生登录。成功后轮换宿主 Session ID／CSRF，保存返回的主体与 `session()` 凭据，最后发送 `nextCredential()` Cookie。原生 Session 更新失败时撤销新登记；不能先向业务宣布登录成功。

| status() | 宿主处理 |
| --- | --- |
| authenticated | 唯一可建立登录的结果，更新宿主 Session 和两个凭据 |
| retry | 另一请求已轮换；本请求没有登录权限，不发送／删除持久 Cookie，提示刷新或重新登录 |
| invalid | 无效、过期、已撤销或身份变化，拒绝恢复并清除本地 Cookie |
| replayed | 已识别真实旧代际重放，同事务撤销该主体所有会话／持久授权，要求完整登录 |
| step_up | 宿主风险策略要求完整重新认证；同事务撤销该设备授权及关联会话，不创建新会话；完整登录后由用户主动签发新授权 |
| blocked | 宿主确认设备凭据已泄露；同事务撤销该设备授权及关联会话，不提供新令牌 |

不自动重试恢复。响应丢失时可能无法取回新令牌；服务器不保存明文新令牌供旧请求重取，用户重新登录。

## 可选可信设备风险决策

`remember.risk_guard` 可指定一个宿主服务名。未配置时保留原有恢复行为；配置后工厂要求该服务可调用。恢复请求在签名令牌和定位索引有效后调用 `risk_guard(scope, subject, selector)`，它必须返回 `Auth\DeviceRiskDecision`。返回值类型错误、回调抛错或服务缺失均拒绝恢复，不发放新会话；回调在可重试存储事务之外执行，不应修改业务状态。宿主只能使用服务端已核实的网络、设备与账号风险信号；不得把客户端自报的设备标签、请求头或 IP 文本直接当成信任证明。

`Auth\DeviceRiskPolicy::decide()` 提供固定优先级和原因码。宿主必须提供 `compromised`、`anomalous`、`changed`、`reauth_required` 四个布尔值；缺项、未知项或非布尔值直接报配置错误。`compromised` 优先返回 `deny/compromised`；其余任一风险返回 `step_up`，依次为 `anomalous`、`changed`、`reauth_required`；全部为 `false` 才返回 `allow/none`。原因码不含原始设备、IP 或账号证据。示例：

```php
$policy = new \SoSecurity\Auth\DeviceRiskPolicy();
$riskGuard = function (string $scope, string $subject, string $selector) use ($policy) {
    // 四个布尔值必须来自宿主可信来源及其当前风险规则。
    return $policy->decide([
        'compromised' => false,
        'anomalous' => false,
        'changed' => false,
        'reauth_required' => false,
    ]);
};
// 配置 remember.risk_guard = 'device_risk'，并在服务表注入 $riskGuard。
```

`step_up` 与 `blocked` 的 `RememberResult::reason()` 提供固定原因码，供服务端审计；不要在未认证页面公开详细风险原因。两者均在同一主体事务中撤销该设备授权及关联会话，宿主都应清除本地 Cookie，且不得建立登录态。`step_up` 引导完整密码／MFA 重新认证；如果风险判断是误判，风险解除后旧令牌仍不能恢复，用户可在完整登录后主动签发新授权。这样后续环境信号变化不能绕过已经要求的强证明。现有期限、容量、账号变更和重放规则仍先于允许恢复；真实宿主的风险信号来源、误判申诉、通知、跨节点一致性与浏览器验收仍属于 R6.3 后续工作。

原生[认证示例](../examples/authentication.php)分别处理两个结果：`step_up` 返回 HTTP 403／`auth.reauthentication_required` 并清除持久 Cookie，完整密码／MFA 登录仍可用；`blocked` 返回 HTTP 401／`auth.denied` 并清除持久 Cookie。示例可通过服务端环境变量 `SOSECURITY_AUTH_EXAMPLE_RISK_SIGNALS` 注入四项严格布尔 JSON 作本地演示；它是在服务进程启动时固定的测试快照，不是生产风险数据源，不接受请求参数覆盖。未设置时示例保持原恢复行为；正式宿主应注入当前可信风险服务。

## 认证强度与期限

恢复保留原认证方式及原 `authenticatedAt()`，包含原有密码／TOTP／恢复码证明；它是持续授权，并不表示刚完成了一次认证。`VerifiedSession::resumed()` 为 `true`，`recent()` 始终返回 `false`。改密、支付、因子管理等敏感操作必须走完整密码／MFA 重新认证，再进行业务对象授权。不得只检查 `strength()` 判断“近期认证”。宿主可对管理端完全禁用持久登录。

重新认证保持当前会话编号和绝对期限，设置 `resumed=false`；不会顺便延长持久授权。需要新期限时再次由用户主动选择并调用 `issue()`。同一会话再次签发替换此前授权，不叠加设备数。

持久授权期限固定为原认证时间加 `ttl`，轮换不续期。恢复会话的绝对期限取授权剩余期限与会话策略中的较短者，活动只更新空闲时间。持久授权到期会终止依赖它的恢复会话；已独立完成重新认证的会话可继续自身剩余期限。

`ttl` 是签发策略，调整它不改写既有授权的固定期限。缩短全站持久授权期限时，宿主需撤销既有授权或提高身份撤销版本，再要求完整登录；不能只改配置并假定历史Cookie已失效。容量收紧同样拒绝新增，不自动踢掉既有设备。

| 配置 | 默认 | 边界 |
| --- | --- | --- |
| keys | 必填服务名 | 独立 HmacKeys，32—128 字节随机密钥、最多8版本 |
| ttl | 2592000 秒 | 1—31536000；从原认证时间计算 |
| capacity | 8 | 每主体1—16授权，满额拒绝、不踢旧设备 |
| fresh_age | 300 秒 | 1—3600；签发需近期非恢复登录 |
| concurrency_grace | 5 秒 | 0—10；只允许重试，不允许第二次授权 |
| risk_guard | 不配置 | 可选宿主服务；返回固定 `DeviceRiskDecision`，错误时拒绝恢复 |
| cookie_name | __Host-SoSecurityRemember | Secure、HttpOnly、SameSite=Lax，无 Domain |
| secure / path | true / / | `__Host-` 强制 HTTPS、根路径 |

本地 HTTP 测试必须显式换无前缀名称并设 `secure=false`；诊断标记为不满足正式传输要求。Cookie 过期不代替服务器期限。

## 原子轮换与重放

令牌由随机设备选择器、递增代际、256位随机秘密及 HMAC-SHA256 认证组成，MAC 绑定作用域和密钥编号。共享状态保存完整令牌摘要，不保存原令牌／明文秘密。旧密钥快照保留至其所有授权到期；移除密钥后旧 Cookie 拒绝恢复。其他协议使用独立密钥。

设备选择器到主体的单独索引只定位账本，没有认证权力。全部可变授权、当前摘要、代际、关联会话及撤销代际位于同一主体记录，所以一次原子事务同时完成秘密轮换和会话登记；重放撤销亦在该事务完成，不依赖跨键删除。

真实旧代际在短并发窗口内只返回 `retry`，不再次发身份或凭据。窗口后再次使用即撤销全部设备和会话，也使此前等待 MFA 的登录失效。无效 MAC 或当前代际的错误摘要不能借此撤销他人授权。最多保存8个短窗口记录；超过该数量的极端并发可能触发保守撤销，宿主限制恢复频率并串行化浏览器请求。持有已泄露 Cookie 的攻击者仍可在首次消费时取得持续授权，重放检测不能事先证明持有者是本人。

`all(scope, trustedSubject)` 返回管理编号、关联会话编号、原认证／签发／使用／到期时间和标签，不含令牌、摘要、MAC。标签仅用于展示，不代表硬件身份或风险证明。`revoke()` 撤销指定持久授权及关联会话；`SessionRegistry::revoke()` 也撤销对应持久授权，即使短会话已经过期。`revokeAll()` 覆盖全部，并更换代际。

`forget(scope, cookieToken)` 支持匿名浏览器主动忘记设备：真实签名凭据只允许撤销对应授权／会话，不读取身份或授予登录。仍需 POST／CSRF，完成后清除本地 Cookie。原生示例退出时同时撤销服务器授权及删除 Cookie。

## 迁移、故障和资源

共享会话账本由 v1 升至 v2。读取严格验证 v1 的全部字段，再在同次事务写为 v2；已有会话保持凭据／期限，初始无持久授权。v2 增加 `remember` 和会话来源／关联字段，损坏或未知版本拒绝使用，不静默重置。旧工作进程不能读取 v2：升级需先停止旧认证工作进程，再切换新版本；回滚到旧代码需要受控失效现有账本并要求完整登录。此候选尚未发布，不自动操作宿主存储。

主体记录上限32会话、16授权，每授权最多8个并发记录，标签最多128字节；配合现有64KiB存储预算。选择器索引随原期限过期；失败签发尝试删除刚分配索引，撤销后尚存索引也不能恢复权限。文件后端需使用现有有界过期清理；宿主对签发／撤销入口和存储总量施加预算。账号账本的永久撤销代际只在受控账号生命周期中清理。

身份源、存储、密钥缺失和时钟倒退均拒绝操作。身份指纹包含保存的密码哈希／撤销版本、角色、MFA策略和因子绑定；它们变化后旧授权失效。身份源在事务外读取，严格业务一致性仍需宿主数据库的版本条件更新。不要将未被读取的禁用后重新启用恢复为旧版本。

原子回调可重试，不执行网络或生成随机值。存储提交后响应／身份复核失败可能消耗一次轮换，不能将异常当成成功或换用本地状态。备份恢复、Redis持久性和多节点一致性需单独部署验收。

恢复旧备份可能复活历史摘要和会话，组件不承诺跨状态恢复的永久重放历史。恢复流程应在开放流量前撤销受影响账号的全部共享会话／授权，并退役旧持久签名密钥；仅删除浏览器Cookie或只轮换密钥不能撤销备份中的短会话。账号枚举、备份一致性和恢复操作由宿主完成。

## 示例与验证

原生示例增加可选 `SOSECURITY_AUTH_EXAMPLE_REMEMBER_KEY`（Base64独立32字节密钥）；完整登录后用户点击记住设备。恢复／忘记／查询／撤销都是 POST，不在页面或 JSON 输出秘密。未配置时不出现持久登录操作。

专项入口：`tests/remember.php`、`tests/device-risk.php`、`tests/remember_http.py`、`tests/device_risk_http.py`、`tests/concurrency.php`；当轮已执行证据见 [verification.md](verification.md)。独立消费者、真实 Cookie／Session、浏览器、生产和独立安全审查分别记录。设备风险决策与完整可信设备策略继续 R6.3。

设计参考：[Symfony Remember Me](https://symfony.com/doc/current/security/remember_me.html) 的主动选择／重新认证边界，以及 [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) 的服务器期限、Cookie 和会话更新要求。本组件的协议和事务行为以上述契约为准。
