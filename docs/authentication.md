# 认证、身份来源与共享会话撤销

原生文档业务 Bearer 路由、格式 3、浏览器及真实中断已接入；[本组证据](state-business-host-integration-2026-10-21.md)保留一次未解释 503，不能当作完整宿主验收通过。

原生 Bearer 已增加同一独立见证内的业务 PDO 组合入口 `withAuthorization`，只读对象／字段授权在 pending 前完成；详见[接入契约与有限证据](state-business-integration-2026-10-21.md)。业务 HTTP、真实中断及全部宿主验收仍未完成。

本地保护宿主已补 SQLite／MySQL 两端 HTTP／TLS 与持续真实时钟的请求中到期检查，见[后端与时钟验收](state-http-mysql-integration-2026-10-21.md)。测试控制器不进入产品接入；业务事务组合、全部宿主及最终恢复仍未完成。

受管示例已增加明确保护模式的 HTTP／TLS 接线：私有引导文件可返回同一 SDK 和纯状态策略，真实 CSRF／Origin 校验先于原生会话更新，Cookie 管理与 Bearer 路由分离。见[本地宿主验收及限定](state-http-integration-2026-10-21.md)；其他宿主、业务事务组合和最终安全恢复仍开放。

未发布候选新增显式[独立见证与认证状态边界](state-boundary.md)（[English](state-boundary.en.md)）。普通配置不会自动启用；显式 `authentication.state_boundary` 认证工厂已接入，见[工厂记录](state-factory-integration-2026-10-21.md)；完整全入口及最终安全恢复仍未完成，F01 保持开放。

新增能力按需启用，旧项目的 Session、账号模型和入口不自动改变。`session()` 仍是原生 PHP Session 配置／期限辅助；`sessions()` 为可撤销的共享认证登记；`authentication()` 组合身份提供器、请求保护和可选第二因素。

## 工厂接入

```php
$security = SoSecurity\Security::fromArray([
    'site' => 'my-site',
    'storage' => ['driver' => 'file', 'directory' => '/private/security'],
    'authentication' => ['identity_provider' => 'users', 'request_guard' => 'protected_request'],
], ['users' => $identityProvider, 'protected_request' => $requestGuard]);
$login = $security->authentication();
$sessions = $security->sessions();
```

身份提供器实现 `Auth\IdentityProvider`。服务器请求保护回调确认 POST、CSRF、HTTPS／代理边界和预算后返回严格 `true`；其他返回值及异常均阻止操作。回调接收阶段 `password`、`second_factor`、`cancel` 和作用域，不接受客户端的“已验证”布尔字段。

构造工厂不启动 Session、发头、联网或建表。工厂拒绝内存／Session 后端承担共享认证；直接构造也必须遵守后端契约。文件后端限本机私有目录，多节点使用实际共享存储。

## 身份来源与版本

`authenticate(scope, identifier, password)` 返回已验证的 `Account`；未知、错误和禁用返回 `null`。`find(scope, subject)` 每次读取当前账号、角色、凭据版本和 MFA 策略，故障必须抛异常，不能用缓存或 `null` 冒充正常结果。账号／认证结果／验证会话禁止序列化，避免把旧快照当成持久身份。

作用域、主体和版本均来自服务器；角色最多 32 个，并与 MFA 策略一起进入指纹。非秘密的撤销版本必须随禁用／重新启用、细粒度权限撤销、恢复和发行方生命周期变化而单调变化。组件无法发现从未被读取的历史状态，不应恢复原版本号。

`PasswordIdentityProvider` 连接按账号名、主体查询的两个回调，返回 `PasswordRecord|null`；宿主进行参数化查询、账号规范化和租户约束。保存的真实密码哈希也进入版本，即使旧系统漏更新版本号，改密仍使旧会话失效。

`PasswordRecord`的哈希与`LoginResult`的MFA挑战值不会出现在常见对象调试或`var_export()`输出中；这两个对象不能作为持久缓存反序列化。宿主须从当前账号存储或认证流程重建它们，并继续保护显式调用`hash()`、`challenge()`得到的敏感值。

部署预生成的占位哈希使用与已选 `PasswordHasher` 相同的算法和参数；它不是可登录账号的默认密码。验证有资源参数上限，不自动写库、通知或升级哈希。统一失败响应不保证绝对恒定耗时：查询、迁移算法和不同计算参数都可能产生时序差异。旧哈希继续通过既有迁移或 `CallbackIdentityProvider` 接入，成功比较更新后返回当前身份，不伪装成现代密码记录。

`CallbackIdentityProvider` 适配既有本地／配置／远程系统，检查结果类型、主体和作用域。[远程 SDK 示例](../examples/identity-providers.php)只映射显式选择的当前属性；SDK 负责可信固定目标、协议／服务凭据验证、TLS 和有界 I/O。这里没有实现 OAuth/OIDC/SAML，也不信任浏览器身份 JSON；联合身份在 R6 继续实现。

## 密码与 MFA

```php
$result = $login->password($tenant, $serverBinding, $identifier, $password, '设备标签');
// 仅当 status() 是 mfa_required 时，保存短期挑战；下一次受保护请求再调用：
$result = $login->secondFactor($tenant, $serverBinding, $pendingChallenge,
    ['type' => 'totp', 'code' => $submittedCode]);
```

`serverBinding` 来自当前浏览器受保护的服务器状态。所有 Cookie 写请求，包括登录、MFA、退出和撤销，仍需 CSRF。代码片段展示接口，不能跳过结果判断直接执行第二步。

| 结果 | 行为 |
| --- | --- |
| denied | 没有新的身份或凭据，统一认证拒绝 |
| mfa_required | 密码通过但尚无完整身份；挑战有期限、次数预算及单次完成限制 |
| enrollment_required | 策略要求 MFA 而未绑定；不授予登录或设置权限，宿主通过受控首次设置／恢复处理 |
| authenticated | 才能读取 `credential()` 与 `account()` 并建立宿主登录 |

成功后先更新原生 Session ID、登录绑定及 CSRF，再保存不透明登记凭据和主体；更新失败应拒绝登录并撤销新登记。可执行流程见 [authentication.php](../examples/authentication.php)。已有会员可在受保护的设置入口绑定因子；强制 MFA 的初始账号需经受控预配置／恢复流程完成设置。

启用原生状态保护时，`password`、`secondFactor` 和 `cancel` 在见证提交后、返回前再次只读检查 `StateRequestGuard::current()`。该回调会重复调用，须只检查当前请求权限，不产生业务写入。宿主状态边界需允许相应的 `authentication.password_check`、`authentication.second_factor_check`、`authentication.cancel_check` 只读检查。整次操作共享30秒时限；返回时过期的挑战或会话凭据拒绝返回。返回检查失败不回滚已提交的会话状态，也不退还已消耗的第二因素证明。请求回调异常使用 `auth.request_unavailable`，时间源异常使用 `auth.clock`，不携带原始异常详情。此行为不包含账号恢复启用。

顶层配置 `mfa` 后，认证工厂默认连接 `TotpSecondFactor`，避免遗漏已绑定因子；`authentication.second_factor` 可覆盖为明确注入的 `SecondFactor` 服务。已迁移到[受管理 MFA](account-factors.md)的宿主应显式设置 `authentication.managed_factors=true`：认证和会话工厂均从 `account_factors` 目录取得当前因子，不回退到原始 TOTP；不能同时配置 `second_factor` 或顶层 `mfa`，缺少目录配置直接拒绝。未启用该选项的现有配置保持原有行为。直接构造时显式传适配器。因子已绑定就要求第二因素；策略要求 MFA 却没有适配器属于配置错误。

挑战绑定账号指纹、因子版本、浏览器和撤销代际；TOTP 在原子消费中检查预期因子版本。改密、撤权、换因子和全部退出会使旧挑战无法完成。恢复码采用 `type=recovery`，其存储／预算见 [MFA 指南](mfa.md)。

## 会话和重新认证

每次业务请求调用 `verify(scope, subject, token, minimumStrength=0)`，检查当前身份、因子、共享记录、摘要、指纹和期限。主体和不透明凭据保存在受保护的宿主 Session，不直接采用提交的主体编号。缺少登记的旧会话需要重新登录。

原生 `examples/authentication.php` 对撤销指定会话与全部退出要求 300 秒内且至少强度 1 的当前认证；持久授权恢复的会话须先重新认证。拒绝时保持当前会话、其他会话和持久授权；普通退出始终可用。低层 `SessionRegistry` 不代替调用方的归属、近期认证、CSRF 或管理员授权检查。

共享记录仅存秘密摘要。`all()` 返回管理编号、方法、时间和标签，不包含秘密或摘要；记录存在不代表浏览器在线。`revoke()` 必须由宿主检查目标归属；`revokeAll()` 换随机代际并撤销全部会话，也阻止此前等待 MFA 的登录重新登记。每个已知账号保留一份代际标记，交由受控账号生命周期清理，不自动扫描或删除账号。

身份源明确无身份且登记凭据真实有效时，撤销该主体全部登记；故障则拒绝本次操作并保留故障语义。恢复后按当前版本重新检查。达到会话数量上限拒绝新登记，不暗中踢掉旧设备。

空闲与绝对期限分别检查；活动更新空闲时间，重新认证保留原绝对期限。收紧配置可收紧旧登记。重新认证调用 `password()` 最后一个参数传当前登记凭据，完成必要 MFA 后只轮换当前秘密，保留管理编号；宿主同时更新原生 Session ID。

`VerifiedSession::recent(maximumAge, now, minimumStrength=2)` 用于高风险操作；明确的密码策略可以要求强度 1。持久授权恢复保留原认证方式和时间，但 `resumed()` 为 true，`recent()` 始终拒绝，不能冒充近期密码／MFA 证明。对象权限仍由业务授权检查。详见 [记住登录](remembered-login.md)。

## 并发与失败

第二因素先领取原子短租约，身份源／验证器在事务外调用，最后核对持有者并单次消费挑战，再登记会话。过期租约的旧持有者不能生成第二个会话。挑战尚存且仍持有租约时，服务故障退回流程尝试额度，不延长期限；已消费的验证码／恢复码不会复活。挑战消费后登记失败需要重新认证。

身份源、挑战和登记没有跨资源事务承诺。结果丢失可能要求重新认证；不自动重放业务写入。授权与业务写入需严格一致时，宿主在自身事务中执行版本条件更新。远程撤销传播、持久性、备份和恢复分别由部署验收。

## 配置与示例

`authentication.identity_provider` 必填，创建认证流程还需 `request_guard` 服务；`second_factor` 为可选服务名，缺省按顶层 MFA 配置连接；`managed_factors` 默认为 `false`，启用时要求受管理目录的全部显式依赖。

| 选项 | 默认 | 范围 |
| --- | --- | --- |
| idle / absolute | 1800 / 28800 秒 | 1—31536000，空闲不超过绝对期限 |
| capacity | 16 | 1—32 个有界会话 |
| challenge_ttl | 300 秒 | 30—600 |
| claim_seconds | 10 秒 | 1—30；远程调用总预算应留在租约内 |
| attempts | 5 | 1—10，外层仍需账号／来源／成本预算 |

独立示例读取 `SOSECURITY_AUTH_EXAMPLE_CONFIG`、`SOSECURITY_AUTH_EXAMPLE_STORAGE` 和 `SOSECURITY_AUTH_EXAMPLE_DUMMY_HASH`（bcrypt cost12 占位哈希）。可选 `SOSECURITY_AUTH_EXAMPLE_KEY` 为 Base64 编码的独立 32 字节密钥；默认要求 HTTPS，仅明确本地测试设 `SOSECURITY_AUTH_EXAMPLE_HTTPS=0`。示例不内置真实账号、默认管理员或生产密钥，不注册宿主路由。

私有配置 JSON 字段：`username`、`subject`、`hash`、字符串 `version`，可选布尔 `enabled`、角色数组 `roles`、布尔 `mfa_required`。部署在 Web 根之外并设置私有权限。正式数据库宿主替换为自己的参数化查询，保持版本及故障语义。

PasswordRecord::account()保留权威业务账号及原始version；identity()返回PasswordIdentityProvider实际使用的身份，其版本包含原始version及保存密码哈希。会话核验继续使用该有效身份，不能改成只核对原始version，否则旧宿主漏增版本时无法发现哈希变更。业务SQL需要同时约束原始版本／保存哈希时，参考[操作授权事务](operations.md)的显式PasswordRecord映射，不能直接用有效version比较原始数据库列。

可选 `SOSECURITY_AUTH_EXAMPLE_DATABASE` 连接已存在的私有SQLite文档库，增加对象／字段／整批授权表单；不自动建表。角色、授权后按列读取和宿主事务／版本冲突处理见[授权指南](authorization.md)，与认证、MFA、CSRF职责分别检查。

`?module=auth` 仅使用每访客独立假账号及公开测试密码；成本10和模拟时间只用于演示。独立示例验证真实多浏览器、MFA、恢复码、Cookie／CSRF 和重新认证；当轮范围见 [验证记录](verification.md)。本地测试权威服务只验证契约，不代表实际发行方、生产 TLS 或联合身份验收。

参考：[OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)、[Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)。
