# 简单配置与只读诊断

独立见证可通过 `authentication.state_boundary` 显式选择[受管理认证工厂](state-factory-integration-2026-10-21.md)，复用准确 FileStore、边界、会话、因子与纯权限策略；普通配置不会自动启用。完整生命周期及最终安全恢复仍未完成，详见[接口指南](state-boundary.md)。

可选`upload_quarantine`提供持久隔离工厂`quarantine()`，显式注入扫描器并要求共享持久状态，和原`upload`同步保存配置独立。配置／构造不扫描或写入任务，诊断不把配置有效当作实际扫描通过；字段与迁移边界见[隔离指南](upload-quarantine.md#工厂配置与诊断)。

可选 `authentication` 配置连接身份提供器与请求保护服务，提供 `authentication()` 和 `sessions()`；同时配置 MFA 时默认连接 TOTP。迁移到受管理因子目录后可显式设置 `managed_factors=true`，要求 `account_factors` 配置并与 `second_factor`、顶层 `mfa` 互斥；两种工厂都使用当前受管理目录，不回退到原始 TOTP。它们保留现有 `session()` 原生辅助；字段、顺序和撤销边界见[认证指南](authentication.md)。

可选 `remember` 需先配置 `authentication`，另注入独立 `keys` 服务；默认30天固定期限、最多8个授权、5秒并发重试窗口和 `__Host-` Secure Cookie。可选 `risk_guard` 指定可信设备风险决策服务；宿主必须提供服务端已核实的信号，返回固定决策，异常时拒绝恢复。显式主动选择、恢复／忘记／撤销及全部字段见[记住登录指南](remembered-login.md)。恢复会话的 `recent()` 拒绝敏感操作，不自动启用持久登录。

可选 `authorization` 注入 `identity_provider`、可选 `policy`／`audit` 服务，不依赖共享存储；身份服务名可沿用已配置的authentication。无策略默认拒绝，不能用身份查询代替宿主登录验证。字段白名单／批量全量预检及配置边界见[授权指南](authorization.md)。

本轮新增可选 `mfa` 配置和 `Security::mfa()`，使用独立注入的加密服务及共享存储，详见 [MFA 与密钥加密](mfa.md)。旧配置不启用 MFA，工厂不会自动生成密钥。

`SoSecurity\Security::fromArray()` 是可选工厂。所有原有组件仍能独立实例化，不依赖框架、容器、YAML或环境变量加载库。工厂创建时只校验配置；不启动Session，不发送响应头，不建立网络连接，也不创建存储目录。

## 最小接入

可选 `budgets` 保存最多64个命名的加权策略，工厂提供 `budgetLimiter(name)`、`budgetGroup(names)` 与 `budgetComposite(names)`，均要求共享storage。默认令牌桶10单位／60秒；算法、字段、原子范围及策略迁移见[请求预算](request-budgets.md)。它不改变既有rate_limits和封禁行为。

```php
require 'vendor/autoload.php';
$security = SoSecurity\Security::fromArray([
    'site' => 'my-site',
    'storage' => ['driver' => 'file', 'directory' => '/private/my-site/security'],
]);
// 宿主按自己的流程先启动Session并保留锁；binding必须由服务器生成并保存在会话内。
$csrf = $security->csrf();
$captcha = $security->captcha();
$login = $security->rateLimiter();
$hasher = $security->passwordHasher();
```

目录由部署提前创建为应用拥有的0700私有目录，放在Web根之外。当前FileStore依赖POSIX私有权限，原生Windows目录不能通过此检查；不要跳过检查或降级为MemoryStore，平台证据见platforms.md。默认验证码/CSRF使用原生Session，跨会话请求限流和密码重置使用显式配置的共享storage。不需要存储的密码辅助可以只配置site。仅在调用需要共享存储的功能时，未配置storage才报错。

FileStore状态节点须为不超过64KiB的普通文件，锁条带须为空普通文件。读取和清理会拒绝FIFO等异常节点，并核对打开描述符与实际路径；检查后替换也不能使打开FIFO无限等待。合法只读数据仍可读取，原子替换后权限仍为0600。新拒绝先后及本地证据见[节点修复](file-store-nodes-2026-10-24.md)。

原生登录完整例子见 [legacy-login.php](../examples/legacy-login.php)，密码重置宿主SQL版本比较例子见 [password-reset.php](../examples/password-reset.php)。后者不自动建表、发送邮件或提交宿主事务；演示账号表结构由测试/宿主明确创建。

## 按场景选择最小配置

[configuration-presets.php](../examples/configuration-presets.php)返回八种独立PHP配置，覆盖六类场景；不读取环境/请求、写目录或初始化服务。选择一份并改为自己的固定site；不要把所有预设一起启用。

```php
$presets = require 'vendor/sohophp/sosecurity/examples/configuration-presets.php';
$config = $presets['login_file'];
$config['site'] = 'shop-production';
$config['storage']['directory'] = '/private/shop/security'; // 部署预先创建的私有目录
$security = SoSecurity\Security::fromArray($config);
```

| 预设 | 需要补充 | 用途 |
| --- | --- | --- |
| form_session | 固定site；宿主启动且持锁的Session、服务器生成的binding | 有状态CSRF/验证码 |
| login_file | 私有目录，已确认的客户端IP及账号规范化 | 同主机跨会话登录预算 |
| login_redis | services.security_redis独立连接、可信部署初始化 | 多进程/多站点共享预算 |
| login_mysql | services.security_db独立PDO、部署建表 | InnoDB共享预算 |
| api_signing | 真实固定HTTPS origin；私有SigningKey | 仅签名，不自动接入认证/验证端 |
| signed_form | services.csrf_keys的HmacKeys；已验证的当前登录绑定 | 无状态CSRF |
| rich_text | 明确安装可选HTML Purifier及DOM/ctype | 基础正文HTML清理 |
| upload_quarantine | Web根外的0700隔离目录与状态目录、实际Web根、宿主注入的Scanner、部署初始化的共享状态 | 强制扫描后才允许读取的上传隔离；配置解析不运行扫描器或创建任务 |

login预设保留独立的ip和login策略；调用方先消费IP总量，再按规范化IP+账号消费login预算，认证/验证码与业务仍由宿主控制。API验证端另配置共享storage和key_provider，不能把仅签名的预设误当完整API认证入口。

## 顶层配置参考

| 项 | 默认 | 规则 |
| --- | --- | --- |
| site | 必填 | 1–128字节固定站点标识，无控制字符；Session命名空间禁止竖线和感叹号；php_binary序列化时需满足最终键长度；同一部署一致，不含秘密 |
| storage | 未配置 | 共享后端，用于跨会话限流和密码找回 |
| token_storage | driver=session | 验证码/CSRF后端；可以显式选择文件、Redis、MySQL或自定义存储 |
| csrf | ttl=7200，capacity=16，exemptions=[] | 秒；容量1–64；精确method/path豁免最多32项 |
| stateless_csrf | 未配置 | keys服务必填；ttl=7200秒，1–86400；不会生成默认密钥 |
| api | 未配置 | origin必填；默认HTTPS、maximum_lifetime=300秒、clock_skew=30秒、maximum_body=1048576字节；验证端需key_provider |
| api_credentials | 未配置，不启用 | 需要authentication、共享storage及独立keys／request_guard／scope_provider；可选management_subject与management_authorization必须成对；范围默认空、ttl=86400、capacity=16、fresh_age=300、minimum_strength=1、delegated_minimum_strength=2；见[账号凭据](api-credentials.md) |
| webhooks | 空端点列表，不启用 | 最多32个命名端点，scope／account／url／protocol必需；接收侧key_provider／request_guard成对配置，inbox显式提供connection／integrity_keys／association_guard；processing显式提供connection／integrity_keys／mapper／association_guard／worker_guard，可选management_guard及policy；仅历史处理可省略接收服务与inbox，见[接收](webhooks.md)与[处理](webhook-processing.md)；不要求authentication或通用storage |
| idempotency | 不启用 | 显式connection／64字符十六进制外部epoch／integrity_keys／authority服务及可选management_guard／policy；工厂idempotency()，不依赖authentication或通用storage，不自动建表或初始化命名空间，见[SQL幂等](idempotency.md) |
| outbox | 不启用 | 显式connection／64字符十六进制外部epoch／integrity_keys／authority服务及可选management_guard／policy；工厂outbox()，入队与显式对账只加入同一PDO的宿主事务，其他操作独立拥有短事务；对账另需每次传入当前决策guard与实际审计依据，不自动建表／初始化／发送，见[事务发件箱](outbox.md)及[超期对账](outbox-reconciliation.md) |
| accounts | 不启用 | 显式同PDO账号库、作用域／epoch、当前账号适配、独立密钥、通知及共享请求预算；registration_authority／request_guard／recovery_authority分别启用注册／地址变更／密码恢复，后者可配置recovery_factor／strong_recovery；管理／通知读取省略拒绝，不建表或发信，见[账号生命周期](account-lifecycle.md)和[密码恢复](account-recovery.md) |
| html | 未配置 | 显式启用；输入65536/输出131072字节、2048节点、64深度、2048属性字节、allow_links=true；自定义sanitizer需审查 |
| captcha | ttl=300，attempts=3，capacity=4 | 秒；错误预算1–10，并存1–16 |
| rate_limits | default策略 | 命名策略，每个limit/window/bans/history_ttl；默认5/300/[60,300,900]/86400 |
| budgets | 空，不启用 | 最多64个命名策略；algorithm=token_bucket、limit=10、window=60、burst=null、maximum_entries=512；组合最多8项，详见[预算指南](request-budgets.md) |
| leases | 未配置，不启用 | maximum=1、ttl=30、maximum_lifetime=300；共享storage，显式资源初始化与业务隔离，详见[租约指南](leases.md) |
| operations | 未配置，不启用 | 依赖authentication／authorization及请求保护；ttl=120、capacity=8、maximum_age=300、minimum_strength=2、methods=[totp,webauthn]；默认不接受密码／恢复码，保护模式可显式 operations($stateAccountPolicy) 启用原生准入，要求准确认证图及纯 RolePolicy；默认 operations() 保留手工外层授权组合，详见[操作授权](operations.md) |
| signed_links | 未配置，不启用 | 显式origin／keys／request_guard；ttl=300、maximum_ttl=86400、capacity=32、allow_http=false；共享状态撤销／消费及严格URL，见[签名链接](signed-links.md) |
| downloads | 未配置，不启用 | 显式directory／temporary_directory／document_root；policy默认20MiB完整核验／响应、3秒I/O、30秒传输、64KiB分块；授权／权威索引显式注入，见[下载指南](downloads.md) |
| password | bcrypt，cost=12，minimum=15，maximum_bytes=72；blocklist=builtin、breach_checker=null | Argon2id默认上限4096字节，不会静默降级；本地表／泄露服务名和故障边界见[密码指南](passwords.md) |
| outbound | 未配置 | hosts必填；默认有界DoH+cURL，预算/白名单及可选resolver/transport服务见[outbound.md](outbound.md) |
| upload | 未配置 | directory/document_root必填；按需的类型/图片预算与scanner；见[upload.md](upload.md) |
| session | idle=1800，absolute=28800，secure=true，same_site=Lax | 不自动应用；调用configureSession才生效；path/domain/lifetime未指定时保留宿主已有值 |

所有未知项、错类型、非法范围都会拒绝，包括配置值显式为null的错误节点；字符串数字不自动当整数。配置和Policy不可变，数组中的外部引用也不能修改已校验的策略。

```php
$security = SoSecurity\Security::fromArray([
    'site' => 'shop',
    'storage' => ['driver' => 'redis', 'connection' => 'security_redis', 'budget_ms' => 1000, 'attempts' => 32],
    'rate_limits' => ['login' => ['limit' => 5, 'window' => 300, 'bans' => [60, 300, 900], 'history_ttl' => 86400]],
], ['security_redis' => $existingDedicatedConnectedRedis]);
// 此Redis namespace需先在可信部署脚本中initializeStorage；请求里不自动恢复。
$decision = $security->rateLimiter('login')->consume('login', $ipAccountKey);
```

连接对象由宿主显式注入。Redis必须是独立、已连接的phpredis客户端，无prefix/serializer；工厂不获取、打印或保存密码。Redis提交使用原子CAS Lua，需要EVAL权限；读取先在同一个原子脚本内执行STRLEN与GET，Redis账号还需STRLEN和GET权限。普通状态值超过65536字节、ready标记超过512字节时，客户端不接收原值并拒绝操作；缺少命令权限同样拒绝。网络等待按总预算限制。文件配置支持lock_timeout_ms（默认1000，1–30000）。Redis首次部署/重启后需[显式初始化或审核恢复](redis-recovery.md)，新格式会隔离旧状态，不能在请求里自动清空封禁。

`driver=mysql, connection=security_db, lock_wait_seconds=1` 接收独立PDO MySQL连接；1–30秒行锁等待，部署阶段显式建独立InnoDB表，不触碰宿主事务。网络/查询超时与客户端认证需宿主确认，见[mysql.md](mysql.md)。

`driver=provided, connection=service_name` 可以注入AtomicStore；工厂添加逻辑站点/用途命名空间。自定义后端必须真实满足原子契约，诊断不能证明它的跨进程能力，会标记人工确认。MemoryStore和SessionStore即使通过provided包装，也不能用于工厂的跨会话限流/找回密码。

服务和存储使用同一个注入Clock：`Security::fromArray($config, $services, $clock)`。生产默认系统时钟；Redis键TTL仍要求服务器时钟同步。时间预算独立于测试用令牌Clock。

输入验证独立使用 `new SoSecurity\Validation\Validator($fields)`，不会要求配置整个Security工厂。字段配置、Unicode/NFC及错误本地化见[validation.md](validation.md)。

## 会话配置是显式动作

```php
$security = SoSecurity\Security::fromArray([
    'site' => 'shop',
    'session' => ['secure' => true, 'same_site' => 'Lax', 'path' => '/admin', 'lifetime' => 0],
]);
$security->configureSession(); // 在宿主session_start之前
session_start();
header('Set-Cookie: ' . $security->sessionCookieHeader(), false);
if (!$security->session()->touch()) { /* 宿主退出认证，拒绝请求 */ return; }
```

默认保留宿主cookie_path、cookie_domain和cookie_lifetime，同时启用strict_mode、仅Cookie、HttpOnly等保护。PHP7.2仍需在start/rotate后显式发送生成的SameSite Cookie；生成头保持实际path/domain/lifetime，不把SameSite拼进路径。Domain扩大Cookie可见范围，host-only通常更合适；已有Domain配置先审核再迁移。`__Host-`要求Secure、路径/且无Domain。

## 只读诊断

```php
$checks = $security->diagnose($knownDocumentRoot);
```

结果包含pass/fail/manual/not_configured/optional和稳定reason，不包含密码、令牌、连接对象、真实目录路径或异常完整文本。检查可选扩展、目录权限及Web根位置、存储选择和Session状态。未启动Session不是自动帮你启动；第三方驱动互斥锁、自定义后端原子性不能自动证明。

Redis默认不进行网络探测，显示manual。显式 `diagnose($root, true)` 才执行有界PING、CONFIG GET maxmemory-policy和无写入的`EVAL return 1`权限检查，再以原子STRLEN/GET限量读取ready标记，并通过INFO核对初始化状态；`bounded_read_permission`单独报告限量读取是否可用，不修改服务器配置、业务键或持久化设置。CONFIG GET因权限不可读时，淘汰策略显示人工确认，不假装通过。使用独立诊断连接，禁止混入宿主事务。

CLI配置文件是运营者信任的PHP文件，位于私有目录，返回：

```php
return ['config' => ['site' => 'shop', 'storage' => ['driver' => 'file', 'directory' => '/private/shop/security']],
    'document_root' => '/var/www/shop/public'];
```

```sh
php bin/diagnose.php /private/security-config.php
php bin/diagnose.php /private/security-config.php --probe
```

退出码：0无已确认失败（仍可能有人工确认项）；1检查失败/服务不可用；2配置无效。不要把退出码0当作所有部署安全条件已验证。

## 错误处理与开发候选迁移

| 类型 | 含义 | 宿主处理 |
| --- | --- | --- |
| ConfigurationException | 未知项/错类型/策略修改/后端选择错误 | 修复配置；不能继续敏感操作 |
| ValidationException | 需要抛异常的输入编码/格式错误 | 返回正常输入错误，不曝光异常全文 |
| StorageException | 连接、锁、提交、损坏记录、资源预算失败 | 停止敏感操作，通常返回503 |
| DependencyException | 验证服务或必要扩展不可用 | 停止依赖此防护的业务 |
| verifier返回false | 普通令牌、验证码或密码验证失败 | 按业务返回400/403/统一登录失败 |

`reason()`是稳定分类接口，不能按英文异常message判断。核心状态变化Change改为value()/expiresAt()/result()读取，Policy改为limit()/window()/banDurations()/historyTtl()读取；自定义AtomicStore按此更新。当前未发布开发候选允许修正这些API，不把更改伪装成稳定版本兼容。

工厂物理存储命名空间为site:shared与site:tokens。原有直接组件的命名空间不会自动改名或迁移；切换真实旧站时先验证并行保护和旧记录保留期，不因引入工厂清空现有封禁。

重置示例以宿主数据库version CAS防止旧令牌覆盖新密码。保存成功后的撤销故障返回reset.applied_cleanup_pending，明确密码已经更新；旧版本令牌不能越过SQL版本检查。宿主事务回滚不会复活已消费令牌，需要重新发令牌，不能由库提交或回滚宿主事务。

## API 凭据与签名

`apiKeys()` 只要求共享 storage，无需 HMAC 配置。`hmacSigner(SigningKey)` 要求 `api.origin`，不要求验证用存储或 KeyProvider。`hmacVerifier()` 同时要求可信 origin、共享 storage 及对应 `api.key_provider` 服务；不自动生成生产秘密。工厂拒绝 MemoryStore/SessionStore 及其命名空间包装作为 API 状态。

api 的固定配置档、默认值与完整示例见 [api.md](api.md)。诊断 `api.key_provider/api.request_boundary/api.transport` 分别提示可信密钥生命周期、原始请求和 TLS/代理边界尚需宿主验收；仅签名端未提供 key_provider 时标记 not_configured，显式配置却未注入正确服务时 fail。只读诊断不加载/列出密钥，不把 HTTPS 配置字符串当成实际 TLS 验收。

## 可选无状态 CSRF

配置 `stateless_csrf => ['keys'=>'private_csrf_keys','ttl'=>7200]`，服务注入 `Support\HmacKeys`，`signedCsrf()` 不要求storage或Session。ttl整数1–86400秒；key服务必填，无默认秘密。`csrfPolicy()` 使用csrf.exemptions纯决策，不自动关闭任何路由检查。密钥加载/可信登录绑定、Cookie及实际认证由宿主提供，诊断只读并标记需人工核实。完整双重提交示例、轮换及失败/迁移边界见 [signed-csrf.md](signed-csrf.md)。

## 可选富文本清理

显式 `html => []` 启用默认受限HTML Purifier适配，`htmlCleaner()` 要求宿主安装可选包及DOM/ctype。输入/输出/节点/深度/属性预算、allow_links默认值和限制见 [html-cleaning.md](html-cleaning.md)。自定义html.sanitizer需注入经过审查的HtmlSanitizer；诊断只读，不构造或调用它，安全策略/渲染上下文标记manual。没有原文返回、strip_tags或正则“清理”的降级方案。


邮箱丢失恢复使用 `accounts.mailbox_authority` 和 `accounts.mailbox_approval` 两个显式服务名称，调用 `Security::mailboxRecovery()`；启用请求权限而未配置强审批会拒绝配置。原有恢复参数与行为保持。MFA账号还需当前 `recovery_factor`，独立管理／投递服务沿用 `management_guard`／`delivery_guard`；模板明确增加 `recover_address` HTTPS地址。真实审批人、消费凭据保留、因子绑定和备份代际均属于宿主必须验证的契约，详见[邮箱恢复指南](account-mailbox-recovery.md)。


## 显式受管理 MFA 目录

可选 `account_factors` 与 `accounts` 分别配置。必须显式给出 `connection`、`scope`、`epoch`、`repository`、`integrity_keys`、`totp`、`fence`、`worker_guard`、`read_guard`、`management_guard`，另可指定完整账号 `policy`。除scope／epoch／policy外均为服务名称；没有默认放行权限。`repository` 必须实现 `Account\FactorRepository` 并使用同一个PDO，`totp` 必须为未受管理的 `Mfa\TotpFactors`，`fence` 必须匹配site／scope／epoch。

`Security::accountFactors()` 建立强类型 `FactorWorkerAuthority`，保持其SQL预算，并返回 `FactorRegistry`；不自动建表、创建栅栏、登记根、迁移因子、发送通知或改变账号。诊断仅检查能力／上下文并将当前注册权威、同PDO、迁移审批及备份代际标为待人工验收，不调用权限回调证明通过。完整步骤和示例见[受管理因子接入](account-factors.md)。

保护模式的三个公开生命周期服务可在建立准确 `StateAccountConnection` 后增加 `accounts.state_request_guard`，服务必须实现 `Account\StateRequestGuard`。它负责 pending 前的公开请求检查和锁内复查，与地址变更的 `accounts.request_guard` 用途不同。未选择该能力仍需显式外层边界；选择后由服务自行执行公开方法的边界，不能再嵌套包装。管理／投递／业务权限保持独立，详见[公开请求接入](state-request-integration-2026-10-21.md)。


### 受保护的账号凭证工厂

已配置 `authentication.state_boundary` 时，用同一 `Security::stateAccountPolicy()` 生成的纯策略调用 `$sdk->apiCredentials($stateAccountPolicy)`。该工厂复用准确缓存的会话／因子／身份服务和实际认证 FileStore，缺少策略或传入另一服务图的策略均拒绝。直接调用返回服务的公开方法，勿再包一层 `boundary->run()`。请求保护和范围回调必须只读；委托仅支持同一身份提供方、不含效果审计的原生 `RolePolicy`。普通未保护配置不需要追加参数。范围、失败语义和未完成项见[接线记录](state-api-entry-integration-2026-10-21.md)。


原生保护的签名链接使用 `Security::signedLinks($stateAccountPolicy)`，沿用显式 `signed_links` 密钥／来源／请求保护配置，但使用准确认证存储和会话图。管理与验证使用 For 方法；业务 SQL 使用 `withVerification`。未传状态策略的保护工厂继续拒绝，见[原生接入与验收](state-native-links-integration-2026-10-22.md)。


原生重置证明显式调用 `resetTokens($ttl,$stateAccountPolicy,$requestGuard,$addressColumn,$addressVersionColumn)`，默认邮箱列 address／address_version。请求授权签名为 `(entry, scope, ?AccountRecord): bool`，必须只读并严格允许；缓存拒绝更换授权函数或列映射。返回的证明仅供受信任交付，完整恢复仍使用 Account\Recovery。准确约束见[原生入口](state-native-reset-integration-2026-10-22.md)。


保护模式的 `hmacVerifier($statePolicy,$keySource,$sourceName,$requestGuard)` 必须声明实际 `KeyRingStateSnapshot(PDO,profile,KeyRing,SignaturePolicy)`，并加入同一完整来源。缓存固定状态映射、来源对象／名称及授权回调；原生只接受具体 KeyRing，在线 KeyProvider 保持普通模式或等待适配。请求保护签名为 `(entry, Identity, ?Intent, method, url): bool`，仅在只读准入调用。新增来源及修改密钥／策略不能自动初始化或采纳旧根，见[接入说明](state-native-hmac-integration-2026-10-22.md)。

受保护工作进程栅栏的实际目录必须在建立见证前通过 `FenceStateSnapshot` 加入同一完整来源；缺失时构造及原生工厂拒绝。完整声明、容量及迁移限制见[工作进程栅栏来源](state-snapshots.md#工作进程栅栏的实际来源)。

## 选项预检查预算（2026-10-22）

固定选项映射在复制键、合并默认值或断开PHP引用前，先按允许键数量拒绝超大输入；未知键仍逐项拒绝。此检查覆盖核心配置、验证规则、角色规则及独立密码、会话、出站请求、上传／隔离、下载、凭据／签名、Webhook、幂等、Outbox、账号和HTML策略。Webhook重试间隔在复制前执行既有20项上限。合法选项、默认值与公开签名不变；宿主仍须限制配置或请求进入PHP数组前的解析成本。

Fixed option maps reject excessive key counts before copying or merging. Existing accepted keys, defaults and public signatures remain unchanged. Webhook retry arrays retain their20-entry limit, now checked before copying. Hosts must still bound parsing before PHP array construction.
