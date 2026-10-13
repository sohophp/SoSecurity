# 简单配置与只读诊断

`SoSecurity\Security::fromArray()` 是可选工厂。所有原有组件仍能独立实例化，不依赖框架、容器、YAML或环境变量加载库。工厂创建时只校验配置；不启动Session，不发送响应头，不建立网络连接，也不创建存储目录。

## 最小接入

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

原生登录完整例子见 [legacy-login.php](../examples/legacy-login.php)，密码重置宿主SQL版本比较例子见 [password-reset.php](../examples/password-reset.php)。后者不自动建表、发送邮件或提交宿主事务；演示账号表结构由测试/宿主明确创建。

## 顶层配置参考

| 项 | 默认 | 规则 |
| --- | --- | --- |
| site | 必填 | 1–128字节固定站点标识，无控制字符；Session命名空间禁止|与!；php_binary序列化时需满足最终键长度；同一部署一致，不含秘密 |
| storage | 未配置 | 共享后端，用于跨会话限流和密码找回 |
| token_storage | driver=session | 验证码/CSRF后端；可以显式选择文件、Redis、MySQL或自定义存储 |
| csrf | ttl=7200，capacity=16，exemptions=[] | 秒；容量1–64；精确method/path豁免最多32项 |
| captcha | ttl=300，attempts=3，capacity=4 | 秒；错误预算1–10，并存1–16 |
| rate_limits | default策略 | 命名策略，每个limit/window/bans/history_ttl；默认5/300/[60,300,900]/86400 |
| password | bcrypt，cost=12，minimum=15，maximum_bytes=72 | 明确可用时选argon2id；不会静默降级；最小长度为Unicode码点，最大为字节 |
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

连接对象由宿主显式注入。Redis必须是独立、已连接的phpredis客户端，无prefix/serializer；工厂不获取、打印或保存密码。Redis提交使用原子CAS Lua，需要EVAL权限；网络等待按总预算限制。文件配置支持lock_timeout_ms（默认1000，1–30000）。Redis首次部署/重启后需[显式初始化或审核恢复](redis-recovery.md)，新格式会隔离旧状态，不能在请求里自动清空封禁。

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

Redis默认不进行网络探测，显示manual。显式 `diagnose($root, true)` 才执行有界PING、CONFIG GET maxmemory-policy和无写入的`EVAL return 1`权限检查，并通过INFO与ready检查初始化状态；不修改服务器配置、业务键或持久化设置。CONFIG GET因权限不可读时，淘汰策略显示人工确认，不假装通过。使用独立诊断连接，禁止混入宿主事务。

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
