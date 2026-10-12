# 使用与配置

所有模块都由宿主显式实例化；配置不合法抛 `InvalidArgumentException`，存储故障抛 `StorageException`。异常时停止敏感业务，可返回503；不要换空 MemoryStore 继续登录。默认有效期是产品默认值，不是所有站点通用的安全策略。

## 存储选择

```php
$clock = new SoSecurity\Support\SystemClock();
// 宿主 session_start 后，操作期间不能先 session_write_close。
$sessionStore = new SoSecurity\Storage\SessionStore('shop', $clock);
// 提前由部署创建目录，0700，应用拥有，位于 Web 根目录之外。
$fileStore = new SoSecurity\Storage\FileStore('/private/shop/security', 'shop-prod', $clock);
// Redis 是专用连接；认证/TLS/数据库选择由宿主配置。
$redis = new Redis();
$redis->connect('/private/redis/redis.sock', 0, 2.0);
$redisStore = new SoSecurity\Storage\RedisStore($redis, 'shop-prod', $clock);
// 此namespace需先在可信部署脚本中initialize；请求里不自动初始化或恢复。
```

所有共同使用的服务及存储必须使用一致的 Clock。生产使用系统时钟并同步服务器；Redis TTL 基于服务器真实时间。自定义 Clock 主要用于测试，不能在真实 Redis 上任意使用虚拟时间。

文件适用于单主机本地磁盘；不能放共享 NFS；需定时在同一实例循环 `$fileStore->pruneBatch(1000)` 到complete()，并监控磁盘/权限；prune()现在只执行一批。锁文件永远不删除；清理整个目录会清除保护状态。目录只能有一个站点的受信任进程读写；namespace 是逻辑隔离，不是不同文件系统用户的访问隔离。存储没有磁盘配额管理，公网创建入口必须先限流，防止随机主体持续创建数据。

Redis 要求 phpredis、独立连接、无 serializer/prefix，不混用宿主的 MULTI/WATCH 状态。默认最多32次CAS尝试、1000ms总等待预算；Lua原子提交需要EVAL权限；回调可重试。配置 noeviction、权限和内存告警；Redis 重启/清空/逐出状态会丢失保护信息，首次部署需显式初始化；进程身份/epoch检测和审核恢复流程见[redis-recovery.md](redis-recovery.md)，仍不能识别所有单键误删或同进程数据导入。

MemoryStore 只用于测试。SessionStore 不能用于 IP/账号跨 Session 限流，禁用锁的自定义 Session 驱动不能用于原子消费。

## CSRF

```php
$csrf = new SoSecurity\Csrf\CsrfTokens($sessionStore, 7200, 16, $clock);
$token = $csrf->issue('account.email-change', $binding);
$submitted = $_POST['_csrf'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
$valid = $csrf->verify('account.email-change', $binding, $submitted);
// 高敏感操作需要时单次消费，发生在业务操作之前：
$validOnce = $csrf->verify('account.email-change', $binding, $submitted, true);
$csrf->revoke('account.email-change', $binding);
```

以上是各方法独立演示，不要在同一提交里机械重复验证。binding 是宿主保存在 Session 的随机值，登录后更新；不能取自提交表单、IP、静态账号 ID 或客户端 Cookie 的未验证字段。每个新表单发新令牌；默认最多16个并存，超过容量最旧表单失效。TTL 到期需要刷新；不要将不透明令牌暴露在 URL 或日志。普通令牌允许重复提交，业务幂等性另行处理。

Twig：把 token 作为普通模板参数传入 `{{ csrf_token }}`，保留自动转义，不使用 `raw`。普通 PHP 用 `Escaper::html` 并给属性加引号。AJAX 可使用请求头；本库不自动解析请求体或给路由注册豁免。Bearer 认证且浏览器不自动发送凭证的 API 应按认证机制决定是否需要 CSRF，Cookie 认证的 API 仍需保护。

## 验证码

```php
$captcha = new SoSecurity\Captcha\Captcha($sessionStore, 300, 3, 4, $clock);
$challenge = $captcha->arithmetic('login', $binding);
// 输出 prompt，提交隐藏 id；answer 只接受用户提交字符串。
$valid = $captcha->verify('login', $binding, $_POST['captcha_id'] ?? null, $_POST['answer'] ?? null);
// 图片：Challenge::image 是二进制 PNG，prompt 为空，没有 answer 属性。
$renderer = new SoSecurity\Captcha\ImageRenderer(180, 60, null, 12);
$imageChallenge = $captcha->image('register', $binding, $renderer, 5);
// 受保护的图片端点：header('Content-Type: image/png'); header('Cache-Control: no-store'); echo $imageChallenge->image;
// 刷新时明确撤销旧挑战：
$captcha->revoke('login', $binding);
$newChallenge = $captcha->arithmetic('login', $binding);
```

有效期1–31536000秒（默认300）、错误预算1–10（默认3）、并存1–16（默认4）；实际不宜配置超长验证码有效期。图片字符4–8位，8–32个不同大写ASCII字母/2–9数字；宽100–600、高40–200、噪点0–100；可选可读 TrueType 字体。使用 CSPRNG 生成。图片比较不区分大小写，输入前后空格会 trim；算术答案使用规范十进制字符串，01 不等于1。

验证码不是抗自动化的完整方案；算术可自动求解，基础图片不保证抗 OCR。创建、刷新和验证端点都应限流。能力需要更强时用第三方：

```php
$provider = new SoSecurity\Captcha\Turnstile(getenv('TURNSTILE_SECRET'), 'www.example.com', 'login');
$valid = $provider->verify($_POST['cf-turnstile-response'] ?? null, $trustedClientIp);
```

前端 widget 配置 `data-action="login"`，服务端固定 expected hostname 和 action；不能从请求头/用户提交值动态取期望值。仅接受后端 Siteverify 结果。默认传输固定HTTPS地址、校验TLS、禁止跳转、连接3秒/总8秒、响应16KiB上限；不可用抛异常。可注入可信 HTTP transport 回调，入参为请求字段数组，返回 JSON 原始字符串；回调必须等价实现安全传输，不能记录 secret/token。本次未调用真实服务。

## 请求预算与封禁

```php
$policy = new SoSecurity\RateLimit\Policy(5, 300, [60, 300, 900], 86400);
$limiter = new SoSecurity\RateLimit\RateLimiter($redisStore, $policy, $clock);
$subject = hash('sha256', json_encode([$ip, $canonicalAccount]));
$decision = $limiter->consume('login.ip-account', $subject); // 密码验证前调用
if (!$decision->allowed) {
    http_response_code($decision->permanent ? 403 : 429);
    if (!$decision->permanent) { header('Retry-After: ' . $decision->retryAfter); }
    return;
}
// 继续验证码/密码验证；默认保留成功请求的计数。
$status = $limiter->inspect('login.ip-account', $subject);
$limiter->ban('login.ip-account', $subject, 600); // 手动临时封禁
$limiter->ban('login.ip-account', $subject);      // 手动永久封禁
$limiter->reset('login.ip-account', $subject);    // 管理员明确解封/重置
```

这些管理方法必须在宿主授权后调用；不是可直接暴露的公共接口。inspect 不占额度、创建记录或延长历史；达到额度但未触发自动封禁时 retryAfter 是剩余窗口。consume 第limit+1次触发封禁，封禁结束重开窗口，下一次越限提高阶梯；历史TTL过后从第一阶开始。historyTtl必须覆盖窗口和最长封禁。固定窗口可能在边缘形成突发流量；要更精确的滑动窗口属于后续策略。

策略一旦使用，不要在不同进程对同一 scope 设置不同的额度、时间或阶梯；变更使用新scope，已存在状态保留其有效期。同一namespace可以用不同scope区分站点业务。Policy不可变；读取使用limit()/window()/banDurations()/historyTtl()，变更时创建新策略并安排scope迁移。IP总量桶配宽松阈值，不自动永久封禁共享IP；单账号桶用于风险观察应慎用硬封禁，避免恶意锁死用户。

## 密码与重置

```php
$hasher = new SoSecurity\Password\PasswordHasher(); // bcrypt cost=12，可移植
// 新部署支持时明确使用：new PasswordHasher('argon2id');
$hash = $hasher->hash($password);
$valid = $hasher->verify($password, $hash);
$upgrade = $hasher->verifyAndUpgrade($password, $storedHash, $knownLegacyVerifier);
// valid 后，如果 replacementHash 非null，宿主以 WHERE password_hash = :old CAS 更新。
$policy = new SoSecurity\Password\PasswordPolicy(15, 72);
$errors = $policy->errors($password); // 机器可读代码，宿主翻译
$reset = new SoSecurity\Password\ResetTokens($redisStore, 1800, $clock);
$binding = $accountId . ':' . $currentPasswordVersion;
$token = $reset->issue($binding);
$validOnce = $reset->consume($binding, $submittedToken);
$reset->revoke($binding);
```

bcrypt 上限72**字节**；不预哈希、不截断；Argon2id允许到4096字节。NUL和空密码拒绝。bcrypt cost配置10–16；Argon2id默认 memory_cost=19456 KiB/time_cost=2/threads=1，不可用抛错。已经更高cost的bcrypt或Argon2不会自动降级到低cost bcrypt。

策略默认15个Unicode码点（不是字节/视觉字形），最大72字节；不强制字符类别组合；可注入 breachChecker，返回true表示已泄露，非bool或服务错误抛异常。该回调不是内置泄露库，不应把明文密码发给不可信服务。

旧哈希迁移不自动识别算法；只能注入已知格式的精确验证器。现代哈希错误时不会调用 legacyVerifier。重置绑定须含每次密码变更后的版本，保存密码成功后撤销/更新版本。token消费与数据库写入之间没有分布式事务，失败后重新发令牌；同一账号并行重置需数据库版本比较确保仅一个写入生效。找回密码入口需统一公开响应和限流。

## Session

```php
SoSecurity\Session\SessionSecurity::configure(true, 'Lax'); // 在session_start和输出前
session_start();
header('Set-Cookie: ' . SoSecurity\Session\SessionSecurity::cookieHeader(true, 'Lax'), false);
$security = new SoSecurity\Session\SessionSecurity(1800, 28800, 'shop');
if (!$security->touch()) {
    unset($_SESSION['user']); // 换成宿主自己的认证字段
    http_response_code(401);
    return;
}
// 认证成功/提升权限后、写认证字段前：
$security->rotate();
header('Set-Cookie: ' . SoSecurity\Session\SessionSecurity::cookieHeader(true, 'Lax'), false);
// 注销：宿主清理认证字段并删除Cookie/销毁Session，本库失效标记：
$security->invalidate();
```

PHP 7.2没有原生 SameSite 配置，start/rotate 后的显式 Cookie 头是必需步骤。configure默认保留宿主已有path/domain/lifetime，可以显式传入覆盖配置；Domain扩大会话Cookie可见范围，应先审核已有策略。原生及生成的同名同路径Cookie以最后发出的安全属性覆盖；反向代理不能重排/删除这些头。生产Secure=true，仅明确的本地HTTP演示才设false。

touch首次调用建立时间基线，已有登录用户首次接入也从此时计时，不会追溯原始登录时间。rotate重新建立基线，旧Session并发请求可能需重新登录。保持失效标记直到重新认证。宿主已有生命周期时可只采用必要方法。

## HTTP、输出与审计

```php
$ip = (new SoSecurity\Http\ClientIp(new SoSecurity\Http\IpRules(['10.0.0.10/32'])))->resolve($_SERVER);
$blacklist = new SoSecurity\Http\IpRules(['198.51.100.0/24']);
$blocked = $blacklist->contains($ip); // 宿主决定黑/白名单优先级
$headers = SoSecurity\Http\SecurityHeaders::build("default-src 'self'", true); // Report-Only
foreach ($headers as $name => $value) { header($name . ': ' . $value); }
// HSTS显式第三参数，仅确认HTTPS可用后设定。不自动includeSubDomains/preload。
$cookie = SoSecurity\Http\Cookie::header('__Host-token', $value, '/', true, true, 'Lax', 3600);
header('Set-Cookie: ' . $cookie, false);
$text = SoSecurity\Output\Escaper::html($input);
$jsData = SoSecurity\Output\Escaper::json($data); // script里的JSON数据字面量
$queryValue = SoSecurity\Output\Escaper::urlComponent($input); // 仅URL组件编码
$logger = new SoSecurity\Audit\AuditLogger($structuredSink, $independentAuditKey);
$logger->record('login.failed', 'login', $accountId, ['status' => 401]);
```

代理只支持明确的X-Forwarded-For部署；默认不信任何代理，从右侧移除可信跳数，格式异常拒绝，IP规范化。CIDR支持IPv4/IPv6，同族匹配，不将IPv4映射IPv6自动混同。Apache/Nginx可配置相同响应头，宿主决定由哪层发出，避免冲突。CSP需要逐步收集违规并验证静态/第三方资源；Permissions-Policy/CORS尚未实现。

HTML编码适用于HTML文本和加引号的普通属性，不适用于事件、style或srcdoc；JSON不是任意JavaScript模板清洗器；URL组件编码不检查scheme，不是SSRF/开放跳转防护。不要对Twig已自动编码的变量重复编码，不使用raw；富文本需要经审查HTML清理器。

AuditLogger只保留allowed/retry_after/status的bool/非负int字段；其他上下文丢弃。event为规范常量代码，scope为受控常量；subject使用独立密钥HMAC假名化（密钥至少32字节），不能传密码/令牌/Session ID。sink故障抛给宿主，由宿主事先决定审计失败是否阻止业务，不能在动作完成后隐瞒业务结果。库没有内置日志文件、查询、日志保留期或自动事件订阅。

可选配置工厂、完整配置参考、只读诊断和开发候选API迁移见 [configuration.md](configuration.md)。

PDO MySQL接入与事务所有权见[mysql.md](mysql.md)，严格类型/嵌套字段和本地化错误见[validation.md](validation.md)。新能力同样可以独立使用，不要求工厂或框架。
