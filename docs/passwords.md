# 密码策略、弱密码、泄露筛查与成本校准

旧 ResetTokens 的[恢复代际](state-proof-retirement-2026-10-22.md)明确作用于整个 FileStore 命名空间的所有账号版本绑定；同一底层 CsrfTokens 的 password-reset 用途也识别标记，普通 CSRF 用途保持。它不修改账号密码，不清空 nonce；受保护 `resetTokens($ttl,$statePolicy,$requestAuthority)` 已接入真实密码／因子／邮箱版本绑定与同边界 SQL，见[原生重置证明](state-native-reset-integration-2026-10-22.md)。原语不自动完成邮件、MFA、账号恢复或登录；完整恢复及最终启用另行验收。

哈希、设置密码的策略、登录验证和账号恢复分别处理。`PasswordHasher` 不自动联网或改库；策略在注册／改密／重置时使用，不在每次登录强制新策略，以免错误锁死已有账号。登录、重置和策略请求仍需宿主预算、CSRF、身份／对象授权及生命周期撤销。

## 与算法匹配的策略

```php
$security = SoSecurity\Security::fromArray(['site' => 'my-site',
    'password' => ['profile' => 'argon2id']]); // 当前构建必须明确支持该算法。
$errors = $security->passwordPolicy()->errors($newPassword);
if (!$errors) { $hash = $security->passwordHasher()->hash($newPassword); }
```

默认 bcrypt cost12、最少15个Unicode码点、最多72字节。Argon2id缺省最多4096字节，默认19456KiB／2轮／1线程；不支持时拒绝配置，不自动换算法。`maximum_bytes` 可收紧，但不能超过已选哈希算法上限。先检查字节预算，再进行UTF-8／NUL／码点检查和弱密码／远程筛查。错误码为 `password.too_long`、`password.encoding`、`password.too_short`、`password.weak`、`password.compromised`。

工厂默认使用基础弱密码表。既有直接构造 `new PasswordPolicy(15,72)` 保持纯长度策略；新接入可用 `PasswordPolicy::forHasher($hasher,15,null,$blocklist,$checker)` 匹配算法。构造配置不读取文件、联网或运行成本基准。

不强制大小写／符号组合，不截断、修剪、大小写折叠或预哈希密码。支持空格和Unicode；此组件保留原始字节，不自行NFC转换。宿主若采用NFC，需在设置与验证两端一致处理，并明确旧账号迁移；码点不同于视觉字形。密码管理器、粘贴和自动填充应保留，设置表单使用 `autocomplete="new-password"`。

bcrypt的72字节限制可能阻止较长Unicode短语；需要长密码时明确选择可用的Argon2id。此兼容限制不代表符合全部身份标准或通过NIST认证。

## 本地弱密码表

`PasswordBlocklist::baseline()` 是透明、有限的基础集：公开常见测试短语、重复ASCII字符及数字／键盘串等全串值。它不是完整泄露语料。`contains()` 对整个密码精确匹配，不因短语包含某个词就拒绝。

宿主可用 `fromPasswords([...])` 创建服务名／账号派生值的补充快照，或传SHA-256十六进制列表构造。最多100000条，单条输入最多4096字节；内部只保留摘要，不保留原文。此快速摘要仅用于拒绝表查询，绝不能用来保存账号密码。

`PasswordBlocklist::fromFile($trustedPath,$expectedSha256)` 显式读取最多8MiB的本地普通文件：每行64位SHA-256，支持LF／CRLF及一个末尾换行。拒绝链接、流包装器、格式／大小／校验和错误。数据由宿主控制，建议审查来源／许可证并原子替换；校验和应来自可信发布渠道，不能把同一被篡改文件现算的摘要当作独立验证。私有上下文词的摘要仍可能被枚举，应保护文件权限。

工厂 `password.blocklist` 默认 `builtin`，可换成注入的 `PasswordBlocklist` 服务名；显式 `null` 关闭本地表，诊断标为未满足。自定义表替换基础表，需补充时自行组合受控数据；空表和数据覆盖程度不能由类型检查证明。

## 可选泄露检查

```php
$checker = new SoSecurity\Password\PwnedPasswords();
$security = SoSecurity\Security::fromArray([
    'site' => 'my-site',
    'password' => ['breach_checker' => 'breach'],
], ['breach' => $checker]);
$errors = $security->passwordPolicy()->errors($newPassword);
```

默认不配置、不联网。`PwnedPasswords` 在服务器计算SHA-1，仅发送五位十六进制前缀到固定 `https://api.pwnedpasswords.com/range/`；请求 `Add-Padding: true`，在本地匹配剩余摘要。零计数是填充，不能判为泄露。SHA-1只用于该查询协议，账号保存仍用原生密码哈希。

原生请求复用[受限外部客户端](outbound.md)的有界DoH和精确IP连接：默认向固定Google DoH端点查询服务主机，bootstrap为8.8.8.8，随后只连接已验证的公开IP，均验证HTTPS证书，绕过可能阻塞的操作系统DNS线程。DoH只接收服务主机名，密码前缀仅发送HIBP。需要libcurl7.57+，禁代理／Cookie／自动重定向。

默认总预算3000ms（包括DoH），可明确设500—10000ms；每次连接最多1000ms，API响应体256KiB、头16KiB、最多5000行，计数最长12位。DoH另有每响应16KiB／8KiB及记录预算，但共用总时间。必须200且全响应通过严格验证，不能匹配首行后跳过后续错误。超时、坏证书、非200、过大／畸形／重复记录均抛 `DependencyException`，稳定原因 `password.breach_unavailable`，不当作“未泄露”。

可注入 `new PwnedPasswords($rangeTransport)`：回调只收 `(prefix, ['Add-Padding'=>'true','Accept'=>'text/plain'])` 并返回完整有界范围文本。可接已下载的离线前缀分片；宿主适配负责可信来源、完整覆盖、更新期限及有界I/O。不要只返回待查询密码对应一行，也不要以空串代表无命中。

需要企业DNS／不同DoH提供器时，在显式范围适配中使用配置好可信 `Resolver` 的受限客户端，并核对HTTP状态再返回范围正文；不会静默改用无界系统解析。原生错误、重定向和DNS失败均保留失败语义。

既有 `errors($password,$breachChecker)` 可覆盖实例上的检查器；回调严格返回bool，故障必须抛错。配置了远端检查后，故障应拒绝本次密码变更／返回可重试服务错误，不能在catch中继续写密码。组件不自动缓存、重试或在输入每个字符时查询；宿主若缓存，按整段前缀与数据版本共享、设置期限，避免保存用户候选值或完整摘要。

哈希前缀仍减少匿名集合，不等于零信息泄露。只在完整提交后检查，不逐键上报；应用日志只记录稳定原因码，不记录密码、完整哈希、前缀、请求体或异常参数／堆栈实参。自定义适配器的原始异常不会被串联。

## 原生验证和升级预算

原生验证前检查已存哈希格式／成本：bcrypt cost4—16、Argon2 memory1—262144KiB／time1—10／threads1—4；新哈希最低参数仍更强。超预算或未知格式返回false，不执行高成本验证。原生bcrypt的2a／2b／2x／2y格式在实际运行时能力内验证；未知旧格式需明确的旧验证器。旧 `crypt` 格式若此前依靠原生偶然接受，需迁移到该显式接口。

`verifyAndUpgrade()` 仅在成功验证后产生替代哈希；宿主以旧哈希或版本条件比较更新，不覆盖并发改密。不会把Argon2降为bcrypt，也不降低更高的bcrypt成本。Argon2已有任一成本维度高于目标时，不自动重哈希；混合参数需要宿主明确决定保留／提高各维度后迁移，不能把“需要重哈希”等同于可安全降低参数。

[重置示例](../examples/password-reset.php)按哈希算法检查策略，默认基础弱密码表，并可传末尾可选泄露回调。无效／弱／已泄露／检查故障均发生在令牌消费和SQL写入之前；通过策略不等于持有有效重置令牌。成功改密还需宿主撤销会话／持久授权并更新身份版本。

## 显式CLI成本校准

```sh
php examples/password-calibrate.php --profile=bcrypt --target-ms=250 --budget-ms=3000 --samples=3
php examples/password-calibrate.php --profile=argon2id --max-memory-kib=65536
```

工具随Composer发行，导入文件不执行。仅允许POSIX CLI与可用进程控制，在隔离子进程中用临时随机测试值预热并采样，从低成本开始，输出测量及建议参数；不读取真实密码，不接受密码参数，不输出密码／哈希，不写配置。父进程总预算到期终止当前探测；退出清理子进程。原生计算不可在同一PHP调用中抢占，所以使用独立进程而非软超时。

`target-ms` 为10—2000，`budget-ms` 为100—30000，`samples` 为1—5；Argon2探测1线程，内存上限19456—262144KiB，默认65536。预算包含进程启动／预热／采样，终止和调度可能产生小幅超时；无完成样本或最低成本仍超过目标时 `recommended=null`，不得伪造达标建议。

在接近实际负载的独立维护窗口执行；单进程中位数不是并发容量结论。选择计算成本后仍需部署预算／延迟验收，并显式修改配置。工具不会因性能慢而突破新哈希安全下限或自动调低生产配置；不支持的Argon2id或进程控制明确失败。

## 证据和参考

专项、原生固定端点TLS、子进程校准、重置SQL边界及演示浏览器证据见 [verification.md](verification.md)。公开已知测试密码的真实HIBP查询与私人账号、生产配置验证分开；未配置真实业务的远程策略不声称已接入。

参考：[NIST SP800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html)的全串拒绝表与Unicode建议；[HIBP范围与填充](https://haveibeenpwned.com/API/v3#PwnedPasswords)的五位前缀、计数和逐键查询风险；[OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)与[Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)的策略、迁移及计算成本边界。标准对照不代表认证或独立审计。


原生新增账本现检查完整物理目录的文件余量：满额在 pending 前拒绝，逻辑过期文件仍占容量，已有账本合法更新不额外占文件。释放空间后同一服务／会话可重试；不会因此清除旧 pending。准确修前反例及范围见[容量准入记录](state-admission-capacity-2026-10-22.md)。

独立 `ResetTokens` 原生入口在完成后只读捕获当前账号记录，重新调用请求守卫并检查期限和整体预算。宿主边界需支持 `password.reset.<entry>_check`（issue／consume／revoke／execute），守卫须可重复只读调用。后置拒绝不退款证明或重放已提交业务。这里仅描述证明原语，不表示最终账号恢复已实现或验收；见[范围及本地证据](native-reset-proof-return-2026-10-23.md)。
