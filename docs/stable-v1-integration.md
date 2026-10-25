# 1.0.0本地交付：最小PHP接入与迁移回滚

本指南面向现有PHP项目按需接入组件，不接管账号、业务数据库或路由。运行时源码为`fedc471`，固定G/B/F/H/C已经按准确候选完成；管理已在`6de2a35`签收S范围及部署限制。准确提交7ad825c的1.0.0本地交付已通过最终管理复核，稳定承诺仅限S；E继续实验，未公开发布或生产上线。最终准确提交和包摘要只写包外交付清单。稳定方法及参数组合以[范围表](stable-v1-api-scope.md)为准，完整结果见[验收记录](stable-v1-acceptance.md)。

## 安装与实际依赖

Composer约束为PHP `>=7.2 <8.6`、ext-json、ext-hash；本地实际验证7.2.34、7.3.33、7.4.33、8.0.30、8.1.34、8.2.32、8.3.35、8.4.23、8.5.9，不外推其他PHP版本或平台。下表是按用途要求，不要求所有使用者安装全部测试扩展。

| 用途 | 要求及边界 |
| --- | --- |
| 普通表单/CSRF与原生会话 | ext-session、可靠加锁的会话存储、HTTPS；多实例须共享会话并保留锁至令牌操作结束 |
| 跨会话登录预算/API防重放 | 共享原子存储；本指南使用应用独占、Web根之外的POSIX 0700 FileStore目录；MemoryStore和单会话SessionStore不能代替 |
| Redis/MySQL替代文件存储 | ext-redis或ext-pdo_mysql及专用连接；本轮实际服务器Redis5.0.3/MySQL8.0.46。显式部署初始化，见[存储用法](usage.md)、[MySQL](mysql.md)，禁止在请求失败后自动重建/恢复 |
| 图片验证码/图片上传 | ext-gd/实际格式codec；上传还需要ext-fileinfo；没有codec就不启用对应格式 |
| HMAC API/普通Webhook验签 | 本地私密密钥和准确当前密钥提供者；Ed25519额外要求sodium；外部密钥/验证码服务不由本地验证代替 |
| 真实写入故障测试 | pcntl及posix_setrlimit或Linux可执行prlimit，仅用于测试；不是产品全局POSIX扩展要求 |

尚无本批授权的公开发布。使用已审发行归档，先核对交接方提供的SHA-256，再解压到一个新的私有目录；不得覆盖现有vendor、配置或状态。C01实际采用Composer path仓库、镜像复制而非符号链接：

```json
{
  "name": "example/local-security-consumer",
  "require": {"sohophp/sosecurity": "1.0.0"},
  "repositories": [
    {"type": "path", "url": "/absolute/path/to/unpacked-sosecurity", "options": {"symlink": false, "versions": {"sohophp/sosecurity": "1.0.0"}}},
    {"packagist.org": false}
  ],
  "config": {"allow-plugins": false}
}
```

在新的消费者目录保存为composer.json，以实际目标PHP执行Composer `install --no-scripts --no-plugins --no-interaction --no-progress`，离线环境设置`COMPOSER_DISABLE_NETWORK=1`。不使用ignore-platform，不把依赖错误跳过；安装后保留composer.lock。`1.0.0`是明确的本地path版本映射；path reference不是Git提交，也不表示已有公开标签或Packagist发行。已有宿主须合并仓库配置并审阅锁文件差异，不能以此JSON覆盖宿主依赖清单。

最终文件为`sosecurity-1.0.0.zip`；在交付目录执行`sha256sum -c SHA256SUMS`，核对包外`delivery-manifest.json`的固定SHA-256及准确提交后才解压。最终ZIP生成后不再修改包内文档；本指南不嵌入自身归档摘要，避免自引用。C01历史归档摘要不能用于此ZIP。367份运行时文件须与fedc471及安装包一致，最终包只做PHP7.2/8.5最小烟测，不重复九版G/B/F/H/C。

## 普通表单、会话、CSRF与共享登录预算

最小工厂只选择普通存储，不声明状态边界或高级模块。部署预先创建私有目录；PHP进程必须拥有读写权限，目录不能与已受保护的账号目录复用。

```php
<?php
require __DIR__ . '/vendor/autoload.php';
$security = SoSecurity\Security::fromArray([
    'site' => 'example-site',
    'storage' => ['driver' => 'file', 'directory' => '/private/example/security'],
    'session' => ['secure' => true],
    'rate_limits' => ['login' => ['limit' => 5, 'window' => 300]],
]);
```

不要在已有框架启动Session后重复调用configureSession或修改Cookie；沿用框架的可靠会话和CSRF也可以。独立PHP入口须在输出前configureSession、session_start，并按[会话用法](usage.md)设置PHP7.2兼容的SameSite Cookie头。绑定值用服务器生成的随机值保存于Session，不接受客户端指定；CSRF按具体scope签发、验证后才执行状态变更。登录预算应在昂贵密码验证前consume，账号规范化必须与宿主一致，可信客户端IP由固定代理配置解析。

可以直接复用已通过H01及C01的[legacy-login.php](../examples/legacy-login.php)：它包含GET表单、会话/CSRF/验证码、共享IP与账号预算、密码验证、成功后轮换和故障503，不连接真实用户库。为了保持其`dirname(__DIR__).'/vendor/autoload.php'`路径，在新消费者根目录创建examples，并将安装包的该文件复制到消费者examples；不要直接在vendor中的示例目录启动服务器。

仅用于本地演示：新建自己的0700状态和会话目录，生成一个临时bcrypt密码哈希，将其作为`SOSECURITY_EXAMPLE_PASSWORD_HASH`，设置`SOSECURITY_EXAMPLE_USER`及`SOSECURITY_EXAMPLE_STORE`，显式`SOSECURITY_EXAMPLE_HTTPS=0`，执行：

```sh
php -d session.save_path=/absolute/private/demo-sessions -S 127.0.0.1:8080 -t examples
```

访问`http://127.0.0.1:8080/legacy-login.php`。HTTP与关闭Secure仅限这一本机示例；业务环境保留HTTPS/Secure。示例凭据不是用户数据库，也不能作为正式账号配置。实际宿主在保护检查之后连接自己的参数化身份查询、当前禁用/版本/权限事实及可靠密码验证，再轮换会话；不要移除既有MFA或改用普通模式接管已受保护的账号。集成顺序和密码渐进升级见[迁移指南](migration.md)。

## 普通API与验签接线

Bearer使用普通`$security->apiKeys()`及`fromAuthorization($header, $requiredScope)`；签发/撤销由已有受认证、受CSRF和权限保护的管理入口或可信CLI负责，禁止照搬测试中的公开`/test-issue`、`/test-revoke`路由。令牌只在签发时交给授权客户端，不记录明文；返回null为拒绝，依赖异常为503。

HMAC接入复用[已验证的请求适配器](../examples/api-request.php)，将该文件复制到消费者examples后require；签名协议、签名端及完整示例见[API指南](api.md)。以下代码放在宿主已完成大小限制和请求头解析的入口内部，`$security`来自上述普通工厂，`$secret`来自服务器私有密钥配置（32—128字节），不能取自请求。

```php
$origin = 'https://api.example.com'; // 可信部署配置，不读取Host/X-Forwarded-*决定它
$key = new SoSecurity\Api\SigningKey('host-key-1', $secret, 'client-1', ['example:read']);
$policy = new SoSecurity\Api\SignaturePolicy(['origin' => $origin, 'maximum_body' => 65536]);
// 使用同一普通共享存储的nonce域；不得使用每请求新建的MemoryStore。
$store = new SoSecurity\Storage\FileStore('/private/example/security', 'example-api');
$verifier = new SoSecurity\Api\HmacVerifier(
    $policy, new SoSecurity\Api\KeyRing([$key]), new SoSecurity\Api\NonceStore($store)
);
// 下面三个值由宿主原始请求适配层提供；重复签名头须在合并前拒绝。
$identity = SoSecurity\Examples\authenticateSignedRequest(
    $verifier, $_SERVER['REQUEST_METHOD'], $origin, $_SERVER['REQUEST_URI'],
    $rawBody, $headers, 'example:read'
);
if ($identity === null) { http_response_code(401); return; }
// 之后仍需宿主按当前资源权限授权；这里没有执行任何业务写入。
```

`$rawBody`须按65537字节上限读取、超过65536返回413；不能先JSON解码再编码。`$headers`须包含原始Content-Type、Content-Digest、Signature-Input、Signature，缺失/重复/非法格式拒绝；代理必须保留原始查询顺序和百分号编码。服务端验签不是业务事务或幂等保证，nonce通过后业务失败也不能把相同签名再次执行。不同站点/密钥用途使用独立命名空间。验签需要当前密钥及最终时效检查，不能缓存失效权限事实换取通过。

普通Webhook仅使用[Verifier](webhooks.md)的`verify`与当前密钥/请求守卫；它不提供持久去重或收件处理。首版不要配置`inbox`、`processing`、`state_connection`，不要调用webhookInbox/webhookProcessor。若业务要求耐久收件或处理保证，应保留原实现或暂不迁移该入口，不能省略保障来适配本版。

## 部署限制与失败处置

默认未配置的模块保持未启用；首版仅允许范围表的S方法及对应普通参数。不要添加accounts、account_factors、api_credentials、authentication.state_boundary、managed_factors、mfa、remember、outbox、idempotency、upload_quarantine或其他E配置；也不要注册E的HTTP路由、后台命令和工作进程。**这是有代码路径和实测依据的支持条件，不是SDK内新增的禁用开关或安全沙箱**：包仍保留E源码和契约，任意宿主自行调用不会被版本标签自动阻止。已有E部署不能通过删配置、解绑或移除目录标记降级到S。

PHP7.2无hrtime，真实耗时预算使用microtime；回拨会使当次预算永久到期并拒绝，不会延长权限窗口。它影响普通FileStore/Redis、SQL归属探测、Webhook和出站等共享路径的可用性。部署须接受回拨期间503/拒绝，避免在宿主/虚拟机时钟不稳定时承诺无中断服务；不能平滑时钟、增加预算或关闭检查。如果不能接受，应由管理选择该站点已有兼容的PHP7.3—8.5运行时，不改变本库PHP7.2支持声明，也不擅自升级宿主。hrtime存在仍不等于业务时间/宿主时间永不异常。

输入/凭据错误按接口统一400/401/403；预算超限按策略429/封禁；依赖、存储、时钟故障拒绝业务并返回脱敏503。日志只保存受控reason、关联号、候选和耗时，不输出密码、令牌、签名密钥、请求正文、Session ID或完整异常对象。PDO清理失败须丢弃连接重建，不能复用未知事务连接。

普通ApiKeys也可能报告`api.issuance_unknown`，存储提交异常不能被当作必然失败；禁止自动重新签发、删除状态或用新请求掩盖未知结果。账号管理旧`account.completion_unknown`及3000ms失败原样保留，不启用/重试它们。历史SqlInbox元数据失败本批未复现，只能按S/E隔离方案签收，不能宣称已找回或修复历史根因。

## 迁移、回滚与验收交付

1. 记录宿主原composer.lock、PHP/扩展、路由、代理、会话、权限和状态位置；备份原配置和实现。新组件先接一个明确入口，保留原有可靠防护；本指南不授权操作真实业务站。
2. 新站点普通状态独立命名空间；共享登录预算不能按请求/实例随机化目录。多主机选择已验收的共享Redis/MySQL方案；SQL只显式安装规范私有表，不能将安全操作塞进已有业务事务。已有状态格式不盲目清空/转换，采用[迁移指南](migration.md)与相应后端说明。
3. 先验证成功、错误/过期/重放、跨标签/实例限流及依赖失败；固定门禁结果可引用准确候选，不再整轮求绿。真正宿主的代理/会话/账号/权限接线由管理指定测试环境后验证，本轮没有生产接入。
4. 回滚先恢复可靠旧保护再停用新调用；旧保护不安全则关闭敏感入口，不能匿名放行。恢复已记录的依赖和配置；保留新旧状态、封禁、nonce、密钥及审计，不回退安全账本、不清空Redis/Session/目录，不重试结果未知的业务。
5. CSRF/验证码切换可能要求刷新旧表单；已签发的API令牌由原管理流程有序撤销，不直接删除数据。密码升级不能还原旧弱哈希；旧版本若不能验证新哈希，保留兼容验证或停用对应登录入口。

管理已签收本指南所列S调用与部署限制。最终准确提交、ZIP摘要、原始安装/来源/最小PHP烟测证据由包外交付清单绑定；最终产物已由包外management-final-review.json确认通过。本次后续文档说明不改已验收ZIP，其内指南保留打包时文案；先读[中文接入速读](stable-v1-php-adoption.zh-CN.md)了解S/E及版本对应关系。实际宿主部署与公开发行未授权。
