# Webhook接收与业务处理深化方案

`Request`保存原始正文、URL和签名头；当前对象导出不会展开这些字节。显式`body()`／`header()`仍返回原值供验签与业务处理，宿主必须保护取得的原始数据。旧序列化请求对象拒绝恢复，接收入口应从当前HTTP请求重新构造。

状态：R4.2接收核心已实现并有历史本地验收；新增MySQL手工事务场景已发现并修复接管缺口，当前重新进行九版复验。以下通过数量为此前基线，不能覆盖该新修复。九版完整检查／既有磁盘耗尽／新消费者通过，每版239协议／900独立请求、201 SQLite／191 MySQL专项、两后端各25项24进程与SIGKILL恢复、原生HTTP／TLS各628断言通过；PHP7.2／8.5真实TLS移动Chromium、152类API、260文件归档及静态检查通过。最初PHP8.5默认文件锁预算超时与同源码串行复验分别记录在verification.md。真实提供器、公网投递、生产及独立审查未验收；业务处理、重试与恢复继续R4.3。

## 当前可调用核心

```php
$endpoint = new SoSecurity\Webhook\Endpoint(
    'events', $trustedTenant, $configuredProviderAccount,
    'https://hooks.example/events', 'standard-hmac'
);
$verifier = new SoSecurity\Webhook\Verifier(
    $endpoint, $currentEndpointKeyProvider, $requestGuard
);
$request = new SoSecurity\Webhook\Request(
    $actualMethod, $actualCanonicalUrl, $boundedOriginalBody, $actualHeaders
);
$proof = $verifier->verify($request);
if ($proof === null) { /* 拒绝，停止业务与状态分配 */ }
// 非null仅表示验签通过：继续验证业务关联并持久接收，不能据此直接确认业务已提交。
```

keyProvider接收Endpoint，返回当前`KeySet`或null，最多8把命名密钥；返回不匹配端点的快照或服务故障拒绝。Standard密钥可用`KeySet::fromEncoded($endpoint, $privateEncodedKeys)`显式解码，其他提供器使用构造器的原始字节，不猜测前缀。每次验证在签名工作后重新取得当前密钥，再核对MAC和期限。requestGuard接收Endpoint与Request，严格true才继续；实际Host／HTTPS、方法／媒体类型、原始请求提取与入口预算由该可信宿主边界负责。Verifier本身无Session、Cookie、数据库、网络或自动账本副作用；可手工组合，也可使用下方工厂。

Standard HMAC原始密钥为24—64字节，Ed25519公钥32字节，Stripe／GitHub秘密16—256字节；遵循提供器给定材料，自管对称密钥建议至少32个随机字节。同一快照拒绝重复材料，密钥标签为1—32字节ASCII名称。提供器负责最新权威状态与撤销传播，不能用永不刷新的进程缓存冒充当前密钥；组件不推断外部缓存是否新鲜，也不在请求中自动轮换生产密钥。

`KeySet`将原始密钥保存在闭包内，常见对象调试与`var_export()`不输出密钥。不要把对象转储视为密钥备份；每次工作进程初始化时从可信服务端配置重建快照。旧序列化对象会明确拒绝反序列化，不能从缓存恢复为当前验签权威。

VerifiedWebhook提供body、摘要、端点、服务器匹配的keyId、verifiedAt以及有签名的messageId／timestamp。GitHub两项时间／消息ID均为null，Stripe消息ID也为null，须从后续验证的正文结构提取业务事件身份。expiresAt对GitHub为null，不能解释成无限期业务授权。请求、私钥快照、验签服务和来源证明拒绝序列化，默认JSON不导出正文或秘密；不得从客户端恢复这些对象作为授权。

默认正文65536字节、上限1MiB，头最多32项、单项4096／总16384字节；支持最多8个当前算法签名和8把密钥，先解析有界格式再查询密钥。时间容差默认过去300秒／未来30秒，不提供关闭签名时间检查；操作预算默认3000毫秒、最多30000。时间和预算在回调返回处复核，无法强制中断宿主阻塞I/O。Endpoint策略断开外部数组引用，不因调用方改原变量而改变已验证配置。

## 协议与原始请求

| 协议配置 | 验签覆盖 | 必须单独处理的边界 |
| --- | --- | --- |
| Standard Webhooks v1 | 消息ID、投递时间戳与原始正文，HMAC-SHA256 | whsec_是编码前缀，按规范解码秘密；固定服务器端协议与端点密钥；有界多签名支持轮换 |
| Standard Webhooks v1a | 同一完整消息，Ed25519 | 使用服务器信任的whpk_公钥；明确依赖sodium，不能按客户端请求降级到其他算法 |
| Stripe v1 | 投递时间戳与原始正文，HMAC-SHA256 | Stripe的whsec_秘密按提供器定义使用，不能套用Standard Webhooks的Base64解码规则；事件ID从验签后的正文提取 |
| GitHub sha256 | 原始正文，HMAC-SHA256 | 投递ID与事件类型头不在签名内，也无签名时间戳；必须显式接受此限制，不能将这些头当作可信重放键或业务身份 |

端点由服务器固定关联提供器、租户、目标账号、预期方法／路径／来源、正文预算、允许媒体类型、密钥来源和事件类型。唯一端点密钥防止跨客户重放，构造器不会自动取得密钥或创建端点。方法／路径等字段是否受密码学签名保护取决于协议；原始请求边界与实际HTTPS、代理、入口预算仍由宿主验证。

验证前限制正文、头数量／单项长度、签名数与密钥数；拒绝重复认证头、非法数字／编码、歧义字段和超限数据。宿主须确认实际接入层到PHP不会提前覆盖重复头；已被SAPI丢弃的信息无法由Request恢复。保持原始正文逐字节不变，不能先JSON解析再序列化。只检查服务器配置的算法和密钥，不从请求取得信任根，不自动尝试其他协议或Cookie。有效MAC之后才解析业务内容或分配共享状态。

签名时间戳同时检查过旧和超前、整数溢出、I/O晚返回及观察时间倒退。带时间戳的合法重试可以使用新的投递时间，但其稳定事件身份不能随之失去幂等关联。GitHub无签名时间，有限去重保留期无法证明首个请求新鲜；原始正文／签名摘要可阻止修改未签名投递ID绕过同正文去重，长期业务版本和事件去重仍需宿主保证。

## 验签、接收与副作用

区分三种结果：来源／内容验证通过、消息已持久接收、业务已提交。验签返回的来源证明不能代表订单／账号关联正确，也不代表已写入消息或执行业务。

`SqlInbox(PDO, string $site, Verifier, HmacKeys $integrityKeys, callable $associationGuard, Clock?)`已实现，九版真实SQLite／MySQL专项及24进程重复／冲突／跨站点与实际SIGKILL恢复通过；工厂／诊断与原生HTTP／TLS专项通过，完整九版本地门禁通过。构造器只检查已有连接类型／错误模式，不创建表或查询业务。数据库连接要求异常模式，MySQL需原生预处理；提交接收前检查实际表结构、主键／索引和持久化配置，SQLite必须为真实文件、启用日志且synchronous为FULL／EXTRA，MySQL要求InnoDB及提交刷盘。显式部署[SQLite结构](../resources/sql/webhook-sqlite.sql)或[MySQL结构](../resources/sql/webhook-mysql.sql)，不在请求中安装或变更结构。

`accept(Request, callable $mapper): ?Receipt`先验签，再将已验签正文映射为Message；null拒绝。Message包含事件ID、类型、目标资源和最多16项有界标量上下文；associationGuard接收固定Endpoint与Message，必须从当前权威来源确认租户／账号／资源关联且严格返回true。组件在接收提交前再次核验签名、当前密钥与业务关联；关联回调必须读取当前权威状态，MySQL同连接事务内应使用锁定读取（如FOR UPDATE）避免REPEATABLE READ历史快照被当作当前权限，不接收外部反序列化的“已验证”对象作为入库凭据。Standard事件ID必须匹配已签名的消息ID；Stripe必须匹配正文id／type及存在时的account；GitHub固定使用`body:SHA256(原始正文)`，未签名投递ID不能绕过去重。

接收表命名空间绑定显式站点、端点ID、租户、提供器账号和协议；修改URL、时间容差或轮换密钥不自动清除去重记录。原始正文、消息描述、首次验签密钥标识／有签名的时间和接收元数据同时由独立HMAC密钥封存，不能靠改写普通摘要伪造来源；该密钥必须与提供器密钥分开保护。封存提供完整性，不加密正文，宿主负责私有数据库、磁盘／备份加密、访问权限和保留期。保留旧封存密钥可核验旧记录，合法重复接收会使用当前密钥重封；移除仍在用的旧密钥后不自动覆盖或重置记录。

Receipt仅为接收元数据，duplicate为true时仍指向原接收ID／时间；不包含正文，也不能充当业务执行授权。已有宿主事务拒绝接管；MySQL要求自动提交开启，旧PDO手工事务由服务器保存点探测补充识别，组件不自动切换连接的自动提交或隔离级别；SQLite通过显式BEGIN IMMEDIATE取得写事务，兼容PHP7.2手工事务不被PDO::inTransaction识别的情况。MySQL接收记录及正文使用锁定读取，不将早期REPEATABLE READ快照当作当前记录。接收事务失败尝试回滚，清理失败后组件拒绝复用连接；无法确认或晚返回的COMMIT不自动重做，数据库可能已经保存消息，调用方重投后按已有合法记录去重。逐条SQL准备／执行前后检查总预算，确认期限已过后不发出新的接收写入；连接选项恢复后再检查总预算与期限，不能因提交已完成而报告晚返回成功。

宿主提供独立连接的传输／锁等待超时、入口和有效来源的请求预算、接收积压上限、私有数据库容量及保留策略。历史去重记录被删除或从旧备份恢复后，不能继续承诺旧事件不会重新进入；GitHub无签名时间的场景尤其需要当前业务版本或外部权威新鲜度核对。业务处理与接收必须分别验收，接收组件不自动执行或重做外部副作用。

## 可选工厂与只读诊断

```php
$config = ['site' => 'my-project', 'webhooks' => [
    'events' => [
        'scope' => 'tenant-1', 'account' => 'provider-account',
        'url' => 'https://hooks.example/events', 'protocol' => 'standard-hmac',
        'key_provider' => 'current_keys', 'request_guard' => 'request_boundary',
        'inbox' => ['connection' => 'receive_db', 'integrity_keys' => 'receipt_seals',
            'association_guard' => 'current_business_association'],
    ],
]];
$security = SoSecurity\Security::fromArray($config, [
    'current_keys' => $currentEndpointKeyProvider, 'request_boundary' => $requestGuard,
    'receive_db' => $privatePdo, 'receipt_seals' => $independentHmacKeys,
    'current_business_association' => $associationGuard,
]);
$inbox = $security->webhookInbox('events');
$receipt = $inbox->accept($actualRequest, $authenticatedBodyMapper);
// 只有非null才确认接收；响应丢失时发送方可安全重投同一事件。
```

最多32个端点，字段未知、服务名缺失、错误类型／协议、非法URL／策略及不完整inbox配置拒绝。省略inbox时只启用`webhook(name)`验签；不要求authentication或通用storage，不生成密钥、账户、连接、目录或表。`webhookInbox(name)`使用全局site隔离接收记录，仍需提前显式部署SQL结构。配置断开外部数组引用，不能在校验后通过改原变量修改端点或预算。

`diagnose()`只检查配置、服务类型和可用扩展，不能代表密钥真实存在、回调新鲜、数据库结构／持久化正确或当前业务关联已验证；不会调用密钥／请求／关联回调，也不查询业务PDO。HTTPS／代理、Github未签名新鲜度、积压保留、封存密钥隔离、接收与处理分别列出人工核实项。工厂的默认原生调试输出隐藏服务回调捕获值、连接和存储对象，不能将安全服务容器的状态导出到公开日志。

示例先把已验签的端点、提供器账号、稳定事件ID、原始正文摘要和有界正文写入宿主SQL接收表，再返回成功。唯一约束与摘要比较区分同事件重投和同ID内容冲突；只有实际已持久接收的重复消息才能确认成功。无效签名、跨租户关联、缺少业务身份、未知事件类型及数据库故障不产生业务副作用。验签前消耗一次Nonce再返回成功会丢失失败重试，不能作为默认流程。

R4.3继续实现通用处理中／已提交／失败／需核对状态、工作进程代际、重试和恢复契约；本阶段SQL接收表只保证持久接收，不能宣称跨消息队列、数据库或外部服务恰好一次。外部副作用发生后响应丢失须使用业务幂等键或人工核对，过期租约不能使未知结果自动安全重做。

默认日志只含端点／事件的有界引用、结果与稳定错误码，不记录完整正文、认证头、密钥或异常链。接收表和备份可能含个人数据，由宿主决定加密、保留期、删除及恢复后旧消息处置；状态恢复不自动证明事件尚未处理。

## 验收安排

1. 公开接口与PHP7.2语法、默认拒绝、原始字节、密钥／协议隔离、时间／签名／正文预算和故障行为。
2. 维护方公开向量与独立Python签发／验证双向对照，覆盖多签名轮换、未知版本、编码别名、正文改动、未签名头变更与无时间戳限制。
3. 真实原生HTTP／TLS入口与SQL接收表；并发重复投递只有一项持久消息，同ID冲突拒绝，数据库失败重投能恢复，未授权业务列不读取／修改。
4. 九个运行时、真实后端与全新消费者、归档／文档／依赖检查；原生运维页面的登录、CSRF及隔离浏览器验证。
5. 实际提供器投递、密钥轮换、公网代理、运维恢复和独立安全审查分别保留外部验证状态，不能用本地模拟签名替代。

当前核心复验：`php tests/webhooks.php`与`python3 tests/webhook_vectors.py php`。独立模型使用Python标准库HMAC和OpenSSL至少1.1.1的EVP C API生成Ed25519签名，再由PHP sodium验证，覆盖二进制、中文、64KiB正文及边界／拒绝；GitHub公开向量与RFC8032原语单独检查。Python测试依赖不成为生产库依赖。OpenSSL1.1.1命令行不支持本测试所需的pkeyutl -rawin，因此使用其受支持的单次EVP API；不安装第三方Python密码库或改变系统OpenSSL。

参考：[Standard Webhooks 1.0.0规范](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md)、[GitHub投递验证](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)、[Stripe验签与失败恢复](https://docs.stripe.com/events/manage-webhook-endpoints)、[Symfony Webhook适配](https://symfony.com/doc/current/webhook.html)。

## 原生接入与管理页面

[webhooks.php](../examples/webhooks.php)为Standard HMAC发布器提供固定的原生接收端点。页面不自动创建数据库、业务账号、因子或密钥；生产提供器协议验收与本地合成投递分开记录。

部署环境变量前缀为`SOSECURITY_WEBHOOK_EXAMPLE_`：`ORIGIN`固定实际来源；`PATH`默认`/webhooks.php`；`HTTPS`默认要求真实HTTPS，只有显式`0`允许本地HTTP；`STORAGE`为Web根外已有0700规范目录；`DATABASE`为已有0600私有SQLite文件；`PROVIDER_KEYS`／`SEAL_KEYS`／`MFA_KEYS`为各自独立的0600私有JSON文件；`DUMMY_HASH`与实际bcrypt默认成本一致。密钥文件均为`{"current":"label","keys":{"label":"规范Base64编码的32字节"}}`，不放入Web目录、URL或日志。组件不信任`X-Forwarded-Proto`，反向代理的实际TLS状态交给可信部署层映射。

显式安装上方SQLite接收结构，再由宿主创建`webhook_accounts`身份源（tenant、subject、username、password_hash、version、enabled、roles、mfa_required）和`webhook_documents`业务索引（tenant、account、id、version、enabled、body）。两表分别约束租户内主体／用户名唯一，以及租户＋提供器账号＋资源ID唯一。账号版本、角色和因子来自当前权威数据；启用管理员的TOTP因子通过受保护的管理流程预先完成，不在页面中初始化。密钥和数据库完整备份／轮换／退役须另行验收。

向固定`?receive=1`端点POST `application/json`原始字节，正文严格映射六个字符串字段：id、type、resource、version、tenant、account。示例固定type=`document.changed`、tenant=`webhook-example`、account=`publisher-example`；资源／版本从当前业务表匹配且enabled=1。Standard消息ID必须与正文id相同，按协议签署消息ID、时间戳和原始正文。入口不会启动或读取浏览器Session，管理员Cookie不代替签名；成功只返回received、稳定receipt_id与duplicate，不返回正文、密钥、封存值或业务执行结果。

入口具有全局1200次／分钟、来源IP240次／分钟、有效发布器120次／分钟预算；有效来源预算在验签后映射阶段预占一次，业务关联回调保持只读。接收记录容量最多1000条，写事务中再检查总量，容量满时仍允许已存在事件的合法重投；该示例使用SQLite写事务串行化保护上限。状态目录键数、数据库字节容量、边缘网络限流及保留清理由宿主监控；示例不自动删除去重历史或重做业务。

不带查询参数的管理页面使用真实密码＋TOTP、CSRF及共享会话撤销；只有具有admin角色、最近300秒内完成强认证的当前会话可读取。数据读取前后复核身份，每次最多20条固定端点的有界接收元数据，无正文查询、业务执行或人工重放按钮。显示的元数据是惰性记录，不充当处理授权；后续处理与重放仍归R4.3。其他角色、仅密码管理员和已变更身份不返回记录。

### 重复头与可信接入要求

真实线缆请求已确认PHP7.2 CLI服务会覆盖同名重复头；应用拿到单值后不能恢复原始歧义。为此原生投递示例默认拒绝，只有可信服务器接入层在信息丢失前拒绝重复头／歧义消息边界后，才设置服务器内部`SOSECURITY_WEBHOOK_HEADERS_VALIDATED=1`请求属性。不得从任何客户端请求头、可直达后端的转发头或未经验证的全局开关复制该属性。部署应限制后端直达；若实际接入能力不满足，保持503并先修复接入层。这里的属性仅为宿主责任的显式契约，不能单独证明接入实现正确。

本地HTTP／TLS测试使用实际读取原始头的独立Python接入层，在转发到PHP之前拒绝同名／不同大小写重复头及不支持的传输编码，再由隔离测试路由核对私有随机凭据设置内部属性与实际TLS状态。直接访问后端或伪造客户端检查声明均拒绝。该接入层和随机凭据仅用于隔离测试，不安装到常驻站点，也不代表生产代理或Apache验收。

## 后续处理

接收后的SQL领取、事务完成、重试与恢复见[处理指南](webhook-processing.md)，R4.3仍在实施。该组件与原生工作端、通用幂等及外部副作用契约须分别验证，不将接收ACK当作业务完成。

接收页可显式设置`SOSECURITY_WEBHOOK_EXAMPLE_PROCESSING=1`显示处理状态和失败重试表单；须另行部署处理及业务示例结构。独立CLI执行、自动重试、业务幂等和调度游标见[处理与恢复指南](webhook-processing.md)，不在投递请求中执行业务。
