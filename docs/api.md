# API 凭据、请求签名与重放防护

这些组件认证调用方并检查精确权限范围。宿主仍须检查资源归属、业务状态和请求预算，明确哪条路由使用哪种认证；不能在签名失败后自动尝试匿名、Cookie 或其他更弱身份。网页演示入口：[API 凭据与签名](http://72.rocky.wsl/SoSecurity/?module=api)。当前为未发布候选 API。

## 两类密钥分别使用

`ApiKeys` 签发 Bearer 凭据：公开 ID 为 128 位随机值，秘密部分为 256 位随机值，格式 `sosk_<32位小写hex>.<64位小写hex>`。共享存储只保存完整随机 token 的 SHA-256 摘要、身份、权限范围和期限。随机 token 的摘要与用户密码不同，不使用可猜测字符串作 token，也不把用户密码拿来作 API 密钥。

`SigningKey` 是服务器之间的 HMAC 密钥，32–128 字节，由宿主从私有配置或密钥服务提供，推荐 `SigningKey::generate()` 或 32 字节 `random_bytes()`。签名端和验证端均需要秘密原文，因此不由 Bearer 摘要派生，不写入 AtomicStore，也不交给浏览器。`KeyRing` 为最多 128 个密钥的不可变配置快照；可信 `KeyProvider` 可实现有界在线查找。库没有默认密钥、密钥管理服务或完整 OAuth 系统。

## Bearer 最小接入

先创建位于 Web 根目录外的私有目录，Linux 权限 0700，再运行以下代码。生产使用共享 FileStore、RedisStore 或 MySqlStore；MemoryStore 和 SessionStore 不能在不同请求/访客之间维护凭据生命周期。

```php
require 'vendor/autoload.php';
$security = SoSecurity\Security::fromArray([
    'site' => 'orders-api',
    'storage' => ['driver' => 'file', 'directory' => '/private/orders/security'],
]);
$keys = $security->apiKeys();
// 仅在已授权的凭据管理操作中签发；并限制每个账号及全站的签发数量。
$credential = $keys->issue('service-account:42', ['orders:read'], 86400);
$tokenForOneTimeDisplay = $credential->token();
$idForManagement = $credential->identity()->id();

// 独立 Bearer 路由中的认证；仅使用宿主实际收到的 Authorization。
$identity = $keys->fromAuthorization($_SERVER['HTTP_AUTHORIZATION'] ?? null, 'orders:read');
if ($identity === null) { http_response_code(401); return; }
// 之后按 $identity->subject() 查询允许读取的订单，不能直接信任客户端提交的账号 ID。
```

`authenticate($token, $requiredScope)` 返回 `Identity|null`，`fromAuthorization()` 接受 `Bearer <token>`，认证失败返回 null。权限范围为最多 32 个、最多 64 字节的小写 ASCII 标识，如 `orders:read`；精确匹配，不支持 `*`、继承或自动授权。`Identity` 提供 `id()/subject()/scopes()/allows()`。

`issue()` TTL 默认 86400 秒，范围 1–31536000 秒，`Credential::expiresAt()` 为 Unix 秒；到期秒开始拒绝。`rotate($id): ?Credential` 原子替换摘要，ID/主体/权限/原始到期时间不变，旧 token 立即失效，不延长寿命；记录不存在或已到期返回 null。`revoke($id): bool` 原子撤销，返回是否原先有记录。管理方法不自带管理员授权，不能直接向普通访客公开。

只在签发/轮换结果中展示 token，宿主不要保存原文、记录 Authorization、序列化凭据对象、缓存响应或把 token 放到 URL。调试展示会遮蔽秘密，JSON 默认不输出私有字段，但显式调用 `token()/secret()`、PHP 序列化和宿主日志仍可能泄露；没有“自动全局脱敏”。凭据 ID 的存在性/存储时延也没有隐藏承诺。并发轮换的后一次可覆盖前一次；若存储提交后响应丢失，旧凭据可能已失效，必须通过已授权管理流程恢复，不能自动重新启用旧摘要。

## HMAC 最小接入

可信服务代码加载秘密后注入 `KeyRing`。`site` 隔离状态命名空间，`api.origin` 来自部署配置，不能用请求 Host 或转发头动态决定。

```php
require 'vendor/autoload.php';
$key = new SoSecurity\Api\SigningKey('orders-2026-10', $secretFromPrivateConfiguration,
    'service-account:42', ['orders:read']);
$security = SoSecurity\Security::fromArray([
    'site' => 'orders-api',
    'storage' => ['driver' => 'file', 'directory' => '/private/orders/security'],
    'api' => ['origin' => 'https://api.example.com', 'key_provider' => 'signing_keys'],
], ['signing_keys' => new SoSecurity\Api\KeyRing([$key])]);

// 调用方：同一原始字节用于摘要和发送，不要发送前再编码 JSON。
$body = '{"item":1}';
$uri = 'https://api.example.com/orders?view=brief';
$headers = $security->hmacSigner($key)->sign('POST', $uri, $body, 'application/json', 60);
// 将这四个头和 $body 交给宿主 HTTP 传输；不可自动重放带同一 Nonce 的业务请求。

// 验证方：读取受限大小的原始请求体，保留原始 REQUEST_URI（含查询顺序）。
// $actualHeaders 为服务器实际收到的字符串头映射；多值或重复安全头须在边界拒绝。
$identity = $security->hmacVerifier()->verify($actualMethod, $trustedOrigin . $rawRequestTarget,
    $rawBody, $actualHeaders, 'orders:read');
if ($identity === null) { http_response_code(401); return; }
// 验证成功表示已原子消费 Nonce。之后检查资源归属，再执行已授权业务。
```

无需工厂也可直接组合 `SignaturePolicy/HmacSigner/HmacVerifier/KeyProvider/NonceStore`。示例 [api-request.php](../examples/api-request.php) 展示可信 Origin 与原始 request-target 组合，实际独立 Python HTTP 测试调用该函数。库不自动读取请求、启动 Session、发响应头或执行业务。

## 配置档与互操作

采用 [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html) 和 [RFC 9530 Content-Digest](https://www.rfc-editor.org/rfc/rfc9530.html) 的有界子集，双方须约定 `sosecurity-v1`。不是接受全部 RFC 算法/组件/结构的通用解析器，其他符合 RFC 的配置档也可能被拒绝。

- 单个签名标签 `sig1`，签名算法固定 `hmac-sha256`，tag 固定 `sosecurity-v1`。
- 覆盖组件固定顺序：`@method`、`@target-uri`、`content-digest`、`content-type`。
- 参数固定顺序：`created`、`expires`、`nonce`、`keyid`、`alg`、`tag`。时间为最多10位、能由当前PHP整数表示的规范十进制非负 Unix 秒；Nonce 为 16–128 个 base64url 字符，默认 24 个随机字节；keyid 为 1–64 个 `[A-Za-z0-9._:-]` 字符。
- `Content-Digest` 固定为原始请求体 SHA-256 的 RFC 9530 字节序列表示，即使空请求体也必须提供。签名为 32 字节原始 HMAC 的规范 Base64 字节序列。
- 签名基串每行是组件名称、冒号空格和值，行之间 LF，最后一行为 `@signature-params`，结尾没有 LF。相关头名称不区分大小写；库拒绝映射中的重复相关头、多值数组、控制字节、超 4096 字节相关头或超 64 个头的映射。
- 方法仅支持大写 GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS；URI 必须与配置 Origin 一致并且已经是共享 `Http\Uri` 的规范形式。不是自动转换后验证：大小写主机、显式默认端口、点路径、片段、省略 `/` 等非规范输入拒绝。保留查询顺序、重复查询键、合法百分号编码和请求体二进制字节；URI 仍拒绝编码控制字节等歧义输入。
- Content-Type 必须提供、1–256 字节可打印 ASCII，去除两端空格后覆盖完整值。双方不得在签名后改变内部空白、参数、请求体或 URI。

只有上述四个组件受保护。宿主不得依据未覆盖的额外头提升身份、权限或改变业务含义；需要覆盖额外业务字段时把它们放进签名的 URI/请求体并验证 schema，或使用经审查的其他配置档。验证前不解析/重排 JSON、表单、查询或百分号编码；对 Content-Encoding、代理路径重写及重复头的处理由明确的服务器边界规则决定。PHP 只能检查服务器交付的头；不能证明前置服务器已经拒绝合并前的全部重复原始头。

| api 配置项 | 默认与限制 |
| --- | --- |
| origin | 必填、精确 HTTP Origin；生产必须 HTTPS |
| allow_http | false；true 仅用于隔离本地测试，不保证传输机密性 |
| maximum_lifetime | 300 秒；1–900；sign() 默认实际签名寿命 60 秒 |
| clock_skew | 30 秒；0–120；包含到期时间加偏差的最后一秒 |
| maximum_body | 1048576 字节；0–20971520；宿主应在读取前/读取中限制，不只在传给库后判断 |
| key_provider | 工厂验证器必须配置对应可信 KeyProvider 服务；无默认密钥 |

## Nonce、拒绝与依赖故障

只有时间、摘要、密钥、权限和 HMAC 全部通过才原子登记 Nonce，错误签名不分配 Nonce 记录。同一 keyid 下、已接受请求的保留窗口内 Nonce 不能跨路由重复；调用方始终生成新随机 Nonce，不复用过期值；存储与所有验证节点必须共享。`NonceStore` 默认接受最大 3600 秒的剩余保留期，构造范围 1–86400 秒；独立调用 `consume($scope,$nonce,$expiresAt)` 使用绝对 Unix 到期秒，过期或超限返回 false。

验证器保留到 `expires + clock_skew + 1`，避免存储在最后可接受秒提前删除；锁/CAS 等待后过期仍拒绝。如果 Nonce 已登记但后续授权或业务失败，它仍已使用。重试需新签名和新 Nonce；业务幂等键/数据库事务由宿主实现，Nonce 不保证业务“恰好执行一次”。

无效/过期/篡改/权限不足/重放返回 null。参数配置错误抛 `ConfigurationException`；故障存储抛 `StorageException`；KeyProvider 故障或返回不同 ID 抛 `SecurityException`（`api.key_provider`）。故障不能降级为成功，也不要把底层异常详情/密钥放进响应。先实施共享入口限流，防止大请求哈希、随机未知 ID 和合法调用方批量 Nonce 占用资源；保留期、定期清理与容量策略见存储指南。

NonceStore 的纯回调可被 Redis CAS 重试，不执行外部 I/O。高层工厂拒绝 MemoryStore/SessionStore 及其 NamespacedStore 包装；自定义 AtomicStore 的共享性仍需宿主证明。Redis 重启/恢复必须遵守 redis-recovery.md；File/MySQL 备份恢复可能丢失已消费 Nonce，也可能复活已撤销 Bearer 摘要，不能把旧状态备份直接恢复为仍有效的凭据。恢复前停流、轮换/撤销相关密钥并等待签名窗口结束，重新验证部署恢复流程；不要使用会丢失状态的驱动切换实现透明降级。

HMAC 撤销/轮换应使用新 keyid，并把新 KeyRing 部署到全部验证工作进程，或使用可信在线 KeyProvider；旧快照不自动更新，不承诺所有节点瞬时撤销。密钥应绑定明确主体和最小权限。生产验证 TLS、代理可信来源、准确 public Origin、原始 URI/请求体交付以及时钟同步；时钟大幅回拨等异常应停流并轮换凭据，不承诺已过保留窗口的历史状态永久阻止重放。Bearers 也必须走 HTTPS；使用 Cookie 认证的其他路由仍需要 CSRF，不因增加 API 路由全局关闭 CSRF。

## 演示与验证命令

网页提供短期测试凭据签发/权限/轮换/撤销、访客归属、签名篡改/正常/重放/过期/存储故障。只操作私有共享文件存储与服务器 Session，没有真实账号或外部签名业务端点；固定 URI 不发网络请求，不显示 HMAC 秘密。分配/消费操作全站共用每分钟 30 次额度；每访客一个有效 Bearer，120 秒到期，签名 60 秒、偏差 0 秒。网页控制仍受 CSRF 保护。

```sh
php72 tests/api.php
python3 tests/api_vectors.py --php php72
python3 tests/api_http.py php72
python3 tests/api_demo.py php72
python3 tests/api_demo.py --url http://72.rocky.wsl/SoSecurity/
```

跨语言测试独立使用 Python hashlib/hmac 实现配置档，并检查 PHP 签发的字节一致性；另校验 RFC 9421 B.2.5 公布的 HMAC 原语向量，不把原语向量当成完整配置档验证。真实 HTTP 测试只在 127.0.0.1 隔离测试服务器发送签名/二进制体/原始查询及 Bearer 生命周期请求；该无管理员校验的固定测试路由不公开部署、不进入 Composer 包。File/Redis/MySQL 的 24 进程重放及凭据轮换检查见 `tests/concurrency.php` 和 `bin/check.sh`。

这些自动检查不替代真实生产客户端、HTTPS/代理、密钥管理服务、完整 OAuth 互操作或独立安全审查。当前未发布版本允许修正 API；接入宿主先限制路由，按最小权限和负面用例验收后再冻结。
