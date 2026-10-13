# 无状态 CSRF 与精确路由策略

`Csrf\SignedTokens` 使用 HMAC-SHA256，把令牌绑定到固定站点、固定业务场景和当前已验证登录上下文。它不创建或查询令牌存储，不自动启动 Session 或发送 Cookie。适合宿主已有可靠无状态 Cookie 认证、且不需要逐令牌撤销/单次消费的表单。已有框架提供合适 CSRF 防护时优先复用；原生 PHP 可以直接使用本组件。

[OWASP CSRF 指南](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)支持绑定登录上下文的签名双重提交模式。签名不能替代身份绑定；静态用户 ID 或邮箱不适合作为每次登录的绑定值。下面的时间窗口、站点/场景及版本化格式是本项目的有界配置档，不声称是 OWASP 的标准令牌格式或通用认证协议。

## 先选择策略

| 场景 | 使用方式 |
| --- | --- |
| 已有持锁 PHP Session | 继续使用 `CsrfTokens(SessionStore)`；无需额外签名密钥 |
| 必须单次消费/显式撤销 | 使用共享原子存储的 `CsrfTokens`，按需 `verify(..., true)`；业务仍需要事务/幂等性 |
| 已验证且每次登录唯一的 Cookie 身份、无需 CSRF 令牌存储 | `SignedTokens`，优先签名双重提交；宿主提供私有密钥及可靠绑定 |
| 登录前/匿名表单 | 优先原有有状态 CSRF；不能把随机客户端 Cookie 或未经验证 JWT 字段当成已验证登录绑定 |
| 只接受已验证 Bearer/HMAC、浏览器不自动携带认证的 API | 明确路由豁免并保持其认证/权限检查；Cookie 认证路径仍需保护 |

纯无状态验证允许有效期内重用，无法在保留同一身份/密钥时逐令牌撤销，也不保证单次消费。不要在原有存储故障后自动切换为无状态模式；两类令牌格式和业务安全边界不同。

## 最小初始化与调用

先在宿主私有配置生成并保存独立的至少 32 字节随机密钥，所有相关节点加载同一配置。不要每个请求生成新密钥，不复用 API/密码/审计密钥，不接受浏览器配置秘密。

```php
require 'vendor/autoload.php';
$keys = new SoSecurity\Support\HmacKeys('csrf202610', [
    'csrf202610' => $secretFromPrivateConfiguration, // 例如初始化时 random_bytes(32)，私有保存后复用。
]);
$security = SoSecurity\Security::fromArray([
    'site' => 'orders-site',
    'stateless_csrf' => ['keys' => 'csrf_keys', 'ttl' => 7200],
], ['csrf_keys' => $keys]);
$csrf = $security->signedCsrf();

// 宿主先完整验证身份、期限及授权；值随登录变化，如已验证登录令牌的唯一 jti。
// $verifiedLoginBinding 不能来自未验证的请求参数/转发头/身份 Cookie 的裸内容。
$method = $_SERVER['REQUEST_METHOD'] ?? '';
if ($method === 'GET') {
    $token = $csrf->reuseOrIssue('orders:update', $verifiedLoginBinding,
        $_COOKIE['__Host-orders-csrf'] ?? null);
    // Secure=true、Path=/、无Domain符合__Host-要求；认证Cookie由宿主管理。
    header('Set-Cookie: ' . SoSecurity\Http\Cookie::header('__Host-orders-csrf', $token,
        '/', true, true, 'Lax'), false);
    header('Cache-Control: no-store');
    echo '<form method="POST"><input type="hidden" name="_csrf" value="'
        . SoSecurity\Output\Escaper::html($token) . '"><button>提交</button></form>';
    return;
}
if ($method !== 'POST') { http_response_code(405); return; }
// 状态变化请求：当前身份已由宿主重新验证，不能只检查CSRF Cookie。
require_once 'vendor/sohophp/sosecurity/examples/signed-form.php';
if (!SoSecurity\Examples\verifySignedForm($csrf, 'orders:update', $verifiedLoginBinding,
    $_COOKIE['__Host-orders-csrf'] ?? null, $_POST['_csrf'] ?? null,
    $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null)) {
    http_response_code(403); return;
}
// 然后按已验证身份检查资源归属、输入和业务状态，执行已授权操作。
```

上述宿主身份/私有秘密由真实认证和部署配置提供，库不创建默认用户或认证系统。[signed-form.php](../examples/signed-form.php)的两个可调用函数已进入真实HTTP/HTTPS测试；表单值和头同时提供但不相等时拒绝，不静默选择一种来源。返回 false 后必须结束业务。

也可直接 `new SignedTokens($keys, $audience, $ttl, $clock)`，不要求工厂或任何框架。`verify($scope,$binding,$token)` 是签名/上下文验证；`verifyDoubleSubmit($scope,$binding,$cookie,$submitted)` 额外要求 Cookie 与显式提交值一致。JSON API宿主先做有界解析，再把选定字段传入；库不自动读请求体。

`reuseOrIssue()` 复用仍有效、属于此登录/场景的令牌，保持多标签页的双重提交对稳定；复用不延长原签名期限。失效后新表单生成新令牌，旧表单应提示用户刷新。不同业务场景若使用双重提交 Cookie，应使用不同 Cookie 名，避免互相覆盖。Cookie 的浏览器保留期与服务端签名期独立，最终以签名验证为准。

HttpOnly Cookie 可以使用从已授权 HTML/JSON 得到的令牌做 AJAX 提交，无需 `document.cookie` 读取；示例采用此方式。若宿主选择JS读取Cookie，应明确取消相应CSRF Cookie的HttpOnly，但认证Cookie仍应保护。生产必须 HTTPS，并核实可信代理及客户端直达路径，不能根据任意 X-Forwarded-Proto 启用信任。

## 密钥、期限与格式

`HmacKeys($currentId,$map)` 为不可变私有快照：1–8个密钥，ID为1–32个 `[A-Za-z][A-Za-z0-9_-]*` 字符，秘密32–128字节；私有配置应使用足够随机的秘密。没有明文getter，调试展示遮蔽秘密，JSON不输出私有属性，PHP序列化明确拒绝。它不提供KMS、自动撤销传播或全局日志脱敏，宿主不能把原始密钥配置写入日志。

SignedTokens 的 TTL 默认7200秒，范围1–86400秒；到期秒开始拒绝，没有隐式时钟偏差。身份寿命、退出和重新登录仍由宿主认证约束，TTL不是认证凭据期限。每次登录必须使用新的可信绑定，即使用户 ID 不变；身份绑定改变会拒绝旧令牌。节点时钟需要同步，异常时间不能代替认证检查。

公开格式为 `socs1.<keyid>.<created>.<expires>.<nonce_hex>.<mac_hex>`，最多256字节，两个时间为最多10位、当前PHP整数可表示的规范十进制，Nonce为32个随机字节的小写Hex，MAC为32字节HMAC的小写Hex。原始绑定/站点/场景不写入公开令牌，不是加密身份令牌。验证固定版本和结构、时间/最大寿命、MAC及上下文，MAC使用 `hash_equals`；最后再次检查时间边界。

HMAC消息以 `SoSecurity.CSRF.v1` 和 LF 开始，随后分别为站点、场景、绑定的「字节长度:值」及 LF，最后为MAC之前的完整公开前缀，无尾随LF；中文和二进制绑定按真实字节长度，不按字符数计。支持Python独立互操作向量，但它是本库有界格式，不接受其他框架自有CSRF格式。

轮换时创建新 `HmacKeys`：current选择新ID，同时在计划窗口保留旧密钥，旧令牌可继续验证，新签发用新ID。移除旧密钥后旧令牌立即在该快照拒绝。所有节点/工作进程都要更新；旧快照不自动刷新。多个旧钥最多8把，恢复备份或密钥泄露时应同时检查宿主身份恢复/失效，不能以过期状态恢复实现透明降级。

无效、缺失、数组、篡改、跨站点/场景/登录、过期及未知密钥返回 false；错误配置/绑定抛 `ConfigurationException`，密钥服务未注入也明确拒绝。Crypto组件没有外部状态服务，宿主身份/密钥加载发生故障仍须拒绝，不能把有效CSRF MAC当作登录成功。XSS、资源授权、Cookie/代理配置、用户意图确认和业务幂等性仍由宿主负责。

## 明确豁免方法与路径

```php
$security = SoSecurity\Security::fromArray([
    'site' => 'orders-site',
    'csrf' => ['exemptions' => [['method' => 'POST', 'path' => '/hooks/provider']]],
]);
$required = $security->csrfPolicy()->requiresToken($actualMethod, $canonicalPathWithoutQuery);
// false仅表示本策略不要求CSRF Token；/hooks/provider仍须执行真实签名认证。
```

`RequestPolicy` 是纯决策，默认对 GET/HEAD/OPTIONS 返回false，对其他大写方法要求Token。宿主必须保证这些读取方法不写业务；禁止从未验证的 `_method` 等字段决定豁免。输入是实际方法与规范路由路径，不是整条URL、带查询的request-target或未经审查的代理改写结果。

最多32项豁免，只有method/path两字段；方法1–32个大写字母。配置路径限定纯ASCII未转义路径，不接受正则、glob、编码别名、矩阵参数、重复斜杠、点路径、片段或查询。精确区分大小写、尾斜杠、子路径和方法；如POST豁免不会豁免DELETE。请求路径出现编码别名或额外子路径时仍要求Token，歧义/非法路径抛`ValidationException`并应结束请求。按查询参数路由的旧站不能把同一index.php入口作为所有业务的宽豁免；应在匹配实际业务路由后决策。实际路由/代理的别名由宿主审查，不自动设置全局中间件、改变已有认证或关闭全部API保护。

诊断 `csrf.signed.keys` 只检查服务类型，密钥生命周期标记manual；`csrf.signed.binding` 标记manual，因为库无法证明宿主已经验证且每次登录更换绑定。诊断不列出秘密或读用户身份。

## 演示与证据

[无状态CSRF演示](http://72.rocky.wsl/SoSecurity/?module=stateless)：30秒令牌、真实独立Cookie双重提交、篡改/跨登录/场景、允许重用、到期、保留/移除旧钥、模拟登录绑定变化、密钥配置错误和固定路由策略预览。控件/模拟身份使用现有演示Session，核心不使用令牌存储；Session中记住的公开token只供界面显示，不用作验证参照。轮换只影响此访客，不改变站点生产密钥；预览策略不应用到入口。

当前HTTP演示不证明生产HTTPS Cookie；独立HTTPS测试在临时TLS终止代理后运行PHP，urllib验证每次测试证书，Chromium确认__Host/Secure/HttpOnly与实际同站不同来源攻击拒绝。Chromium仅为临时自签测试证书设置ignoreHTTPSErrors；不安装系统CA，也不声称生产证书/代理已验收。测试身份为固定私有测试上下文，没有真实用户；测试登录路由不公开、不进入Composer包。

```sh
php72 tests/signed-csrf.php
python3 tests/signed_csrf_vectors.py --php php72
python3 tests/signed_csrf_http.py php72
python3 tests/signed_csrf_https.py php72
SOSECURITY_PLAYWRIGHT_MODULE=/absolute/path/to/playwright python3 tests/signed_csrf_https.py php72 --browser
python3 tests/signed_csrf_demo.py --url http://72.rocky.wsl/SoSecurity/
```

HTTPS测试工具要求Python 3.7+的TLS接口及openssl；本机使用Python 3.11。核心不依赖Python/Node。具体已执行/失败/未执行状态见 [verification.md](verification.md)。无状态功能不替代1.0的全版本、真实旧站和独立复核；旧项目分路由迁移，保留状态变化/认证/资源授权检查及明确拒绝路径。
