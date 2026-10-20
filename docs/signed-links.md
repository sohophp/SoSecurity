# 签名链接

`IssuedLink`包含可直接使用的完整凭据URL；当前对象导出不会展开URL或目标参数。只有显式调用`url()`才取得凭据，宿主仍须保护返回值及访问日志。旧序列化对象拒绝恢复，签发结果应从当前权威重新生成。

`Link\Links`提供固定来源地址、严格URL格式、资源版本绑定、有期限且可撤销的签名链接。默认保留共享状态，既支持有效期内重复读取，也支持原子单次消费；不在状态丢失或后端不可用时改为无状态放行。R3.5本地九版本完整检查、共享后端并发、新消费者、真实HTTP及PHP7.2／8.5浏览器验收完成；仍为未发布候选，完整R1—R6及生产验证继续，见[跟踪](security-refinement.md)与[验证](verification.md)。

## 最小调用

```php
$keys = new SoSecurity\Support\HmacKeys('current', ['current' => $privateSigningKey]);
$links = new SoSecurity\Link\Links($sharedStore, $keys, 'my-site',
    new SoSecurity\Link\Policy('https://files.example.com'), $requestGuard);
// 从权威业务源加载当前租户、对象版本和属性，不能从请求中接受这些授权声明。
$resource = new SoSecurity\Authorization\Resource('tenant-a', 'document', 'a', '17', ['owner' => 'account-a']);
$target = new SoSecurity\Link\Target('document.read', $resource, '/document', ['id' => 'a']);
$issued = $links->issue($target); // 默认300秒，可重复读取；URL仅在此显式交给用户。
$url = $issued->url();

// 独立请求：重新加载Resource／Target，传原始、完整绝对URL及实际请求方法。
$verified = $links->verify($currentTarget, $rawAbsoluteUrl, $requestMethod);
if ($verified === null) { /* 返回403，结束请求，不读取正文。 */ }
// 即时使用；仍要按当前资源版本读取，不能缓存VerifiedLink作为以后权限。
```

请求保护回调签名为 `(string $operation, Target $target, string $method): bool`，必须返回严格true。操作名为issue／verify／revoke／revoke_all／all；verify传调用方给出的实际方法，其余操作传逻辑方法（签发／撤销POST、元数据查询GET），宿主仍需校验真实入口请求。每个公共状态操作调用一次，回调不在可重试事务内；异常转为固定link.request_unavailable，不串联可能含秘密的原异常。false或其他返回值拒绝。管理操作需宿主身份／对象权限和预算，写请求还需CSRF；verify需真实路由／方法和请求预算，Cookie参与业务身份时还须对应CSRF／身份验证，不能仅因链接签名有效而混用另一账号的Cookie权限。组件不会自行查询账号、注册路由、启动Session、发送响应头或建表。

## 签名与URL格式

`Policy(origin, ttl=300, maximumTtl=86400, capacity=32, allowHttp=false)`要求精确规范来源地址，默认HTTPS，不接受路径、查询、凭据、尾斜线、默认端口或大小写别名；显式allowHttp仅供许可的本机验证。origin来自可信部署配置，不能从任意Host或转发头推断。宿主需确认入口Host／HTTPS／代理配置正确。

`Target(purpose, Resource, path, parameters=[], method='GET')`绑定用途、Resource完整指纹（作用域、类型、编号、版本、属性）、方法、路径和全部查询参数。方法仅支持GET／POST；路径为不超过512字节的绝对路径，各段按rawurlencode规范编码，支持UTF-8段，不接受点段、重复斜线、编码斜线／反斜线／百分号、二次解码或大小写编码别名。路径不含查询或片段。查询为最多32个具名字符串，名称为字母起始的ASCII标识，每值最多256字节有效UTF-8；拒绝控制字符、数组、数值和隐式类型转换。按名称排序并采用RFC3986编码，总查询最多1KiB，完整签名URL最多2KiB。

格式为 `origin + target.relativeUrl() + ?或& + _ss=sl1.keyId.randomId.issued.expires.mode.mac`。随机ID为128位，MAC为HMAC-SHA256的规范Base64url；密钥独立于CSRF、持久登录、API等协议。固定签名输入包含版本域signed-link-v1、站点、来源、目标指纹、密钥ID、随机ID、签发／到期时间、模式及可选绑定摘要。格式版本用于兼容审核，不宣称与其他框架的URL签名直接互操作。

签名覆盖所有查询参数，没有可忽略的跟踪参数。verify比较原始规范URL，不用PHP已折叠重复项的查询数组重建待验URL；重复、额外、重排、大小写或编码别名均拒绝。不能先替客户端规范化再验签。用途和Resource不是从token中解码的身份声明，由宿主重新加载的Target确定。

## 期限、绑定与单次策略

issue的可选ttl为1至maximumTtl，默认300秒、最大配置不超过一天；期限固定，不因读取续期。`issue($target, true)`创建一次性链接，verify在原子账本中消费后才返回VerifiedLink；九版本File／Redis／MySQL各24进程竞争验证仅一次成功。响应丢失、业务读取失败或用户未收完内容也不退款，必须重新签发。

GET链接可能被邮件扫描、浏览器预取或自动重试读取，一次性GET会被第一个有效GET消费。需要明确用户动作的兑换流程，应签发method=POST的Target：GET仅显示受保护的确认表单，不调用verify或执行业务，实际POST在完成所需CSRF／业务验证后消费。HEAD不能验证或消费GET链接，不能通过改成GET验签而借用授权；Range／条件请求及重复读取的具体下载策略继续R3.6。

可选binding用于绑定当前已验证上下文：issue和verify必须传入相同、服务器确定的值，最多1024字节；账本和URL不保存其明文。空绑定表示持有URL即具备该链接明确授予的读取能力，可以分享给另一浏览器；非空绑定不自动建立身份。不能把公开账号ID当作会话秘密；宿主决定使用会话、账号代际或其他可信绑定，并核验当前有效性。

## 查询、撤销和资源生命周期

all返回有界元数据快照：ID、签发／到期时间、单次标记、密钥ID和目标指纹，不含URL、MAC、参数或绑定；不是授权证明，也不是全站记录扫描。每个站点／用途／资源身份最多32条，可配置1—64，满额拒绝新签发，不挤掉有效链接。版本、路径、参数和绑定不同的同一资源用途共用容量；宿主另管理总资源／键数、签发预算和清理任务。

revoke(target,id)撤销该资源用途的一条链接，revokeAll(target)撤销其全部链接，包括此前版本／路径／绑定；不同用途、租户、资源和站点不受影响。管理时重新加载当前对象并验证管理权限。更换资源版本／归属等属性后，旧链接与当前Target不匹配；删除对象或禁用相关身份由宿主资源加载器明确拒绝。签发者退出并不自动撤销所有可分享链接，如需联动须接入撤销或将其安全代际纳入当前Resource属性／binding。

密钥轮换用新ID签发，保留旧密钥时旧链接仍可验证，删除旧密钥后旧签名拒绝；需让所有工作进程更新快照，不能只更新一个对象。all中的key_id可供宿主清理退休密钥记录。不复用旧密钥编号替换密钥，不将密钥写进URL、Session或日志。

v1账本仅保存秘密摘要、目标指纹、期限／单次标记和密钥ID，逐次验证其结构及与已认证签名内容的一致性。验证／查询保存观察时间并清理到期项；有活动链接时观察到的时钟回退拒绝。全部记录消失时没有可恢复的旧授权；不得从旧token重建状态。策略指纹改变、结构损坏、时钟错误、存储故障均拒绝；活动策略变更需按旧配置撤销／显式迁移。真实期限由注入Clock和后端时间／TTL共同保障，生产时钟、驱逐、持久性及备份恢复须另验收。

事务回调可重试且纯粹，随机数、密钥运算、请求保护和时钟读取均在回调之外。I/O后到期或时钟回退不返回授权，并按ID及秘密摘要精确清理，不删除并发替代记录。一次性消费只保证账本内单次授权，不保证业务数据库／邮件／外部服务恰好执行一次，也不保证旧账本备份恢复后永久防重放。

## 缓存与输出

签名URL属于敏感凭据，接入处使用HTTPS、no-store／private等适当缓存策略、Referrer-Policy:no-referrer，限制日志、统计脚本、第三方资源及错误页中的完整URL。CDN／代理缓存不能绕过每次验证，不能对未验证请求返回304或复用先前VerifiedLink。公开生成URL时按HTML属性上下文编码，禁止开放跳转或任意远程抓取。

浏览器不发送URL片段；它不能携带需服务器验证的授权信息。Target不接受片段，传给verify的完整URL也不接受片段；浏览器端后来添加的片段不会改变HTTP请求中已经签名的目标。UTF-8按实际字节绑定，不自动做Unicode规范化或二次解码。

撤销只影响后续验证，无法收回已下载内容或中断已开始的响应。并发撤销与验证各自在账本提交点生效，之后的业务副作用仍需宿主资源版本／事务控制；完整文件路径、符号链接、流读取及预算继续由R3.6授权下载处理。

## 工厂

```php
$security = SoSecurity\Security::fromArray([
    'site' => 'my-site',
    'storage' => ['driver' => 'file', 'directory' => '/private/my-site/security'],
    'signed_links' => ['origin' => 'https://files.example.com', 'keys' => 'link_keys', 'request_guard' => 'link_guard'],
], ['link_keys' => $keys, 'link_guard' => $requestGuard]);
$links = $security->signedLinks();
```

默认不启用，必须注入独立HmacKeys及请求保护。工厂拒绝Memory／Session共享后端；直接构造允许用于隔离测试，不代表跨会话或生产支持。诊断只报告密钥／传输／请求保护／当前资源和缓存的人工核验边界，不生成凭据或联网。

## 原生页面

[signed-links.php](../examples/signed-links.php)提供真实密码登录的签发／查询／撤销，以及独立浏览器通过Bearer链接读取固定租户文档；三种模式为期限内GET重复读取、一次性GET、GET只显示通用表单再POST明确兑换一次。兑换页GET不读取正文，也不声称链接已经有效；实际POST须本访客CSRF及有效签名。公开读取不解析登录身份，不把另一浏览器的Cookie权限混入Bearer授权。

部署需显式配置：

- SOSECURITY_LINK_EXAMPLE_DATABASE：Web根之外现有0600私有SQLite文件；SOSECURITY_LINK_EXAMPLE_STORAGE：独立0700共享FileStore目录，命名空间link-example。
- SOSECURITY_LINK_EXAMPLE_KEYS：Web根之外现有0600 JSON密钥文件，最多16KiB，且有界读取；仅current和keys两项，keys将1—8个密钥ID映射至32—128字节秘密的规范Base64。使用随机秘密并按新ID轮换，不在网页填写或生成生产密钥。
- SOSECURITY_LINK_EXAMPLE_ORIGIN：固定规范来源地址；SOSECURITY_LINK_EXAMPLE_PATH可选，默认/signed-links.php；SOSECURITY_LINK_EXAMPLE_DUMMY_HASH：与默认bcrypt cost12匹配的假账号哈希。
- SOSECURITY_LINK_EXAMPLE_HTTPS默认启用；真实请求必须由可信服务器标记HTTPS，Host精确匹配来源地址。仅隔离本机HTTP验证时设为0并配置http来源；不信任客户端转发头，不自动适配任意反向代理。
- SOSECURITY_LINK_EXAMPLE_TTL可选，服务器限定1—86400秒，不接受客户端改期限。入口／动作预算分别120／80次每分钟。

宿主预建link_accounts(tenant,subject,username,password_hash,version,enabled,roles)，唯一(tenant,subject)和(tenant,username)；roles为有界角色列表JSON，enabled只取0／1。link_documents(tenant,id,owner,version,title,body)按(tenant,id)唯一；租户固定link-example。页面不建表或创建默认账号，签发者须真实登录、editor角色且拥有对象；生产需要的MFA和账号管理继续接宿主认证流程。

资源元数据来自当前SQL，绑定文档版本和所有者有效身份指纹；账号禁用、角色／密码哈希变化或对象版本／归属改变会让旧链接失配。正文仅在签名通过后读取，并同时约束租户、对象版本、归属、原始账号版本及保存密码哈希；读取后复核链接期限。数据和角色／身份生命周期变更仍须正确推进权威版本，缓存／业务事务及已开始响应边界不因此消失。

页面使用no-store,private、no-referrer、限制CSP及HTML编码；未知额外查询、错误方法、撤销／到期及故障不能返回正文。常驻Apache未配置此示例私有库或密钥，缺配置仅503通用错误；隔离HTTP／浏览器通过不表示生产已接入。

设计参考：[Laravel签名URL](https://laravel.com/framework/docs/12.x/urls#signed-urls)、[OWASP授权](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)。
