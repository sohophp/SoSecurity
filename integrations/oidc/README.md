# SoSecurity OIDC 可选适配（阶段性实现）

此包目前要求 PHP 7.2–8.3，依赖 `jumbojett/openid-connect-php` 稳定 1.0.2 系列。核心包不自动安装或启用 OIDC。当前提供固定 HTTPS 端点的授权码客户端、严格 ID Token 声明校验、`issuer + sub`关联账本、独立联合会话及Back-Channel Logout Token验证／持久回执。联合会话在每次请求重查账号、关联和注销栅栏；失联恢复解绑的SDK入口已提供，但真实宿主独立审批／审计、MFA账号的联合登录、第三方发行方及真实宿主接入仍未完成，不应直接作为完整单点登录方案上线。

`VerifiedSubject`和`VerifiedLogout`的主体、提供方会话ID与注销令牌ID不会出现在常见对象导出中；读取方法仍只面向当前已验证的对象，旧序列化对象会被拒绝。`StrictClient`的普通调试与对象导出在构造后、授权码回调成功及失败后均不保留客户端密钥或上游令牌；密钥只在实际换令牌时短暂装入上游对象并在`finally`清除。直接调用继承的`authenticate()`、令牌setter、刷新、旧注销入口、客户端凭据／密码／令牌交换等其他授权方式及动态注册会拒绝；外部直接重定向也拒绝，`getClientSecret()`在令牌交换之外不可用；宿主通过`VerifiedSubject::fromClient()`和`VerifiedLogout::fromToken()`进入协议流程，不得把客户端对象交给模板、调试端点或不可信代码。实现依赖上游v1.0.2的内部字段，可选包精确锁定该版本，升级前须重新审查字段清理与协议测试。

`StrictClient` 接收已审核的发行方、客户端 ID／私密凭据、回调 URL、授权／令牌／JWKS 端点。构造后关键安全配置不可改写；固定令牌端点认证方式并拒绝隐式发现；出站读取仅允许固定令牌／JWKS端点，不跟随跳转，响应上限128 KiB，连接／总超时分别为3／10秒；回调先核对服务端保存的 `state`，再将授权码交给上游令牌端点。宿主须将其配置固定在可信服务端，保管客户端密钥，使用共享服务端会话保存 OIDC `state`、`nonce` 和 PKCE 状态，并由该客户端完成回调及上游签名验证。`VerifiedSubject::fromClient()` 只接受原始 `StrictClient` 实例并在回调验证成功后产生外部主体，保留已签名的`issued_at`与可选提供方`sid`；这些字段尚未赋予本地会话权限；`null` 表示开始跳转，不能当作已登录。当前静态 URL 检查不负责 DNS／网络层防 SSRF；端点仍须由宿主批准并限制出站访问。适配器禁用环境代理，部署需能直接访问已批准端点。不要向不可信代码暴露客户端实例。

`LinkRegistry` 使用宿主的 `AtomicStore`、`IdentityProvider` 和 `SessionRegistry`。`link()`／`unlink()` 要求宿主请求保护回调放行，并验证最近 300 秒内的非恢复本地登录；MFA 账号要求二级认证。一个外部身份最多关联一个当前本地账号；同一账号重复绑定该外部身份保持原关联。`resolve()` 每次重新读取本地账号并核对指纹，账号版本变化后旧关联不授予权限。关联不依据邮箱、名称或声明自动完成。宿主应通过`FederatedSessions::issue()`及`verify()`接入联合登录，在每次受保护请求重新验证凭据，并对绑定、解绑和异常进行审计。`MemoryStore` 仅适合单进程测试；实际部署使用共享原子存储。

提供方不可用且拿不到新的`VerifiedSubject`时，宿主可以调用`recoverUnlink($scope, $subject, $localSessionToken, $issuer, $remoteSubject, $approveRecovery)`。宿主请求保护回调须批准`federation_recovery_unlink`，本地凭据必须是最近300秒内的非恢复认证；MFA账号仍须二级认证。`$issuer`和`$remoteSubject`须由宿主可信的关联清单或受保护的管理流程取得，不能让用户输入邮箱并推断外部身份。`$approveRecovery`在存储事务外收到准确的站点、账号、发行方、外部主体及原关联时间／旧账号指纹／当前账号指纹，以及新版记录的`binding_id`（旧版记录为`null`）；仅严格返回`true`才执行删除。宿主必须用独立强审批和持久审计实现该回调，不能把当前本地会话本身当成第二重批准。审批后SDK重新验证本地会话和账号版本，再对准确关联作原子比较；期间重绑或改动均拒绝删除。新关联加入随机代际标识，仍能读取旧版关联。成功后`FederatedSessions::verify()`会拒绝旧联合会话，本地密码会话保持有效。宿主须在成功后通知账号持有人并记录操作结果；仅有此SDK入口不等于完整失联恢复验收。

`FederatedSessions`使用与关联和栅栏相同的共享`AtomicStore`，默认单账号最多16个会话、闲置30分钟、绝对8小时；宿主可在构造时收紧这些上限。`issue()`要求已验证的`VerifiedSubject`、当前关联和宿主的请求保护回调；返回`SessionCredential`中的`sofs_`令牌，只应保存在受保护的服务端会话中。`verify($scope, $localSubject, $token)`返回独立`FederatedSession`，认证方式明确为`oidc`，不提供本地密码／MFA强度，也不能传给本地`SessionRegistry`。账号配置或因子绑定要求MFA时直接拒绝签发／验证，直至独立二级验证流程可用。宿主不能缓存`FederatedSession`作为后续请求的权限依据，并须自行落实Cookie、CSRF、租户路由与授权映射；管理接口`revoke()`／`revokeAll()`只处理联合会话。

可选`LogoutFence`与`LinkRegistry`共用持久`AtomicStore`；构造`LinkRegistry`时作为第六个参数传入。签名Logout Token可由`LogoutProcessor::process($scope, $jwt, [$federatedSessions, 'revokeFromProvider'])`处理：先记待处理回执，回调持久写入栅栏后才标记完成；宿主必须将全部联合会话请求交给同一个共享存储上的`FederatedSessions::verify()`。栅栏按`issuer + sub`、`issuer + sid`或双目标分别记录最近注销`iat`，旧ID Token不再能通过绑定或解析；双目标仅影响该组合，单目标分别覆盖该主体或提供方会话。栅栏最多保留48小时，并在每次检查时拒绝超出当前ID Token 24小时签发窗口的旧凭据；每次解析仍需检查，不能缓存先前解析出的`Account`作为登录凭据。已有本地密码会话不受该栅栏影响。对`FederatedSessions`管理的凭据，持久栅栏会在下一次验证时使匹配会话失效；其他宿主自管会话还须在回调中单独持久撤销，不能只写栅栏就返回成功。

`VerifiedLogout::fromToken()`仅接受原始 `StrictClient`，验证签名、发行方、受众、`iat`、`jti`、注销事件、`sub`／`sid`及禁止`nonce`；显式提供的`sub`／`sid`不可为`null`，`azp`若存在必须匹配当前客户端；JWT最多16 KiB，`iat`限过去24小时至未来60秒，头部若含`typ`须为`logout+jwt`，不支持加密Logout Token。返回的`sid`是提供方会话ID，不是本地`SessionRegistry`管理ID。`LogoutProcessor::process($scope, $jwt, $revoke)`用共享`AtomicStore`先记录待处理回执，再在事务外调用宿主撤销回调；只有回调严格返回`true`且完成回执写入成功才报告成功。相同已完成令牌在回执保留期内不重复调用回调；失败或进程在撤销后中断时仍会重试，因此回调必须持久、幂等，并只撤销由`issuer + sub`或`issuer + sid`定位的联合会话。同一`jti`对应不同签名内容会拒绝。宿主应从受保护的路由配置取得`scope`，限制表单正文并只接受单个`logout_token`；不得在持久撤销前向提供方返回成功。当前包按本地账号保存有界联合会话记录，不提供跨账号会话枚举；注销栅栏在逐请求验证时拒绝匹配凭据，并不调用`SessionRegistry::revoke()`／`revokeAll()`，避免误撤本地密码会话。协议要求见[OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0-final.html)。

当前未实现MFA账号的完整联合登录、真实宿主失联恢复审批／审计／通知、关联记录批量撤销或迁移，本地签名令牌回调与原始客户端到本机自建HTTPS发行方的闭环已通过，但没有第三方发行方联调。依赖稳定版 v1.0.2 在 PHP 8.4 已发出隐式可空参数弃用告警，在 PHP 8.5 的严格错误处理下会中断，因此包的 Composer 范围暂不包含 PHP 8.4／8.5；发布前需要依赖兼容版本及完整联调。上游开发分支只用于本地兼容性探索，不是本包发布依赖。

本地专项（独立 Composer 消费者的 `vendor/autoload.php`）：

`python3 tests/oidc_consumer.py php72` 会创建并清理独立 Composer 消费者，检查锁定的上游 v1.0.2、依赖公告及下列专项；MySQL／Redis 只启动测试脚本拥有的本地私有实例。参数可换成任何包支持且安装了所需扩展的 PHP 运行时。CI 在 PHP7.2—8.3 运行此入口；PHP8.4／8.5 超出可选包声明范围。
追加`--archive`会先生成仅含运行时源码、README、Composer清单和许可证的ZIP，再从解包目录全新安装。PHP7.2／8.3本地已分别从ZIP运行完整消费者检查并通过，包含私有MySQL／Redis双进程与本机HTTPS回调／注销；CI定义已切换到此入口，远端尚未执行。真实发行方、宿主和公开仓库安装不由此证明。
该入口会清除继承的`SOSECURITY_TEST_*`目标变量；独立MySQL／Redis控制器也会隔离对方的测试socket，同时给双进程脚本传入两个后端目标会直接失败。

```sh
php72 integrations/oidc/tests/claims.php /path/to/consumer/vendor/autoload.php
php72 integrations/oidc/tests/client-debug.php /path/to/consumer/vendor/autoload.php
php72 integrations/oidc/tests/proof-export.php /path/to/consumer/vendor/autoload.php
php72 integrations/oidc/tests/links.php /path/to/consumer/vendor/autoload.php
php72 integrations/oidc/tests/fences.php /path/to/consumer/vendor/autoload.php
php72 integrations/oidc/tests/sessions.php /path/to/consumer/vendor/autoload.php
python3 integrations/oidc/tests/process_race.py /path/to/consumer/vendor/autoload.php php72
SOSECURITY_OIDC_AUTOLOAD=/path/to/consumer/vendor/autoload.php python3 tests/mysql_check.py --oidc-process php72
python3 integrations/oidc/tests/redis_process.py /path/to/consumer/vendor/autoload.php php72
php72 integrations/oidc/tests/signed-callback.php /path/to/consumer/vendor/autoload.php
python3 integrations/oidc/tests/tls_integration.py /path/to/consumer/vendor/autoload.php php72
php82 tools/vendor/bin/phpstan analyse -c integrations/oidc/phpstan.neon --autoload-file=/path/to/consumer/vendor/autoload.php --no-progress
```

`claims.php` 只探测声明校验路径，`links.php`／`sessions.php` 使用仅限测试的反射对象和本地存储；`signed-callback.php` 用本地 RSA 密钥、模拟端点响应和服务端 Session 走上游验签与回调。`process_race.py` 用两个实际PHP进程和私有FileStore复现签发提交后及验证读取后的并发注销，等待双方结束再清理目录；`mysql_check.py --oidc-process`创建私有无TCP MySQL实例，显式安装测试表，在该实例上执行同样的双进程竞态与`sessions.php mysql`完整定向场景，结束后关闭并清理，不使用宿主数据库。`redis_process.py`创建只监听本机Unix socket的私有Redis实例，显式初始化各命名空间，再运行同一组会话与双进程竞态检查，结束后关闭服务；运行时必须实际加载`ext-redis`。`tls_integration.py` 在私有临时目录生成测试证书，启动只监听本机的HTTPS发行方，用原始 `StrictClient` 验证TLS、令牌端点、JWKS、回调凭据到本地账号关联、独立联合会话、签名Logout Token、持久回执的失败／重试／中断恢复、重放及跳转／超限响应拒绝，结束后停止服务并清理目录。这些本地测试不证明第三方发行方、浏览器或真实宿主接入。
