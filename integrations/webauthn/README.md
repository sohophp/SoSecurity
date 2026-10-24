# SoSecurity WebAuthn 可选适配

此包独立要求 PHP 8.2+，依赖 `web-auth/webauthn-lib` 稳定 5.3 系列；SoSecurity 核心继续支持 PHP 7.2。适配器提供注册和登录的挑战生成、一次性状态绑定、响应加载、上游密码学验证、可选SQL凭据仓库、授权单设备删除及强审批恢复边界，不提供 HTTP 路由或宿主身份验证。当前是 R6.1 的阶段性实现，已通过本地 Chromium 虚拟认证器的 HTTPS 注册／登录验证；真实宿主审批／会话栅栏及实体安全密钥验收尚未完成。

生产接入应使用 `BoundCeremonies` 和 `ChallengeStore`，底层传入共享的 `AtomicStore`（如受保护的 `FileStore`、`RedisStore` 或 `MySqlStore`），以站点作用域隔离挑战。`beginRegistration()`／`beginAuthentication()` 返回随机句柄和应发给浏览器的选项；`finishRegistration()`／`finishAuthentication()` 依据句柄、账号、会话及用途在验证前原子消费选项。挑战期限为 30–600 秒，默认 300 秒；错误账号／会话不消费正确挑战，验证失败也不能重试同一挑战。`MemoryStore` 仅用于单进程测试。不要把句柄、完整选项或凭据对象直接写入日志。

SQLite／MySQL宿主可分别执行 `schema.sqlite.sql`／`schema.mysql.sql` 创建专用表，再用 `SqlCredentialRepository` 与 `PersistedCeremonies` 将验证和凭据持久化串联。仓库以站点作用域隔离，凭据ID全站唯一，账号最多32个活跃设备；签名计数器和备份状态用修订号比较并更新，撤销也按修订号生效。正文超过32768字节时SQL只返回长度与空正文，避免把异常大字段读入PHP；SQLite按BLOB字节长度计算，包含NUL的TEXT也不能绕过限制，并继续读取现有的正常TEXT记录。SQLite读取账号代际、设备数量、凭据索引和修订号时也先在SQL层校验类型或长度，异常元数据不会作为大值进入PHP。原始记录采用上游Serializer而非PHP反序列化。`revoke()`是低层存储操作，**不负责授权**。

宿主必须从当前服务端身份取`userHandle`和会话绑定，不接受请求体自行决定。设备注册与删除要先完成独立的近期认证；凭据恢复须另有强验证流程。`PersistedCeremonies::finishAuthentication()`成功返回后才能授予登录会话，数据库更新失败或修订号冲突均不得登录。SQL表的安装、备份和维护由宿主负责；当业务事务需要与登录状态变更合并时须另行设计同连接事务入口，当前仓库拒绝嵌套宿主事务。

新建表使用本包当前`schema.sqlite.sql`或`schema.mysql.sql`。若已安装早期无`generation`列的草案表，维护窗口内备份后**只执行一次**`migrations/001_generation.sqlite.sql`或`migrations/001_generation.mysql.sql`；不要对已含该列的表重复执行。`SqlCredentialRepository::register()`现在要求调用者传入本账号当前`generation()`，并在SQL事务内再次比较；`PersistedCeremonies`会自动绑定代际。单设备撤销及恢复都会推进代际，旧注册和登录挑战因此失效。

`DeviceManager::remove()`要求宿主提供`DeviceAuthority`：`before`阶段必须从服务端重读当前站点、账号、会话、近期认证，并消费POST的单次CSRF／请求证明；`return`阶段重读当前身份和授权状态，不再消费同一证明。任一拒绝均不能报告成功。删除在SQL事务中检查账号和修订号，并在并发情况下保留至少一个活跃设备；删除最后一个设备只能走另行设计的强恢复流程。通知回调在数据库提交后运行，如回调或`return`授权失败，方法抛“需对账”异常：数据库可能已撤销，宿主必须按当前存储状态补发通知并核对会话，不能将其当作普通失败重试。低层`SqlCredentialRepository::revoke()`不执行这些授权检查，不应直接暴露给HTTP入口。

可选`SessionDeviceAuthority`将这项宿主责任接到核心`SessionRegistry`及`CsrfTokens`。构造时提供与凭据仓库相同的作用域，以及每次都从受保护的宿主会话重新读取`subject`、注册表不透明`token`和宿主会话`binding`的回调；不得从请求体取这些值或缓存`VerifiedSession`。展示删除表单前调用`issueRemovalProof($serverUserHandle, $credentialId)`；提交时由宿主先验证HTTPS、POST、来源及当前会话，再把该证明传给`DeviceManager::remove()`。适配器要求强度2且默认300秒内的近期认证，把单次证明绑定到当前会话与准确设备，删除后再次核对同一会话；失联、权限变化或结果未知时抛错／拒绝，不替宿主发送通知、更新其他会话或实现恢复栅栏。生产`CsrfTokens`应使用宿主提供的共享原子存储，不能使用测试专用`MemoryStore`。

删除成功后，宿主可用`Ceremonies::acceptedCredentialsSignal()`生成WebAuthn 5.3的剩余有效凭据JSON，并在受保护页面通过浏览器[Signal API](https://github.com/web-auth/doc/blob/5.3/pure-php/advanced-behaviours/signal-api.md)更新通行密钥列表；信号只改善客户端显示，服务端撤销以SQL状态为准。生成前必须重新读取本账号的当前凭据，将`SqlCredentialRepository::forUser()`返回的各个`StoredCredential`转换为`record()`，不把其他账号的凭据传入。本地Chromium已验证两个虚拟认证器注册、受权删除一条凭据、服务端只列出剩余凭据及浏览器同步移除旧凭据；实体设备和真实宿主页面仍须单独验收。

`RecoveryManager::recover()`另要求宿主提供`RecoveryAuthority`。`begin`必须消费独立的强审批证明，并在返回`true`前持久阻断旧会话和新登录；本包随后事务撤销本账号全部凭据、把`generation`加一，再调用`complete`。宿主`complete`必须保留栅栏直至旧会话失效、恢复通知及新绑定策略完成。若`begin`以后任一步失败，返回的是“需对账”异常；不能解除栅栏或假定凭据未撤销。宿主每次接受现有会话和签发新会话时都必须检查同一恢复栅栏与账号代际，避免恢复与登录提交的竞态。此接口只规定调用顺序，**没有替宿主实现强审批、会话撤销或通知**。

`Ceremonies` 仅接受精确的 HTTPS Origin 与 RP ID 主机，注册选项明确提供 ES256／RS256、要求用户验证，默认只启用 `none` 证明类型。登录强制用户验证，输入 JSON 上限 65536 字节，并检查凭据归属、允许列表和 ID；其余 WebAuthn 协议检查交给上游 5.3 库。仅支持预先识别用户的登录流程，匿名用户名探测和无用户名登录尚未实现。

验证：用 PHP 8.2 在独立 Composer 消费者安装本包和 `web-auth/webauthn-lib` 5.3.9，然后运行：

可用`python3 tests/webauthn_consumer.py php82`一次创建并清理全新本地消费者：锁定5.3.9、执行`composer audit --locked`、核对机器可读依赖清单（本地path路径脱敏），并运行下列十一组组件测试。追加`--mysql`会由测试控制器建立禁TCP的临时私有MySQL并执行仓库测试，不使用业务数据库。设置`SOSECURITY_PLAYWRIGHT_MODULE`为本机Playwright目录并追加`--browser`，可让同一份新装依赖完成临时HTTPS／SQLite的Chromium虚拟认证器测试。当前源码PHP8.2—8.5各通过十一组，新增宿主授权专项各12项；PHP8.2／8.5另从ZIP在同一消费者中各通过私有MySQL 27项及Chromium闭环。CI定义覆盖四版，并在两端安装Playwright 1.58.2／Chromium后执行MySQL与浏览器组合；远端CI尚未运行。实体安全密钥须单独验收。

追加`--archive`时，控制器先生成本包Composer ZIP，再从解包目录全新安装并执行同一组检查。PHP8.2／8.5的归档消费者十一组、私有MySQL各27项及浏览器闭环均已在准确组合中通过；CI四版入口已改用归档消费者，远端未执行。发行ZIP只包含`src/`、数据库结构／迁移、`composer.json`、README及许可证，排除测试源码。

```sh
php82 integrations/webauthn/tests/smoke.php /path/to/consumer/vendor/autoload.php
php82 integrations/webauthn/tests/challenge.php /path/to/consumer/vendor/autoload.php
php82 integrations/webauthn/tests/challenge-race.php /path/to/consumer/vendor/autoload.php
php82 -d memory_limit=8M integrations/webauthn/tests/repository.php /path/to/consumer/vendor/autoload.php
php82 integrations/webauthn/tests/persisted.php /path/to/consumer/vendor/autoload.php
php82 integrations/webauthn/tests/device-management.php /path/to/consumer/vendor/autoload.php
php82 integrations/webauthn/tests/session-device-authority.php /path/to/consumer/vendor/autoload.php
php82 integrations/webauthn/tests/device-race.php /path/to/consumer/vendor/autoload.php
php82 integrations/webauthn/tests/recovery.php /path/to/consumer/vendor/autoload.php
php82 integrations/webauthn/tests/recovery-race.php /path/to/consumer/vendor/autoload.php
php82 integrations/webauthn/tests/migration.php /path/to/consumer/vendor/autoload.php
```

私有无TCP MySQL测试需先创建仅用于测试的Composer消费者，再以其`autoload.php`执行：

```sh
SOSECURITY_WEBAUTHN_AUTOLOAD=/path/to/consumer/vendor/autoload.php python3 tests/mysql_check.py --webauthn php82 php85
```

本地浏览器闭环需要 Python 3、Node.js、Playwright 与 Chromium；脚本只建立临时 SQLite 数据库及两个本地 HTTPS Origin，结束后清理。测试使用临时自签名证书并关闭测试浏览器的证书校验，这不验证生产 TLS 配置：

```sh
SOSECURITY_WEBAUTHN_AUTOLOAD=/path/to/consumer/vendor/autoload.php SOSECURITY_PLAYWRIGHT_MODULE=/path/to/node_modules/playwright python3 integrations/webauthn/tests/browser.py php82
SOSECURITY_PLAYWRIGHT_MODULE=/path/to/node_modules/playwright python3 tests/webauthn_consumer.py --browser php82
```

当前测试覆盖依赖加载、挑战随机性、账号／会话／代际绑定、过期、重放、文件存储并发消费、SQLite／私有MySQL凭据唯一性与修订号、16MiB异常BLOB与含NUL的SQLite TEXT及元数据限量读取、受权删除拒绝条件、SQLite双进程末设备保留和旧注册／恢复竞态。Chromium 虚拟认证器还验证了真实浏览器 API 的注册／登录、两设备受权删除后Signal API的客户端凭据同步，以及重放、旧挑战、篡改签名和错误 Origin 的服务端拒绝；实体安全密钥、宿主强审批／会话栅栏／通知及生产数据库流程尚未执行。

### 设备删除授权的近期认证时限

`SessionDeviceAuthority`在宿主会话读取及SessionRegistry验证后重新读取自身时钟，拒绝早于调用方时间的时钟及已超过近期认证期限的会话。签发删除证明和消费CSRF证明后再次检查截止时间；这些I/O跨过边界或时钟倒退时拒绝，不因调用开始时尚有效而放行。已消费的一次性证明不退还；失败签发过程中可能留下不可用于过期会话的证明，按原TTL自然失效。重新认证及重建请求仍由宿主负责。

方法签名、设备SQL格式和原近期认证时长保持；不新增设备恢复或账号启用能力。`tests/authority-time.php`使用合成的可信强会话测试权限时限，不能当成真实WebAuthn设备或浏览器验收。

Device removal authority rechecks recent-authentication expiry after host/session I/O and after CSRF issue/consume. Expired authority and observed clock rollback fail closed. Consumed one-use proofs are not refunded. This preserves public signatures and SQL schema and does not implement account recovery.

### 注册／登录凭据列表预算

`Ceremonies::beginRegistration()`最多接受32个现有凭据（可为空）；`beginAuthentication()`接受1—32个已注册凭据。两者在遍历、创建描述对象前检查数量，超过上限抛出`InvalidArgumentException`。上限与SQL仓库及设备信号一致，也适用于自行调用无状态Ceremonies的宿主；此前传入超过32项的自定义接入需调整。用户归属、挑战及签名校验保持。

### 挑战读取／写入期间到期

`ChallengeStore`在存储返回和选项解析后重新核对期限与时间单调性。读取期间到期返回null；写入期间到期抛`StorageException`（`webauthn.expired`），不返回已过期句柄。负值、加法溢出范围、单次操作内时钟倒退或时钟异常均以`webauthn.clock`拒绝，原始时钟异常不向外传播。已消费挑战不因迟到或错误退回，调用方必须重新发起挑战。格式v1及绑定规则保持，不需要迁移既有挑战记录。

### 设备删除权限与异常边界

`DeviceAuthority::allow()`现在有三个阶段：`before`验证当前权限并消费一次性请求证明；`current`在读取目标凭据后、SQL删除前再次检查当前身份、近期认证与权限；`return`在删除后复核。`current`不得重复消费证明或重复扣减请求预算，未知阶段应默认拒绝。内置`SessionDeviceAuthority`已接通新阶段，保持同一会话／目标／证明绑定；自定义授权器如果只认可旧两个阶段，需要显式实现`current`，否则会安全拒绝删除。

读取期间失权返回false，设备保持；删除之后才失权或通知失败仍抛“outcome requires reconciliation”，实际删除不回滚、不自动重试，也不伪造通知成功。宿主授权、通知及Clock异常不再通过原始异常链泄露；若依赖原始异常类型或getPrevious()诊断，需要在受控宿主回调内部记录脱敏结果。

## 删除授权的宿主会话绑定与错误边界

before／current／return现在同时比较实际宿主会话binding的摘要、注册会话ID、账号、设备和请求证明。即使注册表token不变，宿主binding在阶段间改变也会拒绝，并清除已接受的阶段状态；不能恢复旧binding后继续完成。宿主应在一次设备删除请求内提供稳定、来自服务端的会话绑定。

SessionDeviceAuthority直接调用入口的宿主会话／身份查询故障为webauthn.authority_unavailable，自身时钟故障为webauthn.clock，请求证明依赖故障为webauthn.request_unavailable；均不附带原始异常文本或previous。CSRF时钟拒绝仍为StorageException及csrf.clock。没有退还一次性证明、撤销已提交删除或自动重试；公开方法签名保持。当前四个支持版本的独立归档消费者及证据见[本批记录](../../docs/webauthn-authority-binding-2026-10-23.md)。
