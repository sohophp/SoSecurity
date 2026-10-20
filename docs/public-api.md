# 1.0 公开 API 候选清单

R2.7新增公开候选`Account\FactorNotices`：在宿主可信MFA事件回调和当前账号PDO事务内，通过`publish()`写加密通知及`account.notice` Outbox引用；`notificationForDispatch()`要求独立当前读取权限并复核账号地址，`dispatcher()`沿用租约与发送预算，`maintain()`有界清理到期通知，`rotate()`有界重加密并重封存通知账本。当前公开候选为232类／接口，PHP7.2／8.5反射契约一致；真实宿主、完整MFA事件矩阵和正式发行尚未验收，见[通知指南](account-notifications.md)。

R4.6新增可选`Audit\RecentEvents`近期索引：构造时绑定共享原子存储、站点、独立密钥、1—64条容量、1—86400秒保留期、下游接收器与逐次宿主授权；作为`AuditLogger`接收器写入，`recent()`在严格授权后按事件／作用域过滤，最多返回配置容量内的新到旧固定结构。容量、损坏状态或后端故障明确拒绝；它不证明下游日志已落盘，也不是长期或不可篡改审计日志。当前公开候选为231类／接口，九版签名检查通过，见[近期事件查询](audit-budget.md#受权近期事件查询)。

R4.6新增公开候选`Audit\MetricsSink`，通过显式事件码映射只按四个固定类别统计已准入审计尝试，`inspect()`返回窗口、计数及告警判定类别；未知事件、非共享存储、容量耗尽和损坏状态拒绝。`siteBinding()`返回用于告警消息身份的非秘密站点绑定摘要。`Audit\AlertOutboxPublisher`把当前已观察到的阈值类别按固定ID写入宿主SQL Outbox；`producer()`返回固定生产者名，`publish()`必须在宿主SQL事务中调用。`Audit\AlertOutboxWorker::runOne()`领取并验证单条消息，调用宿主提供的持久通知回调后确认或失败结算。错过轮询窗口不会自动补采；宿主仍须提供通知目标和幂等处理。当前候选为229类／接口，九版反射契约及工作者SQLite专项、PHP7.2／8.5私有MySQL专项通过；API尚未冻结，见[审计接入](audit-budget.md#已观察告警的持久入队)。

`Audit\Diagnostics::inspect()`是宿主受保护运维入口的固定字段诊断快照，每次先执行宿主授权回调，严格返回`true`才读取`MetricsSink`与`BudgetedSink`。它不提供HTTP身份认证或长期审计查询；详见[受权运维诊断](audit-budget.md#受权运维诊断)。

`Audit\MetricsSink`的可选`retainedWindows`参数允许保留最多64个已完成窗口；`inspectRetained()`返回有界窗口列表，`AlertOutboxPublisher::publish()`对列表中达到阈值的窗口使用原固定ID入队。默认值`0`保留原行为；旧状态格式与新策略不可在未过期时混用。保留期、Outbox消息年龄及宿主轮询约束见[审计指南](audit-budget.md#固定类别指标与告警判定)。

R6.3新增`Auth\DeviceRiskDecision`与`DeviceRiskPolicy`两个公开候选类型；`RememberedLogin`构造末尾追加可选`riskGuard`参数，`RememberResult`追加`reason()`及`step_up`／`blocked`结果，`Config.remember`追加可选`risk_guard`服务名。旧参数与未配置时的恢复行为保持；该阶段公开候选为226类／接口，九版反射契约和专项通过，API尚未冻结。接入与误判处理见[记住登录指南](remembered-login.md#可选可信设备风险决策)。

`Link\IssuedLink`、`Webhook\Request`、`Idempotency\Request`及`Idempotency\Response`追加拒绝旧对象反序列化的`__wakeup()`；原公开getter签名和返回字节保持，导出对象不展开凭据URL、签名头或业务正文。

R1.2本轮对`Api\SigningKey`及`Captcha\Turnstile`／`Recaptcha`／`HCaptcha`补齐私有密钥对象导出边界，并将同一保护扩展到`Api\Credential`／`IssuedCredential`、两种Auth凭据、租约、操作Confirmation／Grant、Webhook ProcessingClaim和下载SessionAccess。原构造、`secret()`／`token()`／`verify()`签名与协议保持；增加调试脱敏（验证码）及拒绝序列化／旧对象反序列化的魔术方法。正常对象在`print_r`、`var_dump`、`var_export`及JSON导出中不暴露合成密钥或完整Bearer令牌；服务对象须从可信配置或当前授权状态重建。13个类型的反射变更已写入224类候选清单；当前修复后的完整九版门禁仍待重跑，见[迁移指南](migration.md#签名与验证码密钥对象导出)。

`Upload\ArchiveInspector`为新增的独立可选公开类型：构造函数接受仅能降低默认上限的整型数组，`inspect(string $path): array`只读取宿主私有暂存的本地普通ZIP文件，返回来源SHA-256、逐条路径／目录标记／展开字节数和展开总字节数。它不返回正文、不写目标文件、无工厂副作用，也不授予后续提取权限。缺少`ext-zip`抛`DependencyException`（`dependency.archive`），错误上限抛`ConfigurationException`（`configuration.archive`），不安全、损坏或超限输入抛`ValidationException`（`upload.archive`）；输入最大值、路径规则和宿主职责见[ZIP指南](archive-inspection.md)。该ZIP阶段公开候选共224类／接口，签名候选未冻结；实际PHP7.2／8.5反射检查通过，默认值与错误分类已对照源码及定向拒绝测试。

`Audit\BudgetedSink::inspect()`追加无事件扣费的共享容量查询，返回既有`BudgetDecision`；它不是下一事件的预留许可，也不证明日志已持久化。原构造和调用签名不变。

隔离接入追加`Security::quarantine()`和`Config::uploadQuarantine()`，既有公开成员签名保持；`upload_quarantine`与原同步上传配置独立，要求扫描器及共享持久状态，见[指南](upload-quarantine.md#工厂配置与诊断)。

上传隔离新增`Upload\Quarantine`／`QuarantineStatus`两个公开类型，`QuarantineFiles`／`QuarantineState`为内部实现；原同步上传成员保持。直接构造、永久有界账本、当前版本扫描和私有快照读取见[隔离指南](upload-quarantine.md)，不把描述状态当作访问权限，完整R4.4验收继续。

上传新增`Upload\ClamAvScanner`，实现既有`Scanner`接口；原Scanner／Saver／StoredFile成员保持。仅接受显式本地Unix socket，内容、期限和完整响应边界见[扫描指南](upload-scanning.md)。

只读快照新增Account下StateSnapshot／StateStoreSource、SqlStateSnapshot／SqlStateCapture、FileStateSnapshot／FileStateCapture、CompositeStateSnapshot／CompositeStateCapture八个公开类型；StateStorageDomain为内部实现。FileStore追加三个纯元数据方法，原有成员签名保持。数据摘要不授予权限或防回滚保证，见[快照指南](state-snapshots.md)。

授权下载追加Download下Policy／File／Request／RangeException／Access／Grant／SessionAccess／LinkAccess／Transfer／Downloads及显式工厂downloads()；LocalReader／Snapshot／Selection／Time为内部实现。可信文件索引、派生内容版本、当前授权及私有匿名快照契约见[下载指南](downloads.md)，R3.6本地九版完整门禁已验收；不暴露可供绕过授权的源路径或流描述符。

签名链接追加Link下Policy／Target／IssuedLink／VerifiedLink／Links及工厂／配置signedLinks()；Encoding／State为内部格式。R3.5本地九版本完整检查、共享并发、原生HTTP／浏览器及消费者验收通过；仍为未发布候选，固定来源／规范URL／资源版本、共享撤销与消费契约见[签名链接](signed-links.md)。
操作授权追加Operation下Policy／Intent／Confirmation／Grant／Permit／Grants，Shape／State为内部格式；工厂追加operations()。R3.4九版本本地完整检查、共享并发、原生HTTP／浏览器及消费者验收通过，公开API仍为未发布候选，数据绑定／阶段／业务事务契约见[操作授权](operations.md)。

PasswordRecord追加identity()返回密码身份提供器使用的有效账号版本；account()继续返回原始账号。SQL宿主同时持有原始业务版本和密码记录时，须按[操作授权](operations.md)的版本映射约束写入，不能直接将有效版本比较原始version列。既有身份计算与撤权行为保持不变。

`PasswordRecord`与`LoginResult`追加拒绝旧对象反序列化的`__wakeup()`，公开getter签名和返回值保持。对象导出不再包含密码哈希或MFA挑战值；见[迁移说明](migration.md#认证结果与密码记录的对象导出修复)。

并发租约追加Concurrency下LeasePolicy／Lease／LeaseStatus／LeaseManager及工厂leases()、配置leasePolicy()，LeaseState为内部格式。显式初始化、永久序号、持有者绑定、总期限及SQL隔离边界见[租约指南](leases.md)。不自动创建业务账本或接管任务。

`resources/api/classes.json` 列出拟稳定的223个类/接口，包含可选的`Audit\BudgetedSink`；`internal.json` 显式列出内部类。每个源码类必须归入其中一类，否则检查失败。`candidate.json` 保存构造/公开方法、参数名称/类型/默认值、返回类型、继承/接口关系、公开常量及属性默认值。名称、参数顺序与PHP8命名参数均是兼容性的一部分。现在是提案基线，尚未经过独立复核并冻结，不等同于已发布1.0。

请求预算追加BudgetPolicy、BudgetLimiter、BudgetDecision、BudgetGroup、BudgetResult、CompositeLimiter及工厂／配置方法；BudgetState／BudgetBindings仅为内部状态实现。既有RateLimiter不变。整体allowed、charged、reservedUntil、只读余额及组合范围见[请求预算指南](request-budgets.md)，检查结果不是可复用操作授权。

授权追加 `Authorizer`／`PolicyProvider`／`CallbackPolicy`／`PolicySet`／`RolePolicy`／`Resource`／`Decision`；`Shape`为内部预算和格式检查。工厂及配置新增显式 `authorization`，默认无策略就拒绝。原有认证与授权职责仍分开，字段／批量及SQL一致性边界见[授权指南](authorization.md)。

密码精修追加 `PasswordBlocklist`／`PwnedPasswords`、`PasswordPolicy` 末尾可选服务参数与 `forHasher()`、`PasswordHasher::maximumBytes()`；原有构造参数前缀保留。`HashBudget` 为内部预检。原生验证资源限制、工厂基础拒绝表、Argon2id默认最大字节数及成本不降级的行为变化见 [密码指南](passwords.md)。

持久登录追加 `RememberedLogin`、`RememberCredential`、`RememberResult`；`RegistryState`／`RememberCodec` 属内部格式。`VerifiedSession` 追加可选来源参数与 `resumed()`，`recent()` 对恢复会话拒绝；`SessionRegistry::policy()` 为只读限制快照。工厂追加显式持久授权／Cookie头接口。v1→v2账本升级及回滚条件见 [持久登录指南](remembered-login.md)。

```sh
php72 bin/api-contract.php
php85 bin/api-contract.php
# 只有有意修订并审核接口时更新；不能通过自动重写基线掩盖变化。
php72 bin/api-contract.php --write
```

检查只使用Reflection，不调用模块构造器，不启动Session/发头/连接存储或初始化可选清理库。PHP8.5会把self解析为类名，旧运行时返回self拼写，工具按声明类规范化语义后比较，避免将反射差异错报成产品接口变化。源码路径分隔符统一后比较，Linux及原生Windows复用同一候选清单。继承关系记录父类及本库接口；PHP引擎自动追加的Stringable等内置接口不作为本库签名变化。遇到未支持的类型结构会失败，不能默默放宽PHP7.2要求。

`Captcha\InteractiveRenderer/SiteVerify`、`Api\SignatureProfile`、`Http\Outbound\PublicAddress/RequestHeaders`、`Storage\Codec`、`Support\Guard/Deadline` 为内部实现辅助，不在稳定合同中；其他类即使公开仍须遵守其文档用途，例如MemoryStore仅用于测试。所有安全默认值/副作用/错误分类也属于行为承诺，需要功能与负面路径检查，签名相等不能证明行为安全。

可选适配器和示例不要求框架；examples为可调用接入示例，宿主认证/权限/请求解析仍由真实应用承担。ABI清单和生成器用于源码开发审核，核心压缩包排除该开发清单，保留MySQL运行时schema。正式冻结须有全目标版本实际运行/Composer证据、独立迁移示例、独立复核和发布审核。

验证码扩展有意增加两个提供器类，增加Captcha方法及可选operation参数、Challenge可选presentation参数/属性、ImageRenderer的renderQuestion；原有调用参数和默认加法/混合字符保留。字符集允许0/1。提供器传输共用内部SiteVerify，服务故障仍拒绝。

账号级凭据追加Api下CredentialPolicy／CredentialInfo／IssuedCredential／VerifiedCredential／CredentialRegistry及工厂apiCredentials()、配置apiCredentials()；CredentialEncoding／CredentialState为内部格式。默认自助管理，可显式注入委派授权及真实操作者解析。范围／代际／期限／策略与操作者引用均绑定签名，完整边界见[账号凭据指南](api-credentials.md)。旧ApiKeys与HTTP签名接口保持兼容；新增五类已完成R4.1本地九版完整验收，公开API仍为未发布候选。

Webhook验签追加Endpoint／Request／KeySet／Verifier／VerifiedWebhook五个公开类，Wire为内部协议解析。`KeySet`追加拒绝旧对象反序列化的`__wakeup()`；现有构造、`fromEncoded()`、`matches()`及`verify()`签名保持。端点固定协议／来源／提供器账号及预算，证明只包含已验签原始字节和真实签名覆盖的元数据；当前核心不承担持久接收、去重确认或业务副作用，R4.2仍在实施，见[Webhook指南](webhooks.md)。

Webhook持久接收追加Message／Receipt／SqlInbox三个公开类及Security.webhook(name)／webhookInbox(name)、Config.webhooks()，InboxState／InboxSchema为内部封存与结构验证。接收命名空间显式包含站点／租户／端点／提供器账号／协议；独立HMAC封存来源与正文摘要，实际SQL提交后才返回接收结果，重复投递不覆盖冲突内容。业务执行与本阶段完整验收继续，见[接收指南](webhooks.md)。

R4.3追加Webhook下ProcessingPolicy／ProcessingStatus／ProcessingClaim／SqlProcessor四个公开类，ProcessingState／ProcessingSchema为内部格式。追加Security.webhookProcessor(name)、ProcessingPolicy.options()及processing配置；工厂不依赖提供器在线密钥，只读诊断不执行SQL或回调。原生CLI和强认证管理接入已有本地验证，通用幂等／出站消息契约及完整验收继续；构造、事务回调与旧凭据边界见[处理指南](webhook-processing.md)。R4.2已完成152类基线的本地九版完整验收，不能将此前证据覆盖新增处理类。

R1.2审计对象追加AuditLogger.__debugInfo()与__sleep()，只控制受支持的调试输出和序列化行为，现有构造／record签名与事件格式保持。服务对象不再支持序列化保存，从可信配置重建，见[迁移指南](migration.md)；其他任意反射和进程内存访问不构成由这些接口提供的安全边界。

R4.3通用SQL幂等追加Idempotency下Policy／Request／Response／Outcome／SqlExecutor五个公开类，State／Schema和共享SqlTransaction／SqlSchema为内部实现。156个既有类的原有成员签名保持，仅追加Config.idempotency()与Security.idempotency()；新增接口尚未冻结。原生接入后最新九版SQLite409／MySQL356、HTTP／TLS各433、161类API与新消费者专项通过；回调元数据额外提供已认证存储fingerprint，冲突请求仍先复核原执行权限。出站消息及完整R4.3验收继续，边界见[SQL幂等指南](idempotency.md)。

R4.3出站消息增加Outbox下Policy／Message／Status／Claim／SqlOutbox五个公开候选，State／Schema为内部格式；随后追加Config.outbox()与Security.outbox()，原166类其他既有成员签名保持。原生CLI／HTTPS示例复用既有接口；后续超期对账再向SqlOutbox追加reconcile、向Status追加resolution，逐项比较其他既有成员签名保持。处置后新增resolved状态并把已封存格式推进为2，旧进程须先停止，不能仅以PHP签名兼容推断可回滚旧代码。事务／证据及阶段验证边界见[核心](outbox.md)、[原生接入](outbox-native.md)和[超期对账](outbox-reconciliation.md)，完整阶段继续。

## 账号通知基础候选

新增 `Account\Address`、`Account\Policy`、`Account\Notice` 与 `Account\Notifications` 四个公开类，当前清单共170类／接口；原166类所有公开成员签名保持。地址与通知对象不自动导出秘密，私有加密内容由明确的 `encode()`／`seal()`／`open()` 接口处理。`reencrypt()` 保持通知上下文和期限，`metadata()` 只提供维护所需时间与密钥编号，见[使用说明](account-notifications.md)。注册／变更核心随后纳入工作树，见下一节；完整恢复及工厂仍待完成，不因这四类可调用而计为完成R2.7；API尚未冻结。

## 注册与双地址核心候选

新增 AccountRecord／Repository／IdentityRepository、Delivery／ChangeDelivery 和 Registration／AddressChange 七个公开类／接口，内部Ledger另行分类，当前公开候选177类。核心与两后端显式DDL已写入工作树，九版检查确认原170类全部公开成员签名保持，当前MySQL组合仍在执行。初始化／管理与公开操作／通知读取权限独立，服务不建表、不自动登录、不清除MFA或发送邮件，见[接入说明](account-lifecycle.md)。强恢复、正式工厂／诊断与完整原生流程继续实施，API尚未冻结。

## 正式账号预算及工厂

新增 `Account\RequestBudgets`，当前178类／接口；原177类全部已有公开成员签名保持，另向 `Notifications` 追加 `validateConfiguration()`、向 `Config` 追加 `accounts()`、向 `Security` 追加 `registration()`／`addressChange()`。预算回调内部协议新增第七个操作编号参数，六参数PHP用户回调兼容；工厂要求正式共享预算、明确权限和一致时钟。请求预算不提供SMTP发送额度，完整恢复／原生流程仍待交付，见[账号指南](account-lifecycle.md)。

## 密码恢复核心

新增 `Account\Recovery`／`RecoveryDelivery` 及 `Security::recovery()`，公开候选180类；原178类全部已有公开成员签名保持。恢复挑战绑定有效密码身份和当前因子代际，成功仅替换密码并推进版本；不清除MFA、不自动登录，也不自动完成旧邮箱丢失后的迁移。独立权限、强审批、外部消费与提交后未知边界见[密码恢复指南](account-recovery.md)，完整R2.7仍待完成。


### 通知投递核心

新增 `Account\DispatchNotice`、`SendBudgets`、`MailMessage`、`MailTemplates`、`MailTransport`、`MailResult`、`SmtpTransport` 和 `Dispatcher`，公开候选共188类／接口。原180类所有既有公开成员签名保持；向三个生命周期服务追加 `notificationForDispatch()`／`dispatcher()`，向 `SqlOutbox` 追加 `currentClaim()`，向 `Claim`／`Message` 追加拒绝反序列化的 `__wakeup()`。九版候选签名一致，API仍未独立复核或冻结。

`Claim` 与 `Message` 的显式访问方法保持；普通导出不再展开领取秘密和正文。发送结果仅表示本次提交观察，服务器接受不等于收件箱送达；自定义 `MailTransport` 属于可信宿主代码，必须遵守每次至多提交一次及上传前调用当前权限门的契约。接入及升级边界见[通知说明](account-notifications.md)。


### 邮箱丢失恢复核心

新增 `Account\MailboxRecovery`、`MailboxRecoveryDelivery` 和 `RecoveryApproval`，公开候选191类；原188类已有成员签名保持，另追加 `Security::mailboxRecovery()` 与 `MailTemplates::supportsAction()`。新流程要求独立强审批和新邮箱证明，保留密码／MFA，不自动登录。审批预览数据不是审批能力；新类型及受限模板的升级边界见[邮箱恢复指南](account-mailbox-recovery.md)。API仍未独立复核或冻结。


## 受管理 MFA 的 SDK 接入（2026-10-18）

2026-10-20 补充公开候选 `Security::managedSecondFactor(): Auth\SecondFactor`，并为现有 `authentication` 配置增加默认关闭的 `managed_factors` 布尔选项。显式启用后 `authentication()` 和 `sessions()` 都从 `account_factors` 建立受管理适配；缺配置／依赖或与 `second_factor`、顶层原始`mfa`并用时拒绝。当前231类／接口的PHP7.2与8.5反射契约通过，两版本地真实密码／TOTP专项各129项、全新Composer消费者各五组及当前454文件归档通过；PHP7.2使用私有sodium启动器，正式候选复核未完成。

新增17个公开候选类型及两个内部实现，当前249源码／208公开候选。原191类已有公开成员签名保持，PHP7.2与8.5的反射契约一致；追加 `Security::accountFactors()`、`Config::accountFactors()` 及 `TotpFactors` 的显式受管理接口。`Mfa\ManagedFactorStore` 和 `Mfa\FactorAuthority` 仅为内部实现，不能替代宿主权限或持久化契约。

[接入指南](account-factors.md)说明注册权威、目录、操作意图和维护入口。公开候选未冻结，新增类型已通过两版新消费者检查，仍需完整规划的API复核、原生流程及发行验收；局部测试不能代替这些门禁。


## 普通未决操作的独立处置

新增 `Account\FactorOperationResolution`，公开候选209类，源码250文件。原208类已有公开成员保持，新增 `FactorRegistry::operationResolution()`、`FactorOperations::resolution()`、`TotpFactors::registeredWith()` 与 `FactorWorkerAuthority::matchesConnection()`；后两个是无SQL／无回调的准确能力核对，不是授权证明。新增服务采用不同签名域和独立审批用途，保持现有构造签名。[接入指南](account-factors.md)说明关闭权威、账号凭据推进、格式2保留期及未知结果；API仍未冻结或独立审查。


## 活跃账号因子特权撤销候选增量

新增 `Account\FactorRevocation` 与 `FactorRegistry::privilegedRevocation()`；当前251源码／210公开候选，原209类已有公开成员保持，PHP7.2／8.5候选反射结果相同。服务提供签名review／reviewClosed、execute／executeClosed及inspectClosed，效果固定为保留MFA要求并阻断登录；普通禁用与独立恢复是不同用途。格式6目录由旧读取代码安全拒绝，`FactorInspection::retired()` 也涵盖活跃账号的privileged revoked状态；没有DDL变更。独立恢复、正式通知、原生入口及完整门禁仍待完成，详见[接入指南](account-factors.md)。
