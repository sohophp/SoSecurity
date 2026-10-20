# 邮箱与加密通知基础

SDK 提供 `Account\Address`、`Policy`、`Notice` 和 `Notifications`，用于构造受限邮箱值和用途绑定的加密通知。注册与双地址变更核心另见[接入说明](account-lifecycle.md)，当前邮箱可用的密码恢复见[恢复说明](account-recovery.md)；投递核心见下文，[邮箱丢失恢复核心](account-mailbox-recovery.md)及[受管理因子](account-factors.md)另有接入说明，原生入口见[认证示例](managed-authentication-native.md)。这些值对象不验证邮件所有权、不创建会话，也不连接 SMTP。

`Address` 保留邮箱本地部分的大小写、点号和加号，仅规范化域名；不要自行采用特定邮件提供器的合并规则。国际化域名依赖 Intl，缺失时明确拒绝；Unicode 本地部分必须显式启用 SMTPUTF8，并由投递端另行验证实际支持。地址最多254字节，拒绝 NUL、换行、显示名和不支持的语法。

```php
use SoSecurity\Account\Address;
use SoSecurity\Account\Notice;
use SoSecurity\Account\Notifications;
use SoSecurity\Account\Policy;

// 由私有配置注入每站点独立、用途专用的32字节密钥映射及当前键编号。
$codec = new Notifications($currentKeyId, $notificationKeys, $clock);
$policy = new Policy();
$now = $clock->now();
$notice = new Notice(
    $scope, $stableNoticeId, 'verify_registration',
    new Address($recipient), $challengeToken,
    $now, $now + $policy->lifetime('verify_registration')
);
$envelope = $codec->seal($notice);
// 将信封持久写入私有通知表；Outbox仅引用稳定通知编号。
$opened = $codec->open($envelope, $scope, $stableNoticeId, 'verify_registration');
```

通知编号与挑战秘密为各64个十六进制字符，由可信业务流程生成；重试沿用已持久化的通知编号。固定通知类型包括注册验证、旧／新地址验证、变更取消、恢复，以及激活／改密／地址变更通知；安全通知不接受挑战秘密。另有 `recover_address` 邮箱恢复挑战，以及 `address_recovery_started`／`address_recovered` 无秘密安全通知。接收地址、编号、用途、作用域及期限都在认证加密内容中验证，`open()` 拒绝过期、未来签发、上下文错误和损坏信封。

受管理 MFA 的固定事件名现可作为无挑战秘密的安全通知类型使用，覆盖管理、绑定、特权撤销、恢复和清理阶段；`Policy::lifetime()` 对这些类型使用 `notification_seconds`，`MailTemplates` 只从已列入 `Notice::supports()` 的固定类型生成邮件主题，不接收请求提供的主题或正文。`FactorNotices` 提供正式同库通知源：宿主在可信 MFA 事件回调内调用 `publish($type,$subject,$operation)`，它只加入当前业务 PDO 事务，保存加密信封及引用通知编号的 `account.notice` Outbox 消息；宿主事务回滚时两者一起回滚。公开返回的通知编号不是授权。`notificationForDispatch()` 每次检查独立当前读取权限、账号状态和当前邮箱，`dispatcher()` 继续使用原有工作端租约、`SendBudgets`、固定模板及传输端。现有只写事件名与操作编号的 MFA Outbox 事件仍不能交给 `Dispatcher` 当作邮件发送。

独立因子恢复的可信事件回调也可调用同一 `publish()`：`factor_restoration_started` 与 `factor_restoration_activated` 使用同一恢复操作编号、不同固定事件名，分别生成通知；取消事件同理。通知发布失败时，恢复服务拒绝本次操作，宿主应检查保留的恢复意图后决定是否重试；不能把未知完成结果直接当作成功或自动重放。

独立因子替换由`FactorRecovery`发出`factor_recovery_started`和`factor_replaced`。两者共用固定流程选择子作为通知操作编号，分别生成通知；`factor_replaced`现属于固定无秘密类型，可使用`notification_seconds`期限和固定邮件主题。替换通知发布失败时账号绑定与通知队列不提交，但先前持久计费的证明尝试次数不退还；宿主须重新检查当前流程和独立审批，不可按原请求盲目重放。

未完成的替换流程取消时还会发出`factor_recovery_cancelled`；保留期届满后的准确流程清理会发出`factor_recovery_purged`。取消通知拒绝时本次SQL取消决定不提交；清理通知拒绝发生在可能的物理删除之后，服务报告完成结果未知并保持关闭的工作栅栏。宿主须检查保留流程与物理状态，使用新的受权关闭态清理尝试；不能把SQL回滚解释成物理删除回滚。

旧因子迁移的账号事件还包括`factor_migration_reserved`、`factor_migration_completed`、`factor_migration_activated`、`factor_migration_cancelled`和`factor_migration_reapproved`。可信迁移回调可从原迁移操作编号与本次审批随机编号派生稳定的64位十六进制通知标识，同一审批重试沿用原标识，不同审批产生不同标识；固定事件类型仍由`FactorNotices`严格校验。迁移历史的批量`purged`／`rekeyed`及工作进程轮换是运维事件，可能没有单一当前活跃账号，不应直接经`FactorNotices`发送账号邮件。

## MFA 事件矩阵

| 账号事件来源 | 固定通知类型 | 本地接入状态 |
| --- | --- | --- |
| 普通管理与独立处置 | `factor_management_started`、`completed`、`abandoned`、`cleaned` | 活跃账号的开始／完成／放弃／清理已接入正式通知源，并通过本地同 PDO 组合验收 |
| 新因子绑定 | `factor_enrollment_started`、`prepared`、`enrolled`、`cancelled`、`cleaned` | 活跃账号的绑定成功、取消及清理已通过本地正式通知源组合验收 |
| 特权撤销 | `factor_privileged_revoked` | 已接入正式通知源 |
| 因子替换 | `factor_recovery_started`、`factor_replaced`、`factor_recovery_cancelled`、`factor_recovery_purged` | 已接入正式通知源 |
| 旧因子迁移 | `factor_migration_reserved`、`completed`、`activated`、`cancelled`、`reapproved` | 真实迁移的本地SQLite及私有禁TCP MySQL组合已通过 |
| 独立恢复 | `factor_restoration_started`、`activated`、`cancelled`、`cleaned`、`previous_cleaned` | 已接入正式通知源 |

上述六组共24个单账号固定事件。迁移／管理／恢复历史的批量`purged`和`rekeyed`事件没有单一收件账号；工作进程轮换和回执维护也属于运维权威流程。这些事件需要宿主运维审计与告警，不进入单账号`FactorNotices`白名单。新增账号事件时须同时核对服务实际发出的名称、`Notice::supports()`、固定模板和同PDO回调验收，不能只在文档中增加名称。

上述组合验收只覆盖当前活跃且已验证的账号。`FactorNotices::publish()` 对停用或未验证账号会拒绝，宿主不能把这类事件的邮件记作已投递；这类账号的安全事件仍需独立审计／告警与宿主处置策略。真实 SMTP、目标宿主回调和完整 R2.7 验收另行判定。

终态清理还有 `factor_restoration_cleaned`（取消后清理新因子）和 `factor_restoration_previous_cleaned`（激活后清理旧因子）。两者在固定事件回调中写通知；若物理因子已被清理而通知发布失败，恢复服务报告完成结果未知，SQL 决定和通知保持原状，旧工作栅栏可能已关闭。宿主须先检查保留意图和物理状态，再取得新的关闭态复核并执行 `cleanClosed()`；不能从普通开放态入口直接重试，也不能声称物理删除已回滚。

使用前显式调用 `FactorNotices::initialize()`；宿主需注入相同 PDO 的 `Repository`、站点／作用域／epoch、各自专用的完整性与通知密钥，以及管理、发布、读取、工作端四类权限。`publish()` 的事件名必须是固定 MFA 类型，操作编号为64位十六进制；同一账号、事件名和操作编号只能记录一次。只有活跃且已验证的账号可发布；当前邮箱变化后旧通知不再可投递。`maintain()` 按1—50条的页界显式清除到期加密记录，Outbox 保留和清理由原 Outbox 运维单独处理；额度满时拒绝新通知，不能依赖隐式清理。

轮换时先停止旧写进程，并同时装入旧、新通知密钥与账号账本完整性密钥。使用`rotate($limit,$after)`逐页重加密信封并重封存账本；调用方沿返回的`next`游标继续到`done=true`，但`done`只是本轮物理键页界，仍须在写入停顿期间重新核查全部在线记录、备份保留及工作端。操作保持通知编号、收件地址、签发／过期时间和Outbox消息正文不变；若处理途中就删除旧密钥，尚未轮换的记录会安全拒绝。Outbox自身的密钥和保留维护仍须按其独立契约处理，`FactorNotices::rotate()`不会改写队列。

若同次退役`account-factor-notice`队列的封存密钥，先保持旧、新Outbox密钥同时可读，完成上述通知账本轮换；再用相同站点、epoch、策略和独立管理权限构造`SqlOutbox`，对准确`account-factor-notice`生产者逐页调用`maintain($scope,'account-factor-notice',$actor,$limit,$afterKey)`直到`complete=true`。停写期间核对该队列根与全部保留记录已由新密钥封存，并用仅含新密钥的独立工作端完成读取／领取后，才移除旧密钥。只轮换通知账本就撤旧Outbox密钥会拒绝队列领取；`factor-recovery`等其他生产者仍可能保留旧封存，须分别核查，不能用本通知队列的完成标记推断整个站点可退役旧密钥。该顺序在本地SQLite／私有MySQL专项验证；完整灾备与多工作进程停旧确认仍由宿主负责。

普通因子管理可把原有同库审计回调与通知发布组合；回调必须由服务在业务事务内调用，不要从浏览器请求直接调用 `publish()`：

```php
$factorNotices->initialize();
$events = static function (string $type, string $scope, $before, $after, string $operation, array $review) use ($factorNotices): bool {
    $factorNotices->publish($type, $review['subject'], $operation);
    return true;
};
$operations = $factorRegistry->operations($fence, $authority, $budgets, $approval, $events);
$worker = $factorNotices->dispatcher($workerId, $sendBudgets, $templates, $transport, $workerAuthority);
```

宿主仍须给回调做准确事件与主体绑定，并提供独立审计；`publish()`不会代替因子服务的审批或证明，且返回编号在外层事务提交前只是暂定结果。其他因子事件的回调签名各异，应按相应服务契约接入，不能套用普通管理示例。

特权撤销的事件回调接收`($type,$review,$before,$after)`；在`FactorRegistry::privilegedRevocation()`传入的事件回调内，可用`$factorNotices->publish($type,$review['subject'],$review['operation'])`写同库安全通知。拒绝发布会阻止撤销SQL事务提交，不能在该回调中同步连接SMTP。本地双数据库专项验证了成功投递到测试传输端及拒绝时账号版本、目录、审计和队列一起回滚；恢复、迁移等其他回调仍须按各自契约接线与验收。

本地专项已在PHP7.2／8.5的私有SQLite和禁TCP MySQL验证普通管理及特权撤销事件回调的同事务发布，以及当前权限、地址变化、额度拒绝和测试传输端投递。另以本机临时CA和回环TLS SMTP服务验证真实`SmtpTransport`提交：成功接受、上传前账号停用、服务器接受后账号停用、接受后回执丢失均按原队列状态结算；只使用临时SQLite和本地测试账号。外部SMTP、目标宿主审批／权限与远端CI仍须独立验收。

`Notice::encode()` 是明确导出敏感内容的接口，只用于私有加密／持久层；不得写入日志、URL、公开 JSON 或异常。普通调试、`var_export()` 和 JSON 不自动展开地址、秘密或密钥；序列化与反序列化拒绝。此防护不阻止同进程恶意代码使用显式访问接口。

轮换时使用包含旧、新密钥的 `Notifications`，调用 `reencrypt()` 后同事务替换私有信封，保持原编号、接收地址、秘密和期限；Outbox正文及指纹不变。`metadata()` 仅返回已认证的密钥编号与时间。已过期信封可供维护认证／重加密，仍不能通过 `open()` 返回可投递通知。移除旧密钥前须停止旧写进程，并核查全部在线记录及备份保留策略。

`tests/account-foundation.php` 在私有 SQLite 验证通知与真实 Outbox 的同事务写入／回滚及信封轮换，覆盖错误用途／作用域／编号、严格格式、期限、时钟、秘密导出、地址预算和可选能力拒绝。常规门禁已接入该测试；加密需要 sodium，不能将缺失扩展时的拒绝测试算作成功加密或实际邮件投递。

## 显式投递核心

SDK已加入显式投递核心，接入后的主工作区专项已通过；完整R2.7仍未完成。工作端必须同时验证 Outbox 的领取秘密、工作端身份和当前租约，以及账号通知独立的当前读取权限；公开的领取对象或通知元数据不能代替这些检查。注册、地址变更和密码恢复分别绑定自己的生产者与用途。

请求预算与发送预算分别计费。发送预算覆盖站点、传输端、收件地址和作用域内账号，另限制每条通知的实际尝试次数；重试保留原通知编号、期限、邮件内容与 Message-ID，不退还已经消耗的额度。首次尝试后缺失预算记录必须拒绝，不能重新从零计数。共享预算仍需要宿主保证持久性及恢复时的独立权威状态，签名不能识别完整有效的旧备份。

SMTP 仅连接私有配置指定的固定地址，TLS 模式验证证书与主机名，STARTTLS 后重新读取能力；仅在实际支持时发送 SMTPUTF8。传输端直接按限额读取协议行，单行最多512字节、全部回复最多8192字节，连接、握手及读写共享发送期限；这些是应用层协议预算，不是数据库、TLS 库或操作系统总内存保证。

| 观察到的结果 | 自动处理原则 |
| --- | --- |
| 正文上传前拒绝或权限撤销 | 不上传正文；仍保留已经消耗的额度 |
| 服务器明确临时拒绝 | 在原期限和剩余额度内允许有限重试 |
| 服务器明确永久拒绝 | 停止自动重试 |
| 正文上传后连接丢失、超时或回复异常 | 记录结果未知，阻止自动重发 |
| 服务器接受后权限或队列确认失败 | 不声称发送已回滚；保留不确定状态供人工核对 |

服务器接受只证明其接受了本次提交，不能作为收件箱送达证明。发送开始、接受及未知状态需要在共享存储中保留；进程崩溃后不能因租约到期就重新发送。隔离阶段已有本地临时接收服务、显式CLI和真实进程验证，完整SDK门禁、恢复处置和原生HTTP页面仍需完成，不能据此关闭完整账号生命周期要求。

由宿主在私有配置中创建 `SendBudgets`、`MailTemplates` 和 `SmtpTransport`，再通过注册、地址变更或恢复服务的 `dispatcher()` 工厂构建工作端。工厂固定已有站点、作用域、生产者、epoch、密钥及策略；传入独立的当前工作端权限回调。工厂构造不查询数据库、不调用权限回调，也不连接SMTP。`notificationForDispatch()` 返回的私有上下文仍须经过原有独立通知权限检查，不能公开给请求调用方。

```php
$worker = $registration->dispatcher(
    $workerIdentity, $sharedSendBudgets, $fixedTemplates, $smtpTransport,
    $currentWorkerAuthority
);
$result = $worker->sendNext(); // 一次有限扫描、最多一次提交
```

`SendBudgets` 使用专用、稳定的伪名密钥和共享原子存储，四个策略键必须明确为 `site`、`transport`、`target`、`subject`。已知内存或Session存储不能用于实际工作端；自定义存储的共享性、持久性及备份恢复由宿主验证。`MailTemplates` 固定发件地址、品牌和同源HTTPS操作地址，不接收请求提供的邮件头；挑战参数放在片段中，宿主页面仍需显式POST和请求保护，不能以GET直接消费挑战。

`SmtpTransport` 的 `starttls`／`tls` 模式需要OpenSSL，固定主机名用于证书与SNI校验，固定IP用于连接；不解析请求提供的目标，不读取代理或netrc。认证仅在验证TLS后使用PLAIN；没有TLS或所需SMTPUTF8能力时拒绝，不降级明文。`unix` 模式仅供显式私有本机接收端，要求当前用户拥有实际socket和私有目录，不接受认证凭据。

原生工作端为 `examples/account-mail-worker.php`。`SOSECURITY_ACCOUNT_MAIL_BOOTSTRAP` 指向宿主可信PHP配置，返回一个已构造的 `Dispatcher`；部署时放在Web根目录之外。工具检查路径规范化、非符号链接、私有文件／父目录权限及64KiB上限；配置文件不负责建表、初始化生产者或迁移。仅显式 `--once` 启动工作，可选 `--after=<游标>`；导入示例文件和错误参数均不加载配置。退出码0表示本轮已处理或没有可提交项，2表示拒绝或未知，1表示配置／执行不可用，错误输出不展开凭据或底层异常。

新生成的通知按通知编号独立聚合，过时验证消息或新地址投递失败不再阻塞新验证、旧地址取消等独立通知。升级前停止旧写入工作端；旧意图保留编号、正文、指纹和聚合，不自动重写。旧聚合的阻塞记录仍需按当前通知状态和管理权限核对，不能将SMTP未知结果直接改成未发送，也不能凭升级恢复已经过期的挑战。
