# 有界安全审计接收器

`AuditLogger`只输出固定结构、白名单上下文和主体HMAC假名；`BudgetedSink`在调用宿主日志接收器前，用共享原子存储为固定站点预留事件额度。两者均需显式构造，不会自动注册全站事件、创建日志文件或发送告警。

```php
$writer = static function (array $record) use ($hostLogger): void {
    // 宿主负责持久化、权限、保留期和查询；失败必须抛出。
    $hostLogger->info('security.audit', $record);
};
$bounded = new SoSecurity\Audit\BudgetedSink(
    $sharedAtomicStore, 'site-id', 1000, 60, $writer, $clock
);
$audit = new SoSecurity\Audit\AuditLogger($bounded, $independentAuditPseudonymKey);
$audit->record('login.failed', 'login', $serverAccountId, ['allowed' => false, 'status' => 401]);
```

`$sharedAtomicStore`必须是适用于所有PHP工作进程的持久原子后端；构造器拒绝`MemoryStore`、`SessionStore`及它们的已知命名空间包装。部署须预先准备私有FileStore／Redis／MySQL状态，并保证时钟一致、存储不被逐出；自定义后端的原子性由宿主证明。同一存储、固定站点标识和相同策略在多个实例中共享一条固定窗口计数；策略变更应使用受控新站点标识或待旧窗口排空。额度最多100000次／窗口，窗口1—86400秒，均须显式设置。

额度耗尽抛出`audit.capacity`，存储或日志接收器故障继续抛出，不静默丢弃。额度在调用日志接收器前扣除；接收器失败后不退款，结果不证明日志已经持久化。高风险业务应在动作前完成所要求的审计准备，或把审计与业务意图放入宿主同一事务；已完成业务后发生的日志故障无法回滚既成事实。最外层错误处理器应给出安全失败并通过独立通道告警，不把异常正文返回客户端。

可信运维代码可调用`$bounded->inspect()`取得`BudgetDecision`，读取`remaining()`、`allowed()`及`retryAfter()`作为当前窗口容量指标。该查询不消耗事件额度，也不返回审计正文或主体；它不是下一次写入的预留许可，并发写入可立即改变余额。查询仍通过`AtomicStore::transact()`访问共享状态，各后端可能重写等值状态，因此需要后端写权限和正常可用性；存储故障会抛出。不要把此方法直接暴露为匿名HTTP端点，也不要把余额当作日志持久化或长期事件统计。

全站共享额度可能被攻击流量耗尽并阻止需要审计的合法操作。部署应在审计入口之前设置独立的匿名／IP预算、容量监控与运维处置；不同风险通道可以使用不同固定站点标识和额度，但不能让高风险事件绕开审计。该组件限制已接受的事件总数，因此同时限制每窗口可写入的不同主体数；它自身不提供事件查询、日志保留、指标或告警。状态被删除或回滚后可能被当作新窗口，需外部恢复权威和运营监控。

## 受权近期事件查询

可选`Audit\RecentEvents`在共享`AtomicStore`保存最多64条近期事件，保留1—86400秒；查询每次先调用宿主授权回调，只有严格返回`true`才访问状态。宿主应在受保护运维入口实施当前管理员权限、近期认证及请求保护。构造时指定独立的至少32字节绑定密钥、站点、容量、保留秒数、下游持久日志接收器和授权回调；再把实例作为`AuditLogger`接收器。`recent($limit, $event, $scope)`按新到旧返回固定字段`at`、`event`、`scope_binding`、`subject`、`context`；`scope_binding`和`subject`均为HMAC摘要，原始作用域及主体不进入索引。`at`取可信服务端时钟，查询可按准确事件码和作用域筛选。

```php
$recent = new SoSecurity\Audit\RecentEvents(
    $sharedAtomicStore, 'site-id', $independentRecentBindingKey, 64, 3600,
    $writer,
    static function () use ($operator): bool { return $operator->mayReadSecurityEvents(); }
);
$audit = new SoSecurity\Audit\AuditLogger($recent, $independentAuditPseudonymKey);
$rows = $recent->recent(20, 'login.failed', 'login');
```

容量满抛`audit.recent_capacity`，拒绝调用下游接收器；损坏状态或存储故障也直接拒绝。索引先写入，再调用下游接收器；后者失败时索引记录可能已经存在，因此查询结果不能当作日志落盘回执。索引会过期、可被存储清空或回滚，也不防具有后端写权限者篡改；长期、不可篡改审计记录仍由宿主持久日志系统承担。容量满会阻断必须审计的业务，宿主应配置前置请求预算、容量监控和故障处置。改变容量、期限或绑定密钥会使未过期的旧状态策略不匹配；应等旧状态过期或换受控站点标识。

## 固定类别指标与告警判定

可选`MetricsSink`接受显式登记的最多64个事件码，把它们计入`authentication`、`authorization`、`abuse`、`availability`四个固定类别；未登记事件在调用日志接收器前拒绝。它只保存类别计数和窗口，不把主体、租户、请求字段或事件码写入指标状态。多个工作进程必须共用真实原子存储，`MemoryStore`／`SessionStore`不可用。窗口为1—86400秒，最多100000次／窗口，超限或状态损坏时拒绝继续写入。

```php
$writer = static function (array $record) use ($hostLogger): void {
    $hostLogger->info('security.audit', $record);
};
$metrics = new SoSecurity\Audit\MetricsSink(
    $sharedAtomicStore, 'site-id',
    ['login.failed' => 'authentication', 'authorization.denied' => 'authorization',
     'csrf.failed' => 'abuse', 'storage.unavailable' => 'availability'],
    ['authentication' => 20, 'availability' => 1], 1000, 60, $writer, $clock
);
$bounded = new SoSecurity\Audit\BudgetedSink($sharedAtomicStore, 'site-id', 1000, 60, $metrics, $clock);
$audit = new SoSecurity\Audit\AuditLogger($bounded, $independentAuditPseudonymKey);
$status = $metrics->inspect(); // 仅可信运维轮询；不要暴露为匿名接口。
```

`inspect()`返回固定类别计数、`total`、`alerts`、`window_start`和`expires_at`。宿主可以用站点、类别和`window_start`做持久去重后发送通知；组件不在存储事务里做网络调用，也不声称已经投递告警。计数在调用下游日志接收器前提交，表示已准入的审计尝试，不是日志落盘数；下游失败不退款，重试可能重复计数。指标存储故障会阻止日志调用；与审计预算、日志持久化及业务事务并非同一原子提交。调整事件映射／阈值／窗口／上限时，应等待原窗口排空或切换受控站点标识；同窗配置不一致会拒绝。时钟回退、状态回滚／丢失及告警投递仍须由宿主监控和恢复。

`MetricsSink`最后一个可选参数`retainedWindows`默认`0`，保持原来的单窗口行为。设为`1`—`64`后，在同一原子状态中保留最多该数量的已完成、有事件窗口；`inspectRetained()`按时间顺序返回仍在保留期内的窗口及当前窗口，`AlertOutboxPublisher::publish()`在宿主SQL事务中逐一入队。每个窗口在结束后最多保留`retainedWindows × windowSeconds`秒；保留期外、存储清空／回滚或轮询未运行时不能补采。Outbox的`message_age`、队列容量和轮询间隔须覆盖最旧可能补采消息及每次最多`4 × (retainedWindows + 1)`条告警，否则入队失败并由宿主回滚事务。启用或修改保留数量会改变状态策略；现有站点须等待旧状态过期或切换受控站点标识，不允许混读旧格式。若指标使用`MySqlStore`且Outbox也用MySQL，应为指标提供独立PDO连接；`MySqlStore`不会加入宿主已经开启的Outbox事务。这个模式增加状态写入及存储保留期，仍不是长期审计查询或持久通知证明。

### 受权运维诊断

`Audit\Diagnostics`把指标窗口与审计额度合成固定字段的只读快照。宿主传入每次调用都重新判断的授权回调；**只有严格返回`true`**才读取共享后端，返回其他值或抛异常统一拒绝。应在管理员路由之外另加服务器端近期认证、请求保护和权限检查；不可把授权回调固定写成`true`并暴露给普通用户。两种接收器应绑定相同站点和窗口配置，否则两组数值不能一起解释。

```php
$diagnostics = new SoSecurity\Audit\Diagnostics(
    $metrics, $bounded,
    static function () use ($operator): bool { return $operator->mayReadSecurityDiagnostics(); }
);
$snapshot = $diagnostics->inspect(); // 仅在宿主受保护运维入口内调用。
```

返回值只含固定类别计数、阈值类别、当前窗口及`budget.allowed`／`remaining`／`retry_after`；不含主体、事件正文或日志内容。后端故障直接抛出，不把空值当健康状态；该快照不证明日志持久化、告警投递或下一次请求一定有额度。组件不创建HTTP端点，也不实现宿主身份认证。

本地验证可运行`python3 tests/audit_metrics_redis.py php72`或`python3 tests/mysql_check.py --audit-metrics php72`；两个控制器只建立临时私有Unix socket实例。专项使用八个真实进程核对80次计数、阈值和容量拒绝，并由服务端生成12MiB异常状态，确认8MiB PHP进程安全拒绝且不调用下游日志接收器。完整门禁中的同类检查只在对应扩展和私有实例可用时执行。

### 已观察告警的持久入队

可选`AlertOutboxPublisher`把`MetricsSink::inspect()`当前窗口已经达到阈值的固定类别写入现有`SqlOutbox`。宿主先按Outbox指南安装表，并为`security-audit`生产者初始化固定作用域；可信轮询进程在**自己拥有的SQL事务**中调用`publish()`，成功后提交，失败时回滚。每个站点绑定、类别和窗口使用固定消息ID及不变正文，多个进程或同窗多次轮询只对应一条消息。正文只含版本、站点绑定摘要、类别和窗口时间，不含主体、租户、原始事件或日志内容。

```php
$publisher = new SoSecurity\Audit\AlertOutboxPublisher(
    $metrics, $sqlOutbox, 'security-operations', 'audit-poller'
);
$pdo->beginTransaction();
try {
    $statuses = $publisher->publish();
    $pdo->commit();
} catch (\Throwable $error) {
    $pdo->rollBack();
    throw $error;
}
```

宿主工作进程用现有Outbox租约领取`security-alert`／`audit.threshold`消息，把`Status::deliveryId()`作为通知目标的幂等键；只有通知目标确认后才`acknowledge()`，故障走原有`fail()`和人工恢复流程。组件不在指标或SQL事务里联网，也不把入队称为已经通知。发送成功但回执提交失败时仍可能重送，通知目标必须按固定键去重。默认单窗口模式仍须在窗口结束前轮询；显式保留模式可在限定期限内补采，Outbox的`message_age`须至少覆盖`(retainedWindows + 1) × windowSeconds`及调度误差。无人轮询直至保留期结束的窗口不会凭空生成消息，队列故障也会使本次入队失败。宿主应监控轮询滞后、队列积压及未确认通知；长期指标和真实告警投递仍属待完成能力。

可选`AlertOutboxWorker`封装单条领取、固定协议校验、投递回调及租约结算。宿主传入的回调接收稳定的`deliveryId`和只含固定类别／窗口的告警数组；仅在通知目标**持久接受**时返回`true`。返回`false`或抛异常会按可重试失败结算，协议不匹配会死信；确认结果未知时抛错，由宿主按同一幂等键恢复。回调须设置短于Outbox租约的超时，通知目标须按`deliveryId`幂等；单次`runOne()`返回`false`只表示当前分页没有可领取消息，不代表全队列清空。该组件不提供通知目标或跨窗口补采。

本地定向检查：PHP7.2—8.5九版在SQLite各验证31项，PHP7.2／8.5另在控制器自建、禁TCP的MySQL上各验证31项；覆盖同窗去重、回执后重入、跨窗新消息、事务回滚／恢复以及正文脱敏，不等于真实通知通道验收。

接收器仅接受`AuditLogger`产生的固定记录形状，不接受直接传入的任意业务正文、头、令牌或异常文本。单条主体最多1024字节，含NUL仍按完整字节假名化；日志接收器本身也应保留结构化字段，不把记录拼成可注入的自由格式文本。

## 可选 PSR-3 宿主日志接入

使用[PSR-3](https://www.php-fig.org/psr/psr-3/)日志接口的项目，可以独立安装`integrations/psr3`中的`sohophp/sosecurity-psr3`适配包；核心包不要求安装`psr/log`。本地开发可用Composer path repository指向仓库根目录和`integrations/psr3`。下例把结构化记录作为PSR-3上下文交给宿主：

```php
$writer = new SoSecurity\Psr3\AuditSink($hostPsrLogger, \Psr\Log\LogLevel::WARNING);
$bounded = new SoSecurity\Audit\BudgetedSink(
    $sharedAtomicStore, 'site-id', 1000, 60, $writer, $clock
);
$audit = new SoSecurity\Audit\AuditLogger($bounded, $independentAuditPseudonymKey);
```

适配器固定消息为`security.audit`，不拼接事件内容；可选择PSR-3规定的八种级别，构造时拒绝其他级别。直接调用适配器时，只接受审计记录的固定字段和类型；额外字段、错误类型和控制字符在调用日志后端前拒绝。日志后端抛出的异常继续向外抛出。PSR-3接口的调用成功不证明日志已落盘，使用`NullLogger`或会静默丢弃的处理器也无法提供强制审计；宿主应选择具备所需持久性和故障报告的处理器，并配置日志访问、保留及独立告警。审计适配器不是业务事务的一部分。

本地独立Composer消费者检查：PSR-3 1.x在PHP7.2—8.5九版执行；PSR-3 2.x和3.x在PHP8.0—8.5六版执行。检查包含含NUL主体的完整字节假名化、结构字段、非法记录拒绝、日志故障传播和私有对象导出。远端CI、真实宿主日志后端及完整R4.6仍待验收。


## 可选独立 SQL 持久日志

`Audit\SqlSink` 已提供固定记录的独立 SQL 提交、容量、保留期和受权清理，接入见[中文指南](audit-sql.md)／[English](audit-sql.en.md)。可作为现有预算／指标链路的下游，但不把指标计数改成持久日志回执，不把独立日志提交与业务或告警接收原子绑定。本地 SQL＋告警投递和接收方持久去重的组合范围见[验收记录](sql-audit-integration-2026-10-22.md)；外部接收器、不可篡改长期档案及真实宿主 HTTP 权限仍需各自验收。

## 查询期间权限变化

`Diagnostics::inspect()` 和 `RecentEvents::recent()` 在访问状态之前及返回数据之前各调用一次宿主授权回调，均要求严格返回true；抛异常或非true均拒绝。宿主回调必须可重复执行，重新判断当前权限，避免消费一次性授权或产生业务副作用。开始即拒绝时不访问存储；读取期间失权时不返回已读内容。读取可能更新内部过期清理状态，这些动作不承诺因后置拒绝而回滚；两次回调也不提供与外部权限数据库的跨系统原子事务。


## 显式保存闭合窗口

可选 `WindowArchive` 为启用后的闭合指标窗口保存有界检查点，支持在 Metrics 保留期结束后按原身份补入队。它不从 SQL 日志行数重建指标，也不处理投递或未知回执。指标仍须配置 `retainedWindows > 0`，调度器必须在源窗口消失前成功保存：

```php
$archive = new SoSecurity\Audit\WindowArchive(
    $metrics, $sharedArchiveStore,
    static function (string $action) use ($currentOperator): bool {
        return $currentOperator->allowed($action === 'write'
            ? 'audit.checkpoint.write' : 'audit.checkpoint.read');
    },
    64, 3600, $clock
);
$confirmedStarts = $archive->checkpointClosedWindows();
```

`$clock` 须与 Metrics 的时钟一致；共享 `SystemClock` 也可分别实例化。档案存储必须是持久共享的 AtomicStore，不能用 MemoryStore 或 SessionStore。使用 MySqlStore 时，须显式安装原状态表，并使用不参加 Outbox 宿主事务的独立 PDO；本功能没有新增 DDL。读写权限需在每次调用时判断当前状态，不能闭包捕获一次性的批准布尔值。

保存只包括原四类计数、阈值判断及窗口边界，不含主体或事件正文。最多64个窗口、单根32768字节；有效容量满时拒绝，过期窗口才可清理。检查点按原窗口结束时间加保留秒数到期，重复保存不延期。操作后撤权或超时可能发生在检查点已经提交之后，此时抛错但不自动撤销或重放。

指定准确的历史窗口起点，在宿主拥有的 SQL 事务中调用：

```php
$pdo->beginTransaction();
try {
    $statuses = $publisher->publishArchived($archive, $windowStart);
    $pdo->commit();
} catch (Throwable $error) {
    if ($pdo->inTransaction()) { $pdo->rollBack(); }
    throw $error;
}
```

Publisher 必须持有与 Archive 相同的 Metrics 实例。读取权限和存储内容在入队前、返回前复核；所有失败都要求宿主回滚 Outbox 事务。原消息 ID、正文、创建时间和 `message_age` 保持，重复入队沿用原状态，不会重新投递。Outbox 的期限及容量必须已覆盖希望恢复的窗口；不能用当前时间替换原消息时间。每次至多补入四条固定类别告警，默认共享调用预算1000ms；存储锁和 SQL 依赖仍须设置自身硬超时。

`window($windowStart)` 可在当前读取授权下检查一份记录。缺失、过期或从未保存的目标明确拒绝，空结果不代表旧历史已处理。存储清空／回滚、未及时保存、外部长期档案和真实通知接收仍需独立处理。实现与验证状态见[本批记录](audit-window-archive-2026-10-23.md)。
