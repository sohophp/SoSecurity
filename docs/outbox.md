# 事务发件箱核心

状态：R4.3实施中的可选核心候选，公开接口尚未冻结。已实现同事务入队、独立领取／确认、失败重试、元数据分页、有界维护、显式工厂与只读诊断；后续新增[原生生产／发送／接收方去重](outbox-native.md)示例并执行专项。超期业务对账核心及原生签名闭环已有[本地候选证据](outbox-reconciliation.md)，完整阶段验收继续，本页不代表完整Outbox交付或生产验收。

## 部署与事务

使用异常模式的64位SQLite／MySQL PDO，MySQL保持原生预处理及 `autocommit=1`。通过宿主受控迁移明确安装 [SQLite结构](../resources/sql/outbox-sqlite.sql) 或 [MySQL结构](../resources/sql/outbox-mysql.sql)，并与业务表位于同一事务数据库。SQLite使用私有真实文件、日志及FULL／EXTRA同步；MySQL要求InnoDB及提交刷盘。

直接构造 `Outbox\SqlOutbox(PDO, site, epoch, HmacKeys, authority, ?Policy, ?Clock, ?managementGuard)`。标签来自可信上下文，epoch为数据库外保存的64位十六进制部署代际，封存密钥与其他协议分离。构造、导入和普通请求不创建表、目录、账号或默认密钥，不接管Session、Cookie、路由或HTTP响应。

管理程序先 `initialize(scope, producer, actor)`；缺少根记录拒绝工作。`enqueue(Message, actor)` 只加入宿主已有显式事务，返回值仍待宿主提交。业务写入、稳定事件账本与入队使用同一PDO一起提交／回滚；入队错误须中止完整业务单元，不能吞掉错误后单独提交业务。[旧PDO及事务所有权](sql-transactions.md)的约束继续有效。

其他工作／管理操作自行拥有短事务，拒绝已有宿主事务。网络、邮件、支付等副作用只能在领取提交并返回之后执行；本组件本身不发送任何请求。

## 显式工厂与诊断

`Security::fromArray()` 可选择配置 `outbox`，必填 `connection`、`epoch`、`integrity_keys`、`authority`，可选 `management_guard` 与 `policy`。除epoch和策略外，配置保存宿主注入的服务名；连接是与业务写入同一个PDO，密钥是独立的HmacKeys，两个权限服务按下方契约返回当前授权结果。不依赖authentication或通用storage，省略outbox时不会创建默认队列。

```php
$security = SoSecurity\Security::fromArray([
    'site' => 'your-site',
    'outbox' => [
        'connection' => 'business_db',
        'epoch' => $trustedExternalEpoch,
        'integrity_keys' => 'outbox_seals',
        'authority' => 'outbox_authority',
        'management_guard' => 'outbox_management',
        'policy' => ['maximum_payload_bytes' => 65536],
    ],
], [
    'business_db' => $businessPdo,
    'outbox_seals' => $outboxIntegrityKeys,
    'outbox_authority' => $currentBusinessAuthority,
    'outbox_management' => $currentManagementAuthority,
]);
$outbox = $security->outbox();
```

配置使用有界值的独立副本；服务缺失或类型错误时拒绝构造。省略management_guard即禁止初始化、人工重试及维护，普通工作权限不会自动升级为管理权限。

`diagnose()` 只检查服务类型，不调用回调、查询或安装数据库；配置有效标记manual，需要宿主核实真实结构／刷盘、宿主事务、稳定业务事件、当前对象与工作端身份、目的端契约、接收方去重、密钥隔离、恢复／保留、容量维护和传输时限。manual不是通过，HTTP请求也不能根据诊断自动修复结构或重建根记录。

## 当前权限

普通权限回调签名为 `function(action, phase, scope, producer, actor, metadata): bool`，严格true才允许。管理回调签名相同，省略即禁止初始化、人工重试、维护和对账。phase为request、current、commit或return；普通动作包括enqueue、claim、acknowledge、fail、status和candidates，管理动作包括initialize、retry、maintain、reconcile和purge_resolution。显式对账还要求每次传入独立决策guard，见[超期对账](outbox-reconciliation.md)。

标签和DTO均不证明身份。宿主每次核对真实当前凭据、角色／版本／禁用、租户、生产者、目的端与业务对象。request元数据为空，负责入口身份；current既有元数据为空的队列级检查，也有记录级检查。新消息提供id、destination、topic、aggregate、fingerprint、payload_bytes和created_at；已有消息提供原记录状态及指纹，冲突请求不能用新参数授权旧事件。队列级许可不替代后续记录级对象授权。

enqueue的commit阶段位于自身局部保存点释放前，仍在宿主未提交的事务内；宿主稍后的COMMIT不会自动再次调用Outbox权限或期限检查。宿主提交完整业务单元之前继续核对身份／资源版本和自身预算，不能把该阶段名称当作数据库提交时钩子。工作／管理操作的commit检查位于其自身COMMIT之前，return检查在已提交之后，返回阶段拒绝不会撤销已经提交的领取或确认。

initialize和maintain需要作用域／生产者整个队列的当前管理权限，retry及reconcile另有具体记录检查。一般维护不逐条授权；清理新增resolved记录时，额外逐条调用purge_resolution的current／commit检查，确认审计仍完整及当前清理权限。只拥有某条业务对象权限的调用方不能因此获得队列维护许可。

回调必须只读，不管理事务、改变连接状态或联网。Cookie写入口另行执行CSRF与预算，服务接口执行实际协议认证及大小／频率／发送预算。库端检查不构成跨系统线性一致性或已在途发送的撤回保证。

## 身份、顺序与工作端

`Message::identifier(businessEvent, createdAt)` 根据不可变业务事件参考和原始秒级创建时间生成 `o1.<时间>.<摘要>`。重试／重启不得用发送时刻重新生成。`Message(scope, producer, id, destination, topic, aggregate, body)` 使用固定服务器目的端／主题标识、可信聚合标识及有界原始字节，不接受任意URL或客户自报已认证标志。

同编号不同正文、目的端、主题或聚合拒绝；相同内容返回已有元数据。正常入队只接受时间不在未来且未超过message_age的编号。投递编号绑定站点／租户／生产者／事件，独立于领取秘密、尝试、密钥或epoch。改变事件时间／参考构成不同意图；稳定业务唯一约束和接收方去重仍由宿主保证。

数据库根记录分配递增顺序，宿主回滚会一起回滚分配，成功清理不重置计数。同聚合中更早的未确认／失败记录阻止后项，其他聚合可继续；宿主不能将迟到的旧业务版本冒充新事件。

`claim(scope, producer, worker, afterOrder=0)` 扫描最多scan_limit条候选，返回Claim或null，null不表示全队列为空。`candidates(scope, producer, actor, limit=20, afterOrder=0)` 返回records、next_cursor、complete；工作端按真实游标分页，对目标使用 `claimMessage(scope, producer, worker, id)`，避免前页阻塞造成扫描饥饿。完成一轮后从0重新扫描等待／退避记录。

Claim仅在领取提交及当前权限／期限复核后返回，提供status()、message()和秘密token()。秘密为256位随机材料，数据库仅保存摘要和代际，绑定记录与工作端，不是对外投递编号；普通调试／JSON／序列化不输出正文或秘密。发送预算须小于剩余租期，慢返回／崩溃／确认丢失仍可能重新投递。

目的端明确接受后调用 `acknowledge(scope, producer, worker, token)`；同一成功凭据可重复确认，过期／旧工作端／被重新领取的凭据不能改写新领取。确认清除正文，sent只表示可信工作端确认了目的端契约，不单独证明接收方业务执行。

明确失败调用 `fail(..., token, fixedErrorCode, retryable=true)`；只传服务器固定错误码，不存异常文本／正文／秘密。有限指数退避后重试，自动次数耗尽或不可重试错误转dead，重复fail不重复安排。人工 `retry(scope, producer, id, actor)` 使用独立管理权限，保留投递编号，受次数、恢复期及累计100次上限限制。

## 生命周期与完整性

默认message_age为86400秒、recovery_age为2592000秒、成功至少保留3600秒；租期60秒、每轮8次、最多3次人工重试，退避5秒起、最大3600秒。默认最多1000条记录、64KiB正文、50条候选、10000ms SQL预算；Policy提供完整单位与边界。

候选、领取与维护的键列表同样使用 SQL 字节限制；聚合阻塞只返回存在标记。查询结果为无效键时，以 `outbox.corrupt` 拒绝，不能把异常键当作缺失记录继续处理。维护按实际表列排序，保留索引路径。本次补齐后的九版SQLite六类专项各1236项、PHP7.2／8.5私有MySQL关联专项各1416项通过，详见[验证记录](verification.md#outbox-键列表读取上限补齐本地专项)。

读取根记录和消息元数据时，SQL 按实际字节数限制每个字段，超限或存储类型异常返回拒绝标记，不截断后继续处理。SQLite TEXT 的 `length()` 遇到 NUL 会停止，因此文本元数据使用 `length(CAST(column AS BLOB))`；正文要求实际存储类型为 BLOB，先核对长度与已认证元数据及策略上限，再读取正文。正文长度相同仍须核对完整字节的摘要；读取前被替换为其他等长二进制值时，以 `outbox.corrupt` 拒绝并回滚该操作。合法正文可以包含首尾 NUL、非 UTF-8 字节或为空；部分旧版 PDO SQLite 把空 BLOB 返回为 NULL，只有 SQL 已证明实际为零长度 BLOB 时才规范化为空字符串，不能据此接受缺失记录或 TEXT 正文。

正文查询同时限制行筛选和返回值：只有实际字节数等于已认证长度才返回正文，异常值不能被截断后继续使用。`outbox-input-bounds.php` 还在历史校验完成后、正文查询执行前注入超大值，覆盖领取、状态查询和维护；通过独立连接确认整个操作回滚，并再次领取确认原始含 NUL 的正文。等长替换包含只改变 NUL 后字节的情况，保证摘要覆盖完整正文；中文聚合标识另验证精确256字节可用、超出字节限额及含NUL在查询和权限回调前拒绝。

本地边界专项为 `php -d memory_limit=8M tests/outbox-body-budget.php` 和 `php -d memory_limit=8M tests/outbox-input-bounds.php`。前者使用私有临时 SQLite 文件，覆盖逐字段 SQL 投影、异常存储类型及 16MiB NUL/TEXT/BLOB 数据，并通过独立连接核对每次拒绝后的有界根记录和消息快照保持不变；核对过程也不读取异常字段的原始大值；后者验证精确输入上限、超限拒绝、二进制往返及宿主事务保持，并验证拒绝后在同一事务写入合法消息时，业务写入、消息和根记录仍按宿主选择一起提交或回滚。事务保持不替代业务完整性判断：必需事件无法入队时仍应中止对应业务单元。MySQL 通过 `python3 tests/mysql_check.py --outbox <PHP运行时>` 创建禁用 TCP 的独立临时实例，禁止将这些会重建测试表的专项指向业务数据库。

硬上限专项为 `php -d memory_limit=32M tests/outbox-hard-limit.php`：首尾含 NUL 的精确 1048576 字节正文须原样入队、领取及确认；1048577 字节在消息构造时拒绝，不触发 SQL 或权限回调，根记录与消息数量保持。该检查已纳入 `bin/check.sh` 和自建 MySQL 测试流程，与 8MiB 异常读取专项分别执行。

本次续验已执行并通过：PHP7.2／8.5本地SQLite每版1782项（字段／正文986、输入边界243、硬上限8、核心175、安全370）。逐字段验证含NUL元数据恰好超出1字节即拒绝，错误存储类型在领取、状态查询、候选扫描和维护时均拒绝，并通过独立连接核对有界快照保持不变；另验证全部256种原始字节的正文精确达到策略上限可往返，追加1字节NUL在SQL和权限回调前拒绝。异常读取仍使用8MiB内存限制。PHP7.2／8.5私有无TCP MySQL各九组、1561项及PHP7.2目标静态分析通过，测试实例已清理；未执行生产数据库测试或完整SDK门禁。

本轮已执行并通过：PHP7.2—8.5 九版本 SQLite 关联测试每版 1297 项，其中字段／正文边界 428 项、输入边界 50 项；PHP7.2／8.5 私有 MySQL 各 1042 项。异常数据被拒绝后，状态、领取次数及根版本不变，超限入队不查询 SQL、不调用权限回调，宿主事务仍可提交自己的业务写入。未执行生产数据库测试或部署验收。

随后针对当前源码再次执行九版字段／正文 428 项与输入边界 50 项，均通过；PHP7.2／8.5 私有 MySQL 关联专项各 1048 项通过，新增执行计划验证不放宽原读取限制。不同阶段的源码快照及最终关联测试结果见[验证记录](verification.md)。

`maintain(scope, producer, actor, limit=20, afterKey='')` 最多处理50条并返回游标。sent记录仅在原编号过了入队期且满足成功保留期后删除；清理后原编号仍过期，容量持续释放且顺序不复用。未知失败超过恢复期只清除正文并保留阻塞墓碑／容量。经当前管理与审计证据验证的超期记录可通过reconcile加入宿主事务，转换为独立resolved终态并解除聚合阻塞；保留期结束且逐条清理授权通过后，维护再释放容量。原生签名证据／持久取消闭环仍在实施，不能把“接收端暂时查不到”当作取消或清空状态后恢复，见[超期对账核心](outbox-reconciliation.md)。

独立HMAC封存根、策略、epoch和元数据，根摘要绑定记录集合、顺序及各条封存，覆盖候选筛选隐藏的状态篡改／等量替换。根记录及消息元数据在SQL端按字段限制返回字节数，异常类型或超限返回无效值并拒绝，不截断后继续使用。正文先检查实际SQL存储类型和字节长度，再加载并验证摘要，区分空BLOB、NULL及缺失行。SQLite的BLOB声明不能替代实际类型检查，TEXT长度遇到NUL停止也不能作为正文长度；合法BLOB中的NUL保持原样。维护验证旧正文再换封存键，移除旧键前须完整分页轮换。完整有效旧备份仍需外部epoch、业务账本和接收方对账，HMAC不是完整防回滚机制。

消息正文硬上限1MiB，另受Policy正文限额约束；默认64KiB，按字节计数，包含NUL及非UTF-8字节。聚合标识为无控制字符的UTF-8，最多256字节，目的端与主题最多64字节。合法正文达到限额仍可入队，超策略限额在SQL查询和权限回调前拒绝，不更改消息或根记录；已开启的宿主事务仍由宿主决定提交或回滚。此边界限制应用取回的字段大小，不承诺数据库引擎内部处理、文件页缓存或总进程RSS受相同内存限额约束。

正文为私有数据库原始内容，HMAC不提供加密；宿主最小化敏感内容并按需使用用途绑定加密。部署另行验证权限、保留、容量、可靠时钟、连接／语句／网络超时和备份。

## 验证状态

字段限额阶段九版PHP7.2—8.5真实SQLite每版Outbox612项、私有MySQL每版561项通过，覆盖提交／回滚、重复／冲突、当前权限、聚合阻塞、旧领取、有限重试、分页／精确领取、篡改／故障、清理／过期编号、密钥轮换及输入边界。SQLite正文／元数据16MiB异常在8MiB PHP限制下拒绝，合法二进制NUL保持。

后续新增24进程／真实SIGKILL专项148项与工厂72项；405文件阶段完成九版SQLite每版Outbox832项、私有MySQL每版709项及关联回归。其后[原生接入](outbox-native.md)在445文件历史快照完成九版实际TLS每版274项、8MiB适配57项、166类API与359文件语法，两版全新消费者、PHPStan及311文件归档通过。

[接收检查点与恢复](outbox-recovery.md)阶段补上业务根、独立写前检查点、外部代际和受控恢复，当时九版本地各501项（恢复342）、最终实际TLS各314项及API／364文件语法、两版消费者和315文件归档通过，库核心与公开API源码保持。

后续[超期对账核心](outbox-reconciliation.md)追加reconcile／resolution与格式2，九版SQLite核心／安全／对账／并发等专项、私有MySQL及当前接口签名检查通过；原生网络预算配置与完整复验另行记录。各阶段失败、源码快照与最终终态见[验证记录](verification.md)。原生签名证据、持久取消栅栏及完整R4.3继续，更早业务备份仍需权威恢复与对账。

设计参考：[AWS事务发件箱](https://docs.aws.amazon.com/prescriptive-guidance/latest/cloud-design-patterns/transactional-outbox.html)、[Symfony稳定业务幂等键](https://symfony.com/doc/current/messenger.html#writing-idempotent-handlers)、[Debezium事件／聚合身份](https://debezium.io/documentation/reference/stable/transformations/outbox-event-router.html#basic-outbox-table)。独立实现，不引入对应框架或基础设施依赖。

私有根／消息表不得声明出站外键或被业务外键引用，避免维护清理级联到业务；发现关系即拒绝，关闭外键执行也不能绕过。已有这类扩展须显式迁移，不自动删约束。完整边界与两后端专项见[SQL 依赖契约](sql-transactions.md#私有安全表的依赖边界)。
