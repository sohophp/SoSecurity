# 有界只读状态快照

无法读取STRINGIFY_FETCHES的严格原生驱动使用固定文本／NULL快照元数据投影，完整SQL和规范参数匹配后可复用已关闭语句；支持该属性或自定义依赖保留原SQL。代码模板最多8种，不缓存表名值、数据库、行或授权；语句池仍最多8条，每次仍新读数据库并重新执行。摘要格式与权限／清理保护保持，见[验证及限制](snapshot-text-pool-2026-10-24.md)。

MySQL每组最多4张表的双别名名称解析仅在严格原生路径合并为一条零行查询；自定义PDO／Statement／入口守卫仍逐表执行。两条路径均须完整关闭游标，关闭false或异常以sql.cleanup拒绝；不缓存权限或观察结果。正常摘要格式、输入及期限保持，见[验证与兼容说明](snapshot-resolution-2026-10-24.md)。

MySQL SQL快照以数据库名原始字节参与摘要，隔离级别与数据库身份在同一条新鲜查询中观察，并在使用前完整关闭游标。原1至64字节限制保持；正常ASCII／UTF8摘要保持，有损结果字符集形成的旧错误摘要不自动转换或接受。不得重建既有见证来绕过不匹配。见[修复及兼容证据](sql-snapshot-context-2026-10-24.md)。

[范围证明代际退役](state-proof-retirement-2026-10-22.md)已增加操作授权、签名链接及 password-reset 的永久标记；所有实际账本和标记同属完整来源，Nonce 已消费记录保留。独立审批固定一至四个原生标记效果，预检合计容量，未知结果只按同一清单及新批准续办；完成后仍保持隔离。

新凭据安装现在使用清单格式 4（或包含会话退役的 5），审批固定覆盖原因子准确字节及永久失效标记，见[原因子退役](state-installation-retirement-2026-10-22.md)。格式 2／3 按原效果读取，不自动补写未审批的退役操作；所有相关读取器须协调升级。安装完成仍保持账号禁用和见证隔离，不能代替最终恢复启用。

文件来源指纹现为 `FileSnapshot.Profile.3`：严格校验但不采用最多 64 个、每个 64 KiB 的 `stage-0` 至 `stage-63` 私有暂存槽；正式认证字节仍完整纳入来源。受保护 FileStore 和原生恢复写入复用固定槽，进程终止不再留下随机暂存节点。新旧来源不可混用，不能删除或初始化旧见证绕过迁移。三个安装持久化点的真实 SIGKILL 与独立进程续办见[当前中断记录](state-crash-integration-2026-10-21.md)。

独立新鲜度检查和显式认证接入见[状态边界](state-boundary.md)；快照本身仍只提供有界完整状态观察，不会自动阻止旧备份恢复。完整 F01 验收尚未完成。

SQL、FileStore目录和组合快照现已并入SDK，可直接通过Composer自动加载。它们提供数据摘要和同次采集结果；摘要本身不能证明权限、新鲜度或防止恢复旧备份。独立见证、审批恢复和安全代际仍按[完整规划](security-refinement.md)分别验收。

## 使用

来源只覆盖显式声明的表、筛选范围与目录；未声明部分不在摘要中。先由宿主建立实际表结构，显式声明全部字段、主键、固定筛选和行数上限。库不会安装示例表，也不接管已有宿主事务。SQLite使用持久数据库、日志及FULL/EXTRA同步；MySQL使用InnoDB、原生预处理和REPEATABLE-READ。采集会开启自己的事务，SQLite可能暂时阻塞并发写入；不要在已打开的业务事务内调用。

```php
$source = new SoSecurity\Account\SqlStateSnapshot($pdo, 'account-state', [
    'snapshot_example' => [
        'columns' => ['scope' => 'bytes:64', 'subject' => 'bytes:64', 'enabled' => 'int'],
        'primary' => ['scope', 'subject'], 'where' => [], 'maximum_rows' => 1000,
    ],
]);
$capture = $source->capture([
    'account' => ['table' => 'snapshot_example',
        'key' => ['scope' => 'tenant', 'subject' => 'demo'], 'columns' => ['enabled']],
]);
$row = $capture->row('account'); // 缺失返回null；损坏或超限抛异常。
$digest = $capture->digest();  // 与上面的字段来自同次完整SQL扫描。
```

类型包括非负`int`、`digest`、`id`、`bytes:N`、`blob:N`及对应`nullable_`类型。字符串按完整字节处理，NUL后的字节参与长度和摘要；NULL与空字符串不同。SQLite字段的实际存储类型也必须匹配声明。表结构和主键不匹配、字段／行数超限均拒绝。

分页选择器使用`page=true`、`maximum`、`after`，并指定至少一个主键前缀。`page($alias)`返回`rows`、`total`、`more`和完整`cursor`；下一页原样传回该游标。分页数据与其摘要共用扫描，不在摘要后重读；额外筛选不能隐藏主键前缀内的成员。跨次调用可能看到变化后的数据库，应用需要自行比较观测，不能仅凭游标假定跨请求一致性。

## 文件与组合来源

`FileStateSnapshot`要求两个不同、规范路径的私有0700目录：实际FileStore目录和临时排序目录。完整扫描包括全部合法状态文件，原始文件最大65536字节，拒绝符号链接、硬链接、错误权限、异常条目或目录替换。排序与归并有界，临时数据在结束时清理。读取期限为1至30000毫秒，单次文件采集最多四项。

少于256个状态文件时，在原内存分块中直接计算同一完整摘要，不创建排序记录文件；256个及以上保留外部排序。来源指纹、摘要协议、逐文件校验和容量预算保持，私有临时工作目录仍创建并确认清理，排序目录仍须配置。见[专项及限制](file-snapshot-memory-2026-10-24.md)。

FileStore新增`snapshotFile($key)`、`snapshotReference($key)`和`snapshotBinding()`，仅计算物理引用。`snapshotBinding()`只表示目录身份；绑定命名空间必须使用包含具体文件名的`snapshotReference()`。两个命名空间可以共用目录，但相同逻辑键的文件引用不同。

`CompositeStateSnapshot`要求所有来源使用同一个PDO对象。组合采集最多四个来源、选定数据合计1MiB；完整观测重复两次，摘要或选定字节变化时拒绝。SQL最多32表、每表64列、复合主键四列；每条声明的字段预算最多2MiB。SQL采集最多八个别名，每条最多16列、64KiB，全部选定记录／游标合计256KiB；每页最多八条。

文件与SQL无法由普通数据库事务实现跨系统原子性。全部相关写入者必须遵守宿主的共同锁协议；连续两次观测不能代替这个协议，也不能抵御绕过协议的任意并发写入者。`capture()`只接受内置具体来源；自定义可信`StateSnapshot`仅可参与摘要组合，不得把其自报摘要作为权限证明。

## 示例、数据处理与验证

[可移植组合示例](../examples/state-snapshot.php)在消费者的Composer自动加载之后引用，返回构造函数；SQLite／MySQL示例DDL位于`resources/sql/state-snapshot-example-*.sql`，只用于显式建立的测试环境。返回的采集对象会隐藏普通调试输出并拒绝序列化；`row()`、`page()`和`file()`仍会显式返回原始数据，宿主应限制访问和日志。

执行`php -d memory_limit=8M tests/state-snapshot/example.php`验证本地SQLite示例。常规检查已纳入SQL／文件／组合、分页与损坏输入测试；一万文件容量测试单列。当前整合后的多版本、私有MySQL、独立消费者和归档结果见[验证记录](verification.md)。这些数据API不包含自动恢复、业务授权或生产验收。

## 本阶段验证（2026-10-19）

已执行并通过：PHP7.2—8.5九版共159条调用，包含每版13组新增快照测试、219类型API、588文件语法及既有核心／存储检查；原211类公开成员保持，FileStore原读写／清理／锁方法逐一核对保持。两版私有无TCP MySQL各十组317项通过，实例停止并删除。261源码PHP7.2目标level5静态、两版各一万文件容量、全新Composer消费者及412文件归档通过。291份冻结输入保持，九个并入源码与已验证候选逐字节一致。

常规入口为 `bin/check.sh`；仅本地私有MySQL专项为 `python3 tests/mysql_check.py --snapshots /path/to/php72 /path/to/php85`，脚本自行建立和清理实例，不读取宿主业务库凭据。本阶段没有完整当前SDK的HTTP／浏览器、远端CI、发布、生产或独立审查验收，恢复权限及安全代际候选也未随此基础模块接入。


原生签名链接现通过 `Security::signedLinks($policy)` 显式接入状态策略；For 方法在只读准入中加载当前服务端目标，`withVerification` 在同一见证内完成证明消费和业务 SQL。见[准确范围与证据](state-native-links-integration-2026-10-22.md)。最终恢复启用和完整 R1—R6 仍开放。


原生重置证明现通过 `resetTokens(ttl,statePolicy,requestGuard)` 显式接入当前状态与请求授权，For 方法加载真实密码／因子／邮箱版本，`withConsumption` 共用证明消费与已声明 SQL 的见证边界。授权回调是宿主明确恢复权限，原语不替代 Account\Recovery，也不自动证明 MFA／邮件交付。见[范围与证据](state-native-reset-integration-2026-10-22.md)。


`KeyRingStateSnapshot(PDO,profile,KeyRing,SignaturePolicy)` 现将真实 HMAC 密钥／身份／范围与签名策略纳入完整摘要；来源身份保持，旧配置内容回滚会改变 digest。原生验签要求准确覆盖来源，在线提供器、来源／密钥轮换、HTTP 和最终恢复仍开放。见[范围与证据](state-native-hmac-integration-2026-10-22.md)。


原生 Links／ResetTokens／Grants／CredentialRegistry 新账本的物理文件余量现于 pending 前检查；过期但存在的文件仍占用容量，已有账本可以继续合法更新，释放空间后可用原服务图重试。见[实际反例与有限验收](state-admission-capacity-2026-10-22.md)。不把它推广为全部字节／SQL／磁盘容量或最终恢复通过。

## 工作进程栅栏的实际来源

受保护的 `LocalEpochFence` 必须由同一 `CompositeStateSnapshot` 中的 `FenceStateSnapshot` 覆盖实际目录，否则构造时以 `configuration.state_coverage` 拒绝。每个旧／当前／计划中的权威目录都应在首次建立见证前显式创建并声明，不能只覆盖当前一个 `.fence` 文件。原生认证工厂也核对这一覆盖。

`FenceStateSnapshot(PDO, profile, directory, maximumFiles=128, milliseconds=10000)` 只读观察规范路径的私有 0700 目录。目录身份参与来源指纹；所有合法 `.fence` 文件的名称与完整原始内容参与摘要。文件必须为 0600、单链接、同属主、最多 128 字节，内容为 `open`／`closed`、密钥 ID 与签名；默认最多 128 个文件，可显式设为 1—4096。未知条目、损坏、超限或目录替换均拒绝。具体上下文的签名仍由 `LocalEpochFence` 验证，来源本身不把格式校验当作签名认证。

```php
$fenceSource = new SoSecurity\Account\FenceStateSnapshot(
    $pdo, 'worker-authorities', $canonicalPrivateFenceDirectory, 128, 30000
);
// 在创建 LocalStateWitness / StateBoundary 前加入完整来源。
$completeSource = new SoSecurity\Account\CompositeStateSnapshot($pdo, [
    'sql' => $sqlSource,
    'files' => $fileSource,
    'worker-authorities' => $fenceSource,
]);
```

来源不会创建或重开权威，也不在文件上再次取得锁，因此持有 SH 或关闭阶段 EX 的回调可以观察完整来源。所有写入者仍须遵守“独立见证→栅栏→SQL→文件”锁顺序；两次读取不能替代共同互斥。来源指纹因此变化，已有见证不能通过删除／重建根或静默接受新摘要迁移。最终恢复、跨安全代际的工作进程交接和账号启用仍须独立完成。

回滚复现与本轮结果见[实际栅栏来源](state-fence-source-2026-10-22.md)。
