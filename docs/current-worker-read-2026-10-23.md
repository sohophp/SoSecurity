# 当前登记工作进程的重复检查点优化

本批只优化 `FactorWorkerAuthority::read()` 中不执行权限回调的当前登记读取，不改变工作进程的权限、代际、账本格式或默认预算。它与地址返回授权修复共用候选验证和归档消费者；下述结果已按冻结输入汇总；其中仍有失败，不代表稳定版、完整 F01 或全项目通过。

## 实际改动

相对[修前源码](current-worker-read-evidence-2026-10-23/src__Account__FactorWorkerAuthority.php.before)，运行时只有一行变化：仅当 `$request !== null` 时执行权限回调后的第二次 `Ledger::checkpoint()`。

`assertCurrent()` 调用 `read(null)`。原实现认证第一次完整检查点后，因 null 判断短路，不调用权限回调，却立即再次认证相同根及完整历史。现在这一条路径只执行第一次完整认证；没有缓存身份、授权、元数据或检查点，也没有跨调用复用结果。修前[定向失败](current-worker-read-evidence-2026-10-23/before.log)明确记录 `Expected 1, got 2`，原日志保留。

非 null 请求继续在实际权限回调前后各认证一次完整检查点；回调返回拒绝时也先核对检查点，合法签名的根变化仍拒绝。首次根锁、格式与签名、全部历史成员及摘要检查均保留。MySQL 仍使用原有 `FOR UPDATE`；SQLite 自有事务仍使用 `BEGIN IMMEDIATE`，加入宿主事务时仍遵循原保存点和锁语义。`SqlTransaction::inContext()`、事务归属见证、调用后的期限检查、回滚及清理均未修改。

本优化没有增加公开类型或方法，没有数据库迁移，也没有改变持久化数据格式。地址修复的独立 API 增量不属于这里的“无新增公开方法”结论。

## 十二种固定场景

[正式测试](../tests/current-worker-read.php)使用真实 `InboxTestConnection`／`InboxTestStatement` 计数，不构造会删除已有表的 `InboxEnvironment`。每个场景只创建自己的临时目录；MySQL 必须来自带所有者标记的私有控制器。SQL 使用严格 `CREATE TABLE`，只有成功创建的表才登记为可清理资源，遇到同名既有表即拒绝。

测试直接构造初次 `LocalEpochFence`、`SqlTransaction` 和准确 format 2 `Ledger`，命名空间及 authority 沿用实际工作进程代码；不构造恢复编排器，不调用交接、后继初始化、未知结果续办或最终账号恢复启用。场景结束核对 SQL 数据及栅栏内容，释放自身事务并清理自身资源。

| 场景 | 要验证的行为 |
| --- | --- |
| `normal` | 无权限回调，根及完整历史各读取一次，数据不变 |
| `normal-joined` | 同一读取加入既有宿主事务，子读取不提交宿主事务，宿主回滚后数据与栅栏保持 |
| `permission` | 非 null 请求仍在权限回调前后各读取一次完整检查点，回调一次 |
| `permission-joined` | 同一权限读取加入宿主事务，两次检查点及回调保持，宿主仍拥有事务 |
| `denied` | 权限回调拒绝，不产生成功授权，两次检查点仍执行 |
| `callback-root-change` | 回调在同一事务内写入合法签名的新历史，检查点变化被拒绝，原数据保留 |
| `transaction-ended` | 回调结束原事务后，保存点归属或清理不确定必须拒绝 |
| `root-corrupt` | 根签名损坏时拒绝，不调用权限回调 |
| `history-corrupt` | 历史签名损坏时拒绝，不调用权限回调 |
| `wrong-pdo` | 不接受另一 PDO，拒绝发生在根读取与权限回调前 |
| `deadline` | 真实延迟使权限回调超出原有测试期限，拒绝并保留数据 |
| `null-deadline` | 无权限回调的读取本身迟到也拒绝，不因少一次检查点放宽期限 |

SQLite／MySQL 的测试事务结束方式必须符合各自实际 PDO 行为；相关测试脚本的可移植性修正单独保存，不修改产品事务保护来迁就测试。

## 默认签发仍失败

本次独立的 PHP8.5.9／私有 MySQL 首次凭据签发诊断仍失败：默认预算 **3000ms**，耗时 **3.028782581910491 秒**，返回 `account.completion_unknown`，见证保留 `pending`。见[结果](current-worker-read-evidence-2026-10-23/default-85-timing.json)、[执行记录](current-worker-read-evidence-2026-10-23/default-85-result.json)、[原始日志](current-worker-read-evidence-2026-10-23/default-85-run.log)及[输入摘要](current-worker-read-evidence-2026-10-23/default-85-inputs.json)。没有 all／rotate 或未知结果续办。

这证明此次去重尚未解决默认签发可用性；不能把单次耗时与较早快照比较后宣称稳定性能收益，也不能以显式延长预算的正常结果替代默认配置验收。

## 最终候选验证状态

[统一终态汇总](address-captured-policy-evidence-2026-10-23/delivery.json)绑定当前7份运行时及测试输入。开发期原型、修前失败及不同输入的后续结果分别保留，不把它们相加成为一次完整验收。

| 检查 | 当前结论 |
| --- | --- |
| 修前重复读取反例 | 已执行但失败，实际两次，保留原始失败日志 |
| 默认 3000ms 首次签发 | 已执行但失败，约 3.029 秒、pending，未续办 |
| PHP7.2—8.5 九版 SQLite 十二场景 | 已执行并通过，九版各12场景 |
| 私有 MySQL 十二场景及宿主事务 | 已执行并通过，PHP7.2／8.5各12场景 |
| 公开契约、静态检查及受影响回归 | API九版9/9、PHPStan及shell通过；固定矩阵1117通过／7失败，不能称整组通过 |
| 实际归档、全新消费者及数据库隔离 | 归档14外层步骤12通过／2失败；四组vendor工作进程各12场景通过；控制器20次真实SQL隔离探测通过 |

最终命令与输入在 [current-verified](address-captured-policy-evidence-2026-10-23/current-verified/summary.json)。最初344条后仅更正SQLite测试的SQL `COMMIT` 写法，保留两条旧事务结束测试失败，并重新运行全部依赖该测试的命令；产品事务保护不改。其余342项按相同源码及无依赖影响复用，另新执行782项，合计覆盖1124项。原 `current/` 及零命令的编排断言失败记录均保留，未改写旧结论。

## 已执行的归档与隔离范围

[归档脚本](address-captured-policy-evidence-2026-10-23/archive.py)共计划14个外层步骤：核心 Composer ZIP、离线全新消费者安装，以及 PHP7.2／8.5 每端的 vendor 来源检查、三个 SQLite 地址场景、SQLite 工作进程 `all` 和一个私有 MySQL 控制器调用。源码树不作为消费者的运行时自动加载来源；七份指定运行时、全部产品 PHP 文件及15份 SQL 资源均核对安装包摘要，SQL 与示例从 vendor 包复制。

SQLite 地址场景固定为 `normal`、`request-late-before`、`complete-late-commit`。MySQL 通过消费者自身的 `tests/mysql_check.py --sql-foreign-plan` 启动自有实例，运行时包装器依次执行 `normal`、`request-final-guard`、`complete-final-expiry` 三个地址场景，然后执行工作进程十二场景 `all`。每个子程序保留退出码，十二个工作进程 PASS 必须全部出现；这不是重新执行整个地址门禁。

[隔离脚本](address-captured-policy-evidence-2026-10-23/gate-isolation.py)另用 `--sql-foreign-plan` 创建外层自有 MySQL，严格创建 `sosecurity_state` 与 `account_example` 并各保存一条测试标记，再运行真实嵌套 `--native-address-captured` 控制器。其运行时参数是专用 SQL 探测器：逐个核对20个实际模式的参数、父控制器进程、独立子 socket、所有者标记及服务器进程，并真实执行 `SELECT DATABASE()`／`SELECT 1`。专用 PASS 仅证明控制器隔离，不代表执行地址产品用例；真实产品场景由固定候选矩阵及 vendor 消费者验证。隔离检查比较外层两表完整记录及两层临时资源清理，不运行完整 `bin/check.sh`。

两个脚本均记录非零退出、缺失 PASS、未执行、超时、输入变化及清理状态。[归档](address-captured-policy-evidence-2026-10-23/archive.json)中保留PHP7.2失败，[隔离](address-captured-policy-evidence-2026-10-23/gate-isolation.json)通过；自身临时资源均已清理，源码摘要保持。跨安全代际交接、未知回执续办、最终恢复启用、完整 F01 及外部验收保持原状态；本批不据此关闭 goal 或宣布稳定版完成。
