# 当前工作进程读取复用外层 SQL 事务

本批处理默认原生 MySQL 凭据签发的本地性能缺口。它只减少当前因子目录读取的嵌套 SQL 单元开销，默认预算仍为 3000ms；是否达到默认预算须看本批首次签发结果，不能从局部查询数推断。

## 已确认与实际修复

`FactorRegistry::snapshot()` 在 before/current/return 三个阶段，各在宿主权限回调前后检查一次当前工作进程。此前这六次检查分别创建嵌套 `SqlTransaction`，尽管外层已有活跃 SQL 单元。[修前反例](current-worker-context-evidence-2026-10-23/before-normal.log)在真实 SQLite 中记录 `Expected 0, got 1`；[首次修后结果](current-worker-context-evidence-2026-10-23/after-normal.log)通过，完整根和历史仍各认证一次。

现在显式传递外层单元，仅 `snapshot()` 的三个阶段启用。`recoveryFacts()`、其他管理路径以及有权限请求的工作进程读取继续原路径。没有更改交接、恢复启用或未知状态续办。

内部 `SqlTransaction::readIn()` 保留子单元的时钟及已启动期限，与外层期限取交集；只接受准确 PDO、未失败且具有有效保存点的外层单元。它核对真实事务归属，限制实际连接锁等待上限并按需恢复；SQLite 已设为 0 的立即失败语义保持。即使预算耗尽，仍执行保存点清理检查；归属不确定会同时拒绝继续使用外层单元。

只有无守卫或准确原生纯守卫的连接可共享结构证书。未知守卫继续原有嵌套路径；宿主回调和写入使证书同步失效。共享的是同事务内的表结构证明，工作进程根和完整历史每次重新认证，不缓存权限。借用子单元禁止 SQL 写入和宿主回调。

[本批五文件差异](current-worker-context-evidence-2026-10-23/runtime-changes.diff)以本批开始前源码副本为基准，未把整个既有 Git 改动算作本次工作。[独立只读审查记录](current-worker-context-evidence-2026-10-23/runtime-review.json)列出实际不变量和修正。

## 兼容性

公开类型仍为 **277**。`FactorWorkerAuthority::assertCurrent()` 和 `TotpFactors::enlistWorkers()` 各增加一个可选、可空的 `SqlTransaction $owner` 参数，原调用方式保持；另两个涉及的方法属于既有内部类型。候选契约只修改这两个方法的参数，其他275条类型记录保持，见[逐项 API 审查](current-worker-context-evidence-2026-10-23/api-review.json)。没有修改数据库 DDL、持久格式或默认预算。

## 固定验证范围

[新增测试](../tests/current-worker-context.php)固定20项：自有／宿主事务、闲置／提交后／错误 PDO、根与历史损坏、外层／子预算、独立时钟倒退和故障、回调后结构复核、真实结构变化、事务丢失、锁等待限制及零等待、禁止子写入／回调、未知入口守卫降级。每项使用自己创建的数据库资源及首次本地工作进程，不进入暂缓链路。

本批执行104条定向命令，覆盖 PHP7.2—8.5 九版 SQLite、两端私有 MySQL、因子目录及事务保护、受保护登录、两端关联地址场景、API、静态分析与 shell 语法；不是全项目验收。[固定清单与当前记录](current-worker-context-evidence-2026-10-23/matrix/commands.json)保留全部失败和未执行子场景。归档消费者另核对实际 ZIP、离线独立 vendor 安装、源码及 SQL 资源来源。

本批已收口，当前定向覆盖 **104/104通过**，其证据为初轮102条通过及测试环境修正后的2条私有MySQL重新执行；不是重新完整跑过104条。初轮两个 MySQL 控制器都在 `schema-change` 的测试建表回调中失败，第二次产品校验尚未执行。[一次原句诊断](current-worker-context-evidence-2026-10-23/shadow-diagnostic.log)保留 `SQLSTATE 42000 / 1066`，确认同名 `CREATE TEMPORARY TABLE … LIKE …` 的测试建立错误。修正只使用已有严格 roots DDL 创建同名临时表，仍测试真实遮蔽，未改变 `sql.unavailable` 预期、权限或 SQLite 执行分支。[修正说明及差异](current-worker-context-evidence-2026-10-23/fixture-correction.json)、[当前覆盖汇总](current-worker-context-evidence-2026-10-23/matrix-final.json)和原失败日志均保留。PHP7.2／8.5 两端修正后各20个 MySQL 场景通过。

| 验证组 | 已执行并通过 | 已执行但失败 | 未执行 | 范围 |
| --- | ---: | ---: | ---: | --- |
| 当前定向命令覆盖 | 104 | 0 | 0 | 102条不受修正影响的既有结果，加2条修正后执行结果；原失败不删除 |
| 归档／消费者外层检查 | 11 | 1 | 0 | 12条构建、安装、来源及产品测试运行命令 |
| 归档消费者产品场景 | 127 | 1 | 0 | PHP7.2／8.5 × SQLite／MySQL，20项上下文与12项工作进程读取 |
| 默认首次签发 | 0 | 9 | 0 | PHP7.2—8.5，同一个私有 MySQL 服务上的九组独立新建数据 |

归档使用实际 Composer ZIP、离线独立安装且禁止软链接；消费者的339个运行时文件以及27个 SQL 资源均与源码摘要一致，类来源指向消费者 `vendor`。归档不包含测试与证据目录；测试作为外部断言单独复制到消费者。详见[归档结果](current-worker-context-evidence-2026-10-23/archive.json)。

归档唯一失败是 PHP7.2 SQLite 上下文测试的最后一项 `lock-immediate`：前19项通过，最后一项进入后抛出 `sql.timeout`，原信息明确为时长时钟倒退。见[完整失败日志](current-worker-context-evidence-2026-10-23/consumer72-sqlite-context.log)。因此128项确实为127通过、1失败；没有用另一次通过覆盖该失败，也没有停用时钟保护。该归档尚不能称为全部通过。

## 默认签发仍未满足本地可用性要求

[默认九版矩阵](current-worker-context-evidence-2026-10-23/default-matrix.json)只启动一个禁止 TCP 的私有 MySQL 服务，顺序创建九组全新账号／因子／见证数据。每组保留原有前置拒绝测试，再执行一次允许的首次签发，随后立即停止；没有 `all()`、轮换、恢复、未知状态续办或前次 pending 数据复用。默认凭据预算均为 **3000ms**，未提高。

全部九组都返回 `account.completion_unknown`，见证为 `pending`，退出码255。仅首次签发调用的计时如下；不包含数据库初始化及账号预设准备时间，也不构成与旧版本的性能对照。

| PHP实际版本 | 首次签发耗时（秒） | 结果 |
| --- | ---: | --- |
| 7.2.34 | 3.151816 | pending / completion_unknown |
| 7.3.33 | 3.083171 | pending / completion_unknown |
| 7.4.33 | 3.005472 | pending / completion_unknown |
| 8.0.30 | 3.285493 | pending / completion_unknown |
| 8.1.34 | 3.155311 | pending / completion_unknown |
| 8.2.32 | 3.484191 | pending / completion_unknown |
| 8.3.35 | 3.366462 | pending / completion_unknown |
| 8.4.23 | 3.331403 | pending / completion_unknown |
| 8.5.9 | 3.357957 | pending / completion_unknown |

成功分支要求真实 `IssuedCredential`、第一代凭据、恰一条 `authorization.allowed` 审计记录、当前见证与源码摘要一致；本轮九版均未通过这些成功断言。已有功能在显式较宽预算下的通过记录不能替代默认预算验收。本次减少嵌套事务的修复确实通过对应安全回归，但**默认原生 MySQL 首次签发缺口仍未解决**，不能将其改列为外部验收或暂缓事项。

## 证据绑定与资源清理

[统一证据清单](current-worker-context-evidence-2026-10-23/delivery.json)由只读收集器生成，不启动测试。收口时五个运行时文件仍与独立审查摘要匹配；归档的1236项输入、默认矩阵的1156项输入均与当前文件一致。初轮定向矩阵仅新增测试文件的 MySQL 建表修正发生变化，复用依据和修正前副本已经保存。公开 API 仍为277个类型，两个可选参数的契约差异与实际候选一致。

归档及默认矩阵记录的自有 MySQL 服务、消费者／诊断目录和进程均已清理。默认每个版本执行前后都实际查询私有数据库为空，且独立测试临时目录已清空；普通失败后继续下一组新数据。定向矩阵记录无残留活跃句柄。收集器另外核对已有清理路径，不删除额外资源。没有提交、推送、部署、外部投递或访问生产数据库。


## 仍开放的要求

默认首次签发九版失败、归档 PHP7.2 的明确时钟拒绝以及历史未解释失败均保持开放。[R4.6 保留期外告警恢复](audit-window-recovery-gap-2026-10-23.md)也仍未实现，旧 SQL 日志缺少精确恢复原指标窗口的信息，不能冒充已有能力。暂缓链路、完整 F01 和外部验收保持原状态。goal 继续 active。
