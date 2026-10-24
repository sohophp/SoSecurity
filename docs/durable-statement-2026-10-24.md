# 固定持久性查询的原生语句复用

本批于2026-10-23开始，2026-10-24收口。仅修改 `SqlSchema::durable()` 和 `SqlStateAccess::metadataRows()` 的固定 MySQL 全局变量读取，不改变持久性要求，不缓存配置值、权限或账号数据。

先用原生 PDO、原生 PDOStatement、真实 SystemClock 和原有纯入口守卫采集自建禁 TCP MySQL 的调用计数。此前覆盖 PDO 的插桩会关闭部分优化，不能代表当前原生路径。本次诊断的失败签发前缀包含2138次 Prepare、2288次 Execute，其中列元数据154次 Execute、0次 Prepare，说明原有语句复用已生效；会话／全局策略类别仍有563次 Prepare。该类别不是全指本批固定变量，不能据此宣称减少563次准备。见 [计数](native-sql-counts-evidence-2026-10-23/counts.json)、[汇总](native-sql-counts-evidence-2026-10-23/analysis.json)、[原生运行器](native-sql-counts-evidence-2026-10-23/run.py)。仅保存固定类别及数量，不导出 SQL 文本或参数；诊断不是性能验收，没有续办未知结果。

对固定 `SELECT @@GLOBAL.innodb_flush_log_at_trx_commit` 独立复现，三次检查实际 Prepare3／Execute3，见 [修复前](durable-statement-evidence-2026-10-23/before.log)。现在仅在已注册连接、原生 PDO／语句及完整取值配置可读取时，使用现有八槽池保存已关闭的预编译语句；每次仍执行查询并严格检查单行单值为1。该固定全局变量不依赖当前数据库，因而不增加 DATABASE 查询；其他元数据的当前数据库核对保持。没有扩大池容量。

游标显式消费并关闭，清理失败以 `sql.cleanup` 拒绝，并使当前单元失效。未注册连接、PDO／语句适配器和不支持读取必要取值配置的驱动均继续逐次准备。取值配置变化使用独立语句，执行中的句柄先从池中移除，重入不会共享活跃句柄。

## 已执行并通过

- PHP7.2—8.5、私有 MySQL8.0.46：10场景×9版本，共90项。覆盖正常／未注册／PDO适配器／语句适配器、全局配置变为2、切库、取值配置变化、八槽淘汰、时钟回调重入、清理失败及单元失效。见 [最终矩阵](durable-statement-evidence-2026-10-23/mysql-final.log)。
- 支持复用的本机驱动三次检查 Prepare1／Execute3；不支持的驱动保持 Prepare3／Execute3。全局配置变为2时，两条路径均在第二次 Execute 后以 `configuration.sql_durability` 拒绝。重入时产生独立活跃句柄；填入八条其他语句后，固定查询须重新 Prepare，证明未增加第九槽。
- 本机 PHP7.2—8.1 缺少必要的 PDO 取值配置读取能力，保持逐次准备；PHP8.2—8.5取得复用证据。该结论限定本机驱动组合，不把 PHP 版本号作为产品中的判定条件。见 [实际能力](durable-statement-evidence-2026-10-23/driver-support.json)。
- 两端原有元数据语句生命周期各81断言、双表结构各221断言和当前权限各20断言通过；九版 SQLite 账本／双表结构共18条程序通过。见 [元数据](durable-statement-evidence-2026-10-23/metadata-regression.log)、[结构与权限](durable-statement-evidence-2026-10-23/schema-regression.log)、[SQLite](durable-statement-evidence-2026-10-23/sqlite.json)。
- PHPStan完成且无错误，原有可选 turbo 扩展 GLIBC 启动警告保留；API检查通过278类型。新专项接入 MySQL控制器及开发检查入口，开发检查脚本仅语法检查，未运行包含暂缓套件的完整脚本。见 [静态分析](durable-statement-evidence-2026-10-23/static.log)、[API](durable-statement-evidence-2026-10-23/api.log)。

两端实际 ZIP／离线全新 Composer 消费者均核对非符号链接安装、三个相关类来自 vendor，以及全部运行时／SQL资源摘要。首轮8步骤中7通过，PHP7.2 MySQL因测试未识别驱动能力而失败；原PHP8.5的10场景及两端SQLite账本通过。修正测试后，以新归档补验PHP7.2，4步骤全部通过，包含其10场景。不重跑源码完全相同且已通过的PHP8.5消费者；最终相关覆盖由准确输入对应的原通过证据和补验组成，不能把原8步骤写成全部通过。见 [原始消费者](durable-statement-evidence-2026-10-23/consumer/consumer.json)、[PHP7.2补验](durable-statement-evidence-2026-10-23/consumer-72-final/consumer.json)。两个自身临时目录均已清理。

首版矩阵同样错误要求PHP7.2 Prepare1，原失败保留在 mysql.log；后来按三个 PDO 取值属性实际读取结果判断能否复用，保留所有场景和每次 Execute／错误类型／清理断言，没有让不支持的驱动进入优化路径。smoke.log 为PHP8.5最初八场景快照，最终增加淘汰和重入后以90项矩阵为准。

## 仍失败及交付边界

上述隔离任务结束后，单独执行未插桩的真实 SystemClock／原生 PDO 默认首次签发。PHP8.5仍失败，约3.147145秒，预算3000ms，栈仍在 `issued()` 第三次 actor 进入时；见证 `pending`，外层 `account.completion_unknown`。没有续办。见 [时序](durable-statement-evidence-2026-10-23/default-85-timing.json)、[原始日志](durable-statement-evidence-2026-10-23/default-85-run.log)、[输入与清理](durable-statement-evidence-2026-10-23/default-85-result.json)。单次计时不能证明整体提速；其他八版真实默认签发本批未重复执行，原失败未关闭。

公开 API、DDL、持久格式、默认时间及资源预算保持。兼容变化是MySQL持久性检查会显式关闭游标并拒绝关闭失败，畸形返回值须满足单行单值；不支持优化的驱动保持逐次准备。未提交、推送、部署、访问生产数据库或外部投递，已有改动保留。

本批为专项验证，不能替代完整项目或稳定版验收。默认签发、历史时钟及其他未解释失败、最终非暂缓候选核对仍开放；暂缓功能和外部环境验收未实现或测试。goal保持active。见 [当前输入摘要](durable-statement-evidence-2026-10-23/inputs.json)、[批次汇总](durable-statement-evidence-2026-10-23/delivery.json)及[Git状态](durable-statement-evidence-2026-10-23/git-status.final.txt)。
