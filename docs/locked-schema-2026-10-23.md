# 同一事务内的账本结构证明复用

2026-10-23。本批修改 `Ledger`、`SqlSchema`、`SqlTransaction`，减少账本检查点在普通宿主回调之后重复读取完整列、索引、引擎及依赖结构。先前[元数据锁与保存点反例](schema-mdl-2026-10-23.md)是实现前置证据，不能替代本批实现测试。

首次仍执行原有双表完整校验。只有原生 PDO、原生语句、SystemClock、可识别的纯入口守卫和同一存活事务见证才保存结构证明。每次复用前后均探测真实保存点，每次重新执行双表实际解析、当前直接 TRIGGER 权限及触发器检查，并核对当前数据库；切库后重新完整校验。权限结果、账号、会话、因子、角色和账本内容均不缓存。原权限可见性 SQL 提取前后逐字相同，见 [对照](locked-schema-evidence-2026-10-23/visibility-comparison.json)。

写入、事务边界、回调失败、归属丢失和清理异常均使证明失效。借用外层事务的只读子单元共享证明及失效状态，退出后解除引用；子读取失败使外层重新校验。其他时钟、PDO／语句适配器及 SQLite 保持逐次完整校验。保留原有权限回调、会话触达、当前来源和最终返回守卫，不提高任何预算。

## 已执行并通过

- PHP 7.2—8.5、私有禁 TCP MySQL 8.0.46：原生路径 12 场景 × 9 版本共 108 项，涵盖普通回调、两表分别撤权、全局权限与 partial_revokes、两表临时遮蔽、切库及含额外 UNIQUE 的同内容克隆库、实际账本更新、写入失效和回调结束事务。见 [结果](locked-schema-evidence-2026-10-23/verified-matrix.log)。
- 同九版补充外层事务借用正常／失败清理 18 项，以及提前保存点回滚 9 项。回滚后在执行当前上下文读取之前拒绝，内部为 `configuration.sql_transaction_lost`，外层为 `sql.cleanup`。见 [借用](locked-schema-evidence-2026-10-23/borrow-matrix.log)、[回滚](locked-schema-evidence-2026-10-23/locked-rollback-matrix.log)。本批新增共 135 项。
- 九版 SQLite 原账本／结构复用边界共 18 条程序通过；PHP 7.2／8.5 私有 MySQL 当前工作进程 40 场景、账本检查点读取 14 场景和原元数据锁 8 场景通过。见 [SQLite](locked-schema-evidence-2026-10-23/sqlite-results.json)、[工作进程](locked-schema-evidence-2026-10-23/current-worker.log)、[账本](locked-schema-evidence-2026-10-23/ledger-regression.log)、[锁](locked-schema-evidence-2026-10-23/mdl-regression.log)。
- PHPStan 无错误；可选 turbo 扩展因本机 GLIBC 不满足而有启动警告，分析实际完成。公开 API 实际清单仍为 278 类型，契约检查通过。见 [静态分析](locked-schema-evidence-2026-10-23/static.log)、[API](locked-schema-evidence-2026-10-23/api-final.log)。
- 两端真实 ZIP 归档及离线全新 Composer 消费者，非符号链接安装，全部运行时／SQL 资源摘要一致，反射核对三个修改类来自 vendor。首轮覆盖两端 SQLite 账本及 24 项 MySQL 新场景；补充两端借用 4 项和回滚 2 项。三个独立归档共 20 个准备／验证步骤通过，其中 8 个产品测试调用；自身临时目录均清理。见 [首轮](locked-schema-evidence-2026-10-23/consumer/consumer.json)、[借用补验](locked-schema-evidence-2026-10-23/consumer-borrow/consumer.json)、[回滚补验](locked-schema-evidence-2026-10-23/consumer-rollback/consumer.json)。这些不是完整项目验收。

原生普通路径的三个连续检查点，完整结构读取由修复前 3 次降为当前 1 次；写入后为 2 次，借用失败清理后也为 2 次。使用私有服务器实际 Execute 日志计数，仅保存计数，不把 SQL 日志带出临时数据库。见 [旧实现对照](locked-schema-evidence-2026-10-23/baseline.log)与上述新测试日志。该结果证明查询次数变化，不证明整个签发操作提速。

## 已执行但失败与未关闭事项

真实 SystemClock／原生 PDO、原 3000ms 默认预算的首次签发仍失败：PHP 8.5 约 3.405 秒，`pending / account.completion_unknown`，栈位于凭据写入后的 `issued()` 第三次 actor 检查。没有续办，没有提高预算。见 [时序](locked-schema-evidence-2026-10-23/default-85-timing.json)、[原始日志](locked-schema-evidence-2026-10-23/default-85-run.log)、[输入与清理](locked-schema-evidence-2026-10-23/default-85-result.json)。不把本次结果解释为整体性能改善；其余八版真实默认签发未在本批重复执行，不能据本批关闭既有失败。

测试开发初轮临时表权限未齐、切库后的临时表权限未齐，以及事务结束时外层异常预期错误，分别保留在 smoke、expanded-matrix、final-matrix 日志；原六场景矩阵另见 matrix.log。后续补齐测试环境权限及同时断言具体内部见证错误／外层 cleanup，没有修改产品拒绝策略或删减失败用例。最终 108 项、18 项和 9 项分别绑定运行时同一快照；测试文件后来增加的独立场景以补验记录为准。

不涉及公开签名、DDL、持久格式和默认预算变化；内部 `verifySchema()` 增加可选当前上下文回调，仅固定账本启用。自定义时钟与适配器不获得这项优化。账号恢复、跨代交接、未知回执续办及完整 F01 未实现或测试；真实外部环境、整项目候选和历史失败未关闭。当前 goal 保持 active，默认签发性能仍是可继续处理的本地缺口。

[源码及测试摘要](locked-schema-evidence-2026-10-23/inputs.json)、三个源码的批次前备份与增量 diff、[Git 状态](locked-schema-evidence-2026-10-23/git-status.final.txt)和[汇总](locked-schema-evidence-2026-10-23/delivery.json)保留在本地证据目录。已有未提交改动保持；未提交、推送、部署、访问生产数据库或外部投递。
