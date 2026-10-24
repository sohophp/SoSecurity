# 固定账本上下文的无效SQL构造移除

2026-10-24。本批仅修改`SqlSchema::ledgerSchemaContext()`：原生路径已有固定SQL及参数，却仍先执行完整备用语句构造，再丢弃其结果。将该构造移入备用分支，避免每次生成两条权限观察、重命名参数及拼接物理表解析SQL。

这是纯构造成本调整，没有减少SQL执行、权限／触发器／耐久性／数据库／事务归属观察，没有缓存授权、改变预备语句模式或扩大语句池。备用分支的构造内容去除新增缩进后逐字一致；固定查询与参数、方法其余部分逐字一致。见[源码增量](ledger-context-build-evidence-2026-10-24/source-change.diff)、[结构核对](ledger-context-build-evidence-2026-10-24/source-equivalence.json)。

[源码清单](ledger-context-build-evidence-2026-10-24/final-inputs.json)共367份；相对于本批开始仅SqlSchema改变，其余366份保持。公开API仍为278类／接口，未修改公开签名、DDL、存储格式、预算和错误码；[上批数据库字节隔离修复](sql-database-identity-2026-10-24.md)完整保留。无兼容性变化。

纯构造微基准交替三轮各50000次，输出固定代码相同。PHP7.2旧构造平均约0.302304秒、直接取固定代码约0.005202秒；PHP8.5分别约0.269795和0.004153秒。旧构造样本通过Reflection调用私有SQL生成器，因此还包含该调用开销，数值不能视为生产方法的精确差值。这只测量纯PHP代码，不包含MySQL或权限观察，不能推导端到端预算验收。[PHP7.2数据](ledger-context-build-evidence-2026-10-24/benchmark-72.json)、[PHP8.5数据](ledger-context-build-evidence-2026-10-24/benchmark-85.json)。

## 当前验证

SQLite27程序、九版API及静态检查合计37/37通过。归档全新消费者通过7/7步骤，含两端8个MySQL与6个SQLite程序，反射来源及367份SDK／SQL摘要一致，自建资源已清理。见[本地检查](ledger-context-build-evidence-2026-10-24/local-checks.json)、[消费者](ledger-context-build-evidence-2026-10-24/consumer/consumer.json)。

MySQL九版矩阵36程序中35通过、1失败。九版上下文池16场景均通过；PHP7.2数据库字节测试的检查点场景通过，准备第二个场景的SQL快照时发生持续时间时钟倒退，保留原始失败，不把该程序余下三个场景记为主轮通过。其他八版数据库字节场景、九版账本语句和通用元数据语句程序均通过。全新消费者在同源码摘要下的PHP7.2四个数据库字节场景通过，作为独立覆盖证据，不关闭主轮时钟失败。[主轮结果](ledger-context-build-evidence-2026-10-24/matrix.json)、[原始失败](ledger-context-build-evidence-2026-10-24/php72-unicode.log)、[消费者逐程序结果](ledger-context-build-evidence-2026-10-24/consumer/test-rows.json)。本批未增加测试或放宽现有断言。

默认首次签发在功能矩阵及消费者均结束后串行检查，九版均取得实际签发计时。每版只用新环境执行一次首次签发，保持真实SystemClock、PDO、纯来源守卫、策略提示1及默认3000ms，不续办未知结果。PHP8.5一次成功，返回真实凭据、审计记录且见证current；其他八版失败。一次成功不足以证明稳定，也不能据此归因于本次微小构造调整。

| PHP | 墙钟秒数 | 结果／见证 |
| --- | --- | --- |
| 7.2.34 | 3.003184 | account.completion_unknown／pending |
| 7.3.33 | 3.004087 | account.completion_unknown／pending |
| 7.4.33 | 3.001272 | account.completion_unknown／pending |
| 8.0.30 | 3.002873 | account.completion_unknown／pending |
| 8.1.34 | 3.004425 | account.completion_unknown／pending |
| 8.2.32 | 3.007906 | account.completion_unknown／pending |
| 8.3.35 | 3.033784 | account.operation_timeout／current |
| 8.4.23 | 3.119647 | account.operation_timeout／current |
| 8.5.9 | 2.904882 | 通过／current |

五个默认命令（7.2／7.3／7.4／8.0／8.3）最初缺ext-sodium，未进入签发即被依赖检查拒绝。这五份原始失败保留；补测使用现有仅加载Sodium扩展的包装器，未安装或变更系统环境、时钟或预算。PHP7.2仍不具备hrtime，使用原时长时钟。见[包装器及配置摘要](ledger-context-build-evidence-2026-10-24/sodium-runtimes.json)、[原默认命令批次](ledger-context-build-evidence-2026-10-24/default-matrix.json)、[扩展补测](ledger-context-build-evidence-2026-10-24/sodium-supplement/result.json)、[九版有效结果汇总](ledger-context-build-evidence-2026-10-24/default-combined.json)。

PHP8.5正常审计管理流程另建环境检查，计划只包含现有正常签发、查询、轮换、替换、撤销及容量／对象拒绝，不进入恢复或续办。但实际在首次签发即约3.061583秒以account.operation_timeout拒绝，见证current；后续查询、轮换、替换、撤销及容量／对象拒绝均未执行，未续办或重试。该结果进一步表明此前一次成功不能作为稳定预算验收。[限定范围](ledger-context-build-evidence-2026-10-24/workflow/scope.json)、[计时](ledger-context-build-evidence-2026-10-24/workflow/default-85-timing.json)、[运行结果](ledger-context-build-evidence-2026-10-24/workflow/default-85-result.json)、[原始失败](ledger-context-build-evidence-2026-10-24/workflow/default-85-run.log)。

完整check.sh、跨安全代际交接、未知回执续办、最终账号恢复启用及依赖完整F01均未执行，外部验收未执行。goal保持active；默认签发及最终非暂缓验收仍开放，不宣称完整稳定版通过。保留既有改动与历史失败，未提交、推送、部署或访问生产数据库。
