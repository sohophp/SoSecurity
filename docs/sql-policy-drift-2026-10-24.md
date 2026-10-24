# SQL 执行期间的连接配置漂移

本批确认并修复一个独立缺陷：`SqlTransaction`只在构造时要求异常模式和MySQL原生预处理，随后宿主、准入守卫或时钟回调能改变连接属性。切换到模拟预处理后，原实现会执行`SELECT`之后分号连接的写入；在`readIn`只读借用中也能写入，并随父事务提交。复现只涉及自建测试表和私有无TCP MySQL，不涉及恢复、交接或未知结果续办。

修复在每次活跃时钟检查中、准入守卫和实际时钟回调返回后，重新读取异常模式和MySQL预处理配置。配置改变或读取不确定时以`configuration.sql_transaction`默认拒绝；属性读取异常在捕获结束后转换，不带原始异常链。保留原SQL、事务所有权、清理、权限和期限检查，不自行修改宿主连接配置。测试恢复宿主属性后，父事务或自有事务仍可正常写入独立记录。

SDK仅修改`src/Support/SqlTransaction.php`的局部执行逻辑，另外366份SDK／SQL文件摘要保持。公开API仍为278类／接口；没有修改签名、DDL、存储格式或默认3000ms凭据预算。兼容变化是异常模式和原生预处理现在必须持续有效，不能在构造后切换为不受支持的模式并继续操作。

[准确源码差异](sql-policy-drift-evidence-2026-10-24/source-change.diff)、[原型](sql-policy-drift-evidence-2026-10-24/probe.json)、[修前失败](sql-policy-drift-evidence-2026-10-24/before.log)、[候选通过](sql-policy-drift-evidence-2026-10-24/candidate.log)。修前36项均失败，含12次模拟预处理导致的实际写入；候选36项／180断言通过。

新增测试覆盖自有事务和只读借用、`query`和`metadataRows`、直接主体／准入守卫／时钟回调修改配置，以及模拟预处理、静默和警告模式。SQLite覆盖后两种模式。每次核对只有恢复合法配置后的正常记录可见，事务结束后不残留宿主事务。定向入口接入`tests/mysql_check.py --sql-policy-drift`及常规检查脚本；本批未运行包含暂缓链路的整项目脚本。

九版SQLite相关27程序、九版API清单及静态分析共37步通过。实际ZIP全新离线消费者通过7个准备／来源／执行步骤，包含两端8个MySQL程序及6个SQLite程序；安装不是符号链接，367份SDK／SQL文件逐一匹配。临时资源已清理。九版MySQL相关72程序全部通过；新增配置漂移检查MySQL324例／SQLite216例，共540例通过。

[MySQL专项](sql-policy-drift-evidence-2026-10-24/matrix.json)、[SQLite／API／静态](sql-policy-drift-evidence-2026-10-24/local-checks.json)、[实际消费者](sql-policy-drift-evidence-2026-10-24/consumer/consumer.json)。

## 未采用的优化及默认调用

先前尝试将固定账本上下文由重新准备改为`PDO::query`，实际PHP8.5仍是两次准备／两次执行，没有减少往返。两轮失败均保留，候选未应用到SDK；没有为此切换连接为模拟预处理。原型观察与[PHP8.5驱动源码](https://github.com/php/php-src/blob/PHP-8.5/ext/pdo_mysql/mysql_driver.c)的原生准备路径一致，不将该实验描述为已完成优化。

[初次观察](ledger-context-direct-evidence-2026-10-24/probe.json)、[附源码来源的复核](ledger-context-direct-evidence-2026-10-24/probe-corrected.json)。原型文件移入证据目录保留，不属于正式测试或发行文件。

本批首次默认签发观察与其他自建MySQL测试并行，约3.002秒失败，状态pending／`account.completion_unknown`，未返回凭据，未续办。该结果不能作为隔离性能验收或证明本次修复导致性能变化。其他测试结束并清理后，串行隔离观察仍约3.006秒失败，pending／`account.completion_unknown`；没有重试或续办已失败的操作，两次观察各自使用全新环境。原失败保留。

[并行观察结果](sql-policy-drift-evidence-2026-10-24/default-85-timing.json)、[并行异常栈](sql-policy-drift-evidence-2026-10-24/default-85-run.log)、[串行隔离结果](sql-policy-drift-evidence-2026-10-24/isolated/default-85-timing.json)、[串行异常栈](sql-policy-drift-evidence-2026-10-24/isolated/default-85-run.log)。

默认签发、历史PHP7.2时钟／预算及其他未解释失败、最终非暂缓候选验收仍开放。上述均为定向检查，未称为整项目或稳定版验收；goal保持active。跨安全代际交接、未知回执续办、最终账号恢复启用、完整F01及外部验收未执行。未删除现有数据、撤销既有改动、提交、推送或部署。
