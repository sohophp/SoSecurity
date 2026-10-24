# SQL锁等待配置的关闭检查与原生语句复用

本批修复 `SqlTransaction` 对锁等待配置查询忽略显式游标关闭结果的问题，并让已登记原生 MySQL 连接复用该固定查询的已关闭预备语句。每次仍执行查询、读取当前会话值；不缓存配置或权限判断，不修改默认预算。输入和汇总见[最终摘要](sql-lock-timeout-evidence-2026-10-24/inputs-final.json)、[结果](sql-lock-timeout-evidence-2026-10-24/delivery.json)。

## 确认及修复

原路径直接 `query(...)->fetchColumn()`，没有检查 `closeCursor()`。受控 SQLite 语句报告关闭失败时，业务主体仍执行1次且没有错误，见[修前失败](sql-lock-timeout-evidence-2026-10-24/before.log)。测试只操作自己创建的数据库。

现在拥有事务、加入宿主事务及借用只读单元均先消费结果并显式关闭游标，只接受一行一列非负整数。关闭返回false或抛异常时，业务不执行，单元失效并返回 `sql.cleanup`；借用子单元同时使拥有者失效。读取失败或畸形结果也在主体前拒绝，成功关闭的单元在实际回滚／清理后仍可复用。正常路径仍收紧锁等待时间，并在完成时恢复原值；不对不确定的清理结果继续操作连接。

MySQL固定查询 `SELECT @@SESSION.innodb_lock_wait_timeout` 进入原八槽语句池，只有准确原生PDO／语句、异常模式、原生预备语句和可核对的取值配置允许复用。它与固定持久性变量查询一样不依赖准备时的数据库；其余元数据查询继续新读DATABASE()。语句使用期间先从池移除，消费和关闭成功后才可返回池；不增加槽位，不启用连接选项。旧驱动不支持相关配置读取时保持逐次准备。

既有持久性故障测试的语句类原来对所有查询报告关闭失败；本批把它精确限定为该测试要覆盖的持久性查询，避免新的前置检查在到达目标之前截断测试。对应20场景仍通过，未删除或放宽产品校验。

## 已执行并通过

- PHP7.2—8.5 SQLite新增24×9＝216场景，覆盖三种事务路径、正常处理、关闭返回false／抛异常、读取异常、空结果、多行、多列和负数；另执行既有上下文／账本18条程序。见[SQLite结果](sql-lock-timeout-evidence-2026-10-24/sqlite.json)。
- 九版私有MySQL新增306场景：相同故障和形状检查216场景，语句复用90场景。后者检查当前会话值改变、切库、取值配置、八槽淘汰、自定义PDO／语句、无缓冲及重入。PHP8.2—8.5普通原生路径准备1次、执行3次；PHP7.2—8.1准备／执行各3次。重入移出池及淘汰均实际验证。见[矩阵](sql-lock-timeout-evidence-2026-10-24/mysql-matrix.log)。
- PHP7.2／8.5私有MySQL既有持久性20场景、元数据语句2条程序、当前登记工作进程40场景、锁定结构证明28场景、事务见证30场景通过。只检查当前进程正常上下文，不涉及跨代交接。见[命令与结果](sql-lock-timeout-evidence-2026-10-24/regressions.json)。
- 两端实际ZIP／离线全新Composer消费者10步通过，新专项116场景及原账本2条程序通过。确认非符号链接vendor来源、全部运行时／SQL资源摘要一致，临时资源已清理。见[消费者](sql-lock-timeout-evidence-2026-10-24/consumer/consumer.json)及[运行器](sql-lock-timeout-evidence-2026-10-24/consumer.py)。
- PHPStan无错误，已有可选turbo扩展GLIBC警告保留；公开API仍278类型，契约未修改。见[静态分析](sql-lock-timeout-evidence-2026-10-24/static-final.log)、[API](sql-lock-timeout-evidence-2026-10-24/api.log)。完整开发检查脚本仅检查语法，不运行其中暂缓套件。

开发失败均保留：首轮烟测错误地要求整个异常链无previous，实际链中只有已脱敏的SDK错误；改为检查整个输出无测试私密标记，错误种类和拒绝断言保持。MySQL首轮计数混入测试自身的观察查询，随后给观察语句加固定注释区分，未修改运行时以适配计数。SQLite27条程序均通过，但运行器末尾全输入断言发现未执行的MySQL计数测试文件正在修正；[独立核对](sql-lock-timeout-evidence-2026-10-24/sqlite-input-verification.json)确认运行时、SQL和该27条程序实际使用的测试没有变化，原摘要与最终摘要分别保留。静态分析首次使用不存在的vendor/bin路径，未执行分析，改用项目现有tools路径后通过。

## 已执行但失败、未执行及兼容变化

准确当前候选的真实SystemClock／原生PDO默认首次签发仍约3.019251秒超时，3000ms预算；在第二次actor的会话复核阶段到期，见证保留pending，外层返回account.completion_unknown，没有续办。见[时序](sql-lock-timeout-evidence-2026-10-24/default-85-timing.json)、[原始日志](sql-lock-timeout-evidence-2026-10-24/default-85-run.log)、[摘要及清理](sql-lock-timeout-evidence-2026-10-24/default-85-result.json)。该次与独立本地隔离回归同时运行，不与历史耗时作性能对比，不据语句准备次数减少宣称默认签发已经修复。

公开签名、DDL、持久格式、八槽上限和时间／资源预算保持。可观察变化是关闭失败现在使单元失效，畸形标量结果不再只取第一值继续执行，准确原生会话查询可能复用语句。有效配置仍每次读取并恢复。历史时钟及其他未解释失败、默认签发、最终非暂缓候选核对继续开放，goal保持active；这些专项不是整项目或稳定版验收。

跨代工作进程交接、未知回执续办、最终恢复启用及完整F01未实现或测试。外部验收未执行，未提交、推送、部署、访问生产数据库或外部投递。运行时增量见[事务差异](sql-lock-timeout-evidence-2026-10-24/SqlTransaction.php.diff)、[语句池差异](sql-lock-timeout-evidence-2026-10-24/SqlStateAccess.php.diff)，精确命令见[命令记录](sql-lock-timeout-evidence-2026-10-24/commands.json)。
