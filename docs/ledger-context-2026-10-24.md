# 账号账本上下文证明合并读取

本批保持默认拒绝、当前权限检查、数据库结构锁和原预算，仅在严格原生 MySQL 路径将账本双表解析证明与上下文／触发器可见性证明合为一条语句。不是完整项目验收，默认首次签发仍失败，goal 保持 active。

## 修复及兼容

修复前，每次 `ledgerSchemaContext()` 分别执行零行双别名连接和两行上下文查询。修后将前者作为零行派生表与后者连接；没有缓存权限、表结构或查询结果。两次调用的 Execute 数量由4变为2，见[修前失败](ledger-context-evidence-2026-10-24/before.log)、[源码差异](ledger-context-evidence-2026-10-24/SqlSchema.diff)。

只有现有 `canBatchLedgerReads()` 接受的原生 PDO、原生语句类、原生时钟及纯原生守卫使用合并语句。自定义时钟、PDO／语句适配器、不透明守卫保持原两步流程；恢复上下文不启用。两张实际表仍分别解析两次，拒绝临时表替代，并要求当前 SELECT／触发器可见性权限。两表结构锁持续到事务结束。公开 API 实查278个类／接口，未更新契约清单；DDL、持久化格式、池容量和默认期限不变。

另修正 `ledger-statements.php` 的8MiB边界断言：原测试在实际已用5,779,528字节、分配恰为8,388,608字节时，由于严格小于判断而失败。现在同时断言实际 `memory_limit` 为8M、实际使用和分配峰值均不超过8MiB。没有提高预算或改变库实现，也没有声称降低内存；[原失败](ledger-context-evidence-2026-10-24/related-ledger-statements-83.log)和[修前测试](ledger-context-evidence-2026-10-24/ledger-statements.before-memory-boundary.php)保留。

## 已执行的定向验证

- [MySQL九版矩阵](ledger-context-evidence-2026-10-24/mysql-matrix.json)：PHP7.2—8.5共117场景全部通过。覆盖原生路径、四类兼容路径、两张临时表、真实触发器、分别撤销两表权限、触发器可见性撤销、数据库切换，以及另一连接对两张表执行 ALTER 均超时的实际结构锁检查。
- [SQLite九版矩阵](ledger-context-evidence-2026-10-24/sqlite-matrix.json)：18条程序全部通过，覆盖默认投影兼容与账号账本。
- [相关MySQL原轮](ledger-context-evidence-2026-10-24/related-mysql.json)：9条命令6通过／3失败。PHP7.2账本非法上下文与首次读取正常场景分别遇持续时间时钟倒退；PHP8.3聚合进程遇上述严格内存断言。原失败全部保留。
- 内存断言修正后，[PHP8.3完整18场景](ledger-context-evidence-2026-10-24/memory-boundary-83.log)通过，分配峰值仍为8MiB。另仅补执行此前未运行的[PHP7.2事务边界](ledger-context-evidence-2026-10-24/transaction-boundary-72.log)及[五个首次读取场景](ledger-context-evidence-2026-10-24/unexecuted-initial-72.log)，均通过；没有重跑两项时钟失败，不能据此把原轮写为全绿。
- [归档及离线全新消费者](ledger-context-evidence-2026-10-24/consumer/consumer.json)：10步骤全部通过。安装包运行时／SQL文件逐一摘要匹配，无符号链接，反射确认使用 vendor 内代码；PHP7.2和8.5覆盖SQLite账本、投影及各13个MySQL上下文场景。只清理自身临时目录和服务器。
- [静态分析](ledger-context-evidence-2026-10-24/phpstan.log)无错误，既有可选turbo扩展GLIBC警告保留；[公开API检查](ledger-context-evidence-2026-10-24/api.log)278通过。完整 `bin/check.sh` 仅检查Shell语法，没有执行其暂缓套件。

输入绑定见[371个文件摘要](ledger-context-evidence-2026-10-24/inputs-final.json)，最终核对见[交付记录](ledger-context-evidence-2026-10-24/delivery.json)。消费者功能验证绑定相同运行时和SQL；文档落盘后的归档另核对打包内容，没有无依据重复安装测试。

## 默认签发与诊断

当前PHP8.5原生 `SystemClock`／PDO、默认3000ms首次签发约3.363614秒失败，原因 `account.completion_unknown`，见证为 pending。见[计时](ledger-context-evidence-2026-10-24/default-85-timing.json)、[原日志](ledger-context-evidence-2026-10-24/default-85-run.log)及[输入与清理](ledger-context-evidence-2026-10-24/default-85-result.json)。没有续办未知结果，其他八版默认签发本批未执行。不得用查询数量减少替代正常签发成功，也不以不同源码的单次耗时宣称性能提升。

随后仅在新建私有MySQL中采集首次签发的服务器语句类别、计数和耗时，不修改SDK、时钟或预算，不导出参数、SQL正文和业务记录。首份[诊断](ledger-context-evidence-2026-10-24/profile/sql-profile.json)的原生预处理事件没有可用SQL正文，主要落入other，不能据此定位具体查询。补充[分类采集](ledger-context-evidence-2026-10-24/profile-categories/sql-profile.json)使用仅该私有实例的服务器日志在服务端聚合查询类别。诊断有额外开销，两份计时均不能作为性能验收成绩；正常默认签发失败记录仍独立保留。

默认首次签发、持续时间时钟倒退及最终非暂缓候选核对仍开放。跨安全代际工作进程交接、未知回执续办、恢复账号最终启用及依赖它们的完整F01未实现或测试；已有源码、审批、隔离和失败证据保持。生产数据库、外部投递、真实IdP／设备／宿主、远端CI和独立审查未执行。未提交、推送或部署。
