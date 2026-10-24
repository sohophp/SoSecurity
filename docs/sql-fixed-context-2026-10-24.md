# 固定账本上下文的事务见证

本批在明确的内部账本查询中减少一次重复事务见证，任意宿主回调继续保留前后检查。实际修改 `SqlTransaction.php` 与 `Ledger.php`，未改变公开API278、DDL、持久化格式或默认预算。

## 问题与实现

[修前日志](sql-fixed-context-evidence-2026-10-24/before.log)确认，同一事务内第二次账本结构验证在固定上下文查询前后各刷新一次见证，计数为2；正常业务已经完成，但目标一次刷新的断言失败。修后严格原生路径为1，仍在查询前确认原保存点存在。

新增的 `verifyLedgerSchema()` 属于既有内部类型 `SqlTransaction`，固定执行耐久性、规范双表结构和 `SqlSchema::ledgerSchemaContext()` 检查，不接受调用者回调。`Ledger` 只接收这次检查刚取得的数据库名并传给紧接着的私有读取，不新增上下文或结果缓存。原通用 `verifySchema()` 的签名和返回void保持。

仅当固定查询前后均满足原有严格原生门槛时，省去查询后的重复见证；原生PDO、原生语句、原生时钟及纯原生守卫之间没有宿主代码可以替代事务。自定义时钟、PDO／语句适配器、不透明守卫、SQLite及恢复上下文保留原流程。通用回调无论返回什么，始终执行原有前后见证；回调结束或替代事务仍拒绝继续。

两表解析、当前权限／触发器可见性、结构锁、完整历史认证、正文读取、游标关闭、八条语句池上限和预算均保持。公开契约清单未重新生成。

## 定向证据

- [九版MySQL专项](sql-fixed-context-evidence-2026-10-24/mysql-matrix.json)：PHP7.2—8.5共81场景全部通过。覆盖原生固定查询、四类兼容路径、普通通用回调、回调提交后开启新事务、回调抛异常，以及真实原生时钟下的1秒预算超时。核对见证次数、业务完成状态、错误脱敏、实际提交／回滚及独立观察连接。
- [九版SQLite](sql-fixed-context-evidence-2026-10-24/sqlite-matrix.json)：18条程序全部通过，覆盖账本及81个SQL入口前置检查场景。
- [相关MySQL](sql-fixed-context-evidence-2026-10-24/related-mysql.json)：五条控制器命令全部通过，包括九版锁定结构126场景，两端上下文26场景，PHP7.2／8.3／8.5账本语句54场景及6个辅助检查，两端原生入口36场景，当前工作进程上下文40场景。后者只涉及初始独立权限，不涉及跨安全代际交接。既有PHP7.2时钟失败没有在本轮复现，不代表历史原因已查明。
- [最终源码离线消费者](sql-fixed-context-evidence-2026-10-24/consumer/consumer.json)：8步骤全部通过。实际归档安装后逐一核对367个运行时／SQL文件摘要，无符号链接，反射确认vendor来源；PHP7.2和8.5执行SQLite相关入口及各9个MySQL专项。自身临时资源已清理。
- [API278](sql-fixed-context-evidence-2026-10-24/api.log)通过；[最终静态分析](sql-fixed-context-evidence-2026-10-24/phpstan.log)无错误，既有可选turbo扩展GLIBC警告保留。完整检查脚本只验证Shell语法。

初轮[静态分析失败](sql-fixed-context-evidence-2026-10-24/phpstan-before-purity-tag.log)指出分析器把读取可变PDO属性的 `canBatchLedgerReads()` 记为纯函数，因而认为回调后的第二次观察恒定。补充 `@phpstan-impure` 后通过，没有修改规则、参数类型或删除检查。功能矩阵执行时的[372文件摘要](sql-fixed-context-evidence-2026-10-24/inputs-before-purity-tag.json)与[最终摘要](sql-fixed-context-evidence-2026-10-24/inputs.json)只差该PHPDoc注释；[可执行token核对](sql-fixed-context-evidence-2026-10-24/purity-tag.json)一致。因此没有为注释修改重复运行整轮功能矩阵；后续消费者和默认签发使用最终字节。

另对PHP7.2及8.5各作20,000次只读时钟采样，见[7.2](sql-fixed-context-evidence-2026-10-24/clock-72.json)及[8.5](sql-fixed-context-evidence-2026-10-24/clock-85.json)。未观察到倒退，未修改环境或替换SDK时钟；这份诊断既不能解释历史倒退，也不能把其归为已解决或已证实的环境问题。

最终打包和证据收集见[交付记录](sql-fixed-context-evidence-2026-10-24/delivery.json)。本批没有实现或运行暂缓的跨代交接、未知回执续办、恢复账号最终启用及完整F01；已有源码、审批及失败证据保持。生产数据库、外部投递、真实IdP／设备、远端CI和独立审查未执行。未提交、推送或部署。

## 默认首次签发

全部专项、相关检查和消费者结束后，独立执行一次最终源码PHP8.5原生 `SystemClock`／PDO、默认3000ms首次签发。实际约3.198944秒失败，原因为 `account.completion_unknown`，见证为pending。详见[计时](sql-fixed-context-evidence-2026-10-24/default/default-85-timing.json)、[日志](sql-fixed-context-evidence-2026-10-24/default/default-85-run.log)及[清理](sql-fixed-context-evidence-2026-10-24/default/default-85-result.json)。其他八版默认签发本批未执行。不续办未知结果，不用减少查询或见证次数代替签发成功。

默认首次签发、历史时钟倒退和最终非暂缓候选核对尚未全部关闭，goal保持active。本批不是全项目或稳定版验收。
