# SQL事务入口的游标关闭检查

已确认并修复 `SqlTransactionGuard` 对 MySQL `autocommit` 查询忽略关闭失败的问题。关闭返回 false 或抛异常时，现在拒绝事务入口；执行或读取失败后，也显式尝试关闭已取得的语句。只修改该运行时文件，其他历史改动保留。

## 复现和修改

[修前日志](sql-guard-cursor-evidence-2026-10-24/before.log)先通过六种正常入口，再证明 `closeCursor()` 返回 false 时 `assertIdle()` 仍成功返回，违反测试要求的失败拒绝。测试使用自行创建的私有MySQL、实际事务和独立观察连接，语句类只注入指定故障。

修复增加私有读取方法，集中完成错误脱敏和显式关闭检查。`assertIdle()` 保持原 `prepare`／`execute`，`active()` 保持原 `query`，没有改变PDO适配器调用形式；没有缓存事务状态、跳过保存点、提高预算或改变宿主事务。新增关闭失败沿用 `storage.transaction_state`；`enlist`／`inContext` 仍按既有逻辑将入口不确定性标记为 `sql.cleanup`，要求重建服务。

已消费但未确认关闭的语句不再被视为成功检查，这是有意收紧。正常调用、SQLite路径、公开API278、DDL和持久化格式保持。

## 验证

- [九版MySQL专项](sql-guard-cursor-evidence-2026-10-24/mysql-matrix.json)：PHP7.2—8.5共324场景通过，每版36场景。覆盖正常、关闭返回false／抛异常、读取抛异常、执行返回false／抛异常，以及 `assertIdle`、`active`、`assertActive`、`run`、`enlist`、`inContext` 六种入口。断言适配器调用形式、显式关闭次数、错误不含私密标记、故障时业务主体未执行、宿主未提交／未回滚及独立观察连接未见业务数据。
- [相关MySQL](sql-guard-cursor-evidence-2026-10-24/related-mysql.json)九版81场景通过；[SQLite](sql-guard-cursor-evidence-2026-10-24/sqlite-matrix.json)九版81场景通过，覆盖忙碌／失败实例及入场守卫改变状态后的拒绝。
- [静态分析](sql-guard-cursor-evidence-2026-10-24/phpstan.log)无错误，既有可选turbo扩展GLIBC警告保留；[公开API](sql-guard-cursor-evidence-2026-10-24/api.log)278通过。完整检查脚本仅检查Shell语法。
- [离线归档新消费者](sql-guard-cursor-evidence-2026-10-24/consumer/consumer.json)验证实际发行包与当前运行时／SQL逐文件摘要、非符号链接安装及vendor反射来源，PHP7.2和8.5执行上述专项和SQLite相关场景。结果及自身临时资源清理以该文件和[最终交付记录](sql-guard-cursor-evidence-2026-10-24/delivery.json)为准。

中间候选把 `active()` 改成了显式prepare，随后恢复原query形式，以保持适配器兼容。该候选的[原日志](sql-guard-cursor-evidence-2026-10-24/mysql-matrix.log)另暴露测试对异常链的错误预期：PHP在finally抛出 `sql.cleanup` 时会带上先前已脱敏的异常。修正后对所有错误完整字符串检查私密标记，直接入口继续断言无前置异常；没有删除故障场景或吞掉业务失败。[初始测试](sql-guard-cursor-evidence-2026-10-24/test.initial.php)和[中间源码](sql-guard-cursor-evidence-2026-10-24/SqlTransactionGuard.php.prepare-candidate)保留，最终九版重新运行。

输入见[371个文件摘要](sql-guard-cursor-evidence-2026-10-24/inputs.json)。本批是独立错误处理修复，未再次执行默认首次签发性能实验；[上批默认3000ms首次签发失败](ledger-context-2026-10-24.md)绑定上批源码，不能当作本批候选已测结果，也不能因此关闭默认签发缺口。

默认首次签发、历史持续时间时钟倒退及最终非暂缓候选核对仍开放，goal保持active，不宣称稳定版完成。跨代交接、未知回执续办、恢复账号最终启用和完整F01未运行；完整SQL enlistment套件含未知结果重放，本批也未执行。未访问生产数据库、外部投递或执行提交／推送／部署；仅清理自行创建的资源。
