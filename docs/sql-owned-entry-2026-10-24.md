# 原生SQL入口的连续归属证明

本批仅修改 `SqlTransaction.php` 的内部入口：严格原生MySQL路径在没有宿主代码介入的连续调用中使用刚取得的事务归属证明，去除重复探测。没有跨调用缓存、权限结果缓存或期限延长，公开API仍为278。

## 问题及实现

上一批私有MySQL诊断在一次首次签发中记录了2011条保存点命令、153次事务状态查询，不能把开销简单归因于一条SQL。本批从实际调用链确认：`run()` 在没有前置回调时仍执行两次相同的 `assertIdle()`；`inContext()` 确认当前无事务后，进入自建事务分支又重复这两次检查。

[修前日志](sql-owned-entry-evidence-2026-10-24/before.log)实测原生直接入口执行两次 `autocommit` 查询，业务正常完成，针对目标一次查询的断言失败。[修后九版矩阵](sql-owned-entry-evidence-2026-10-24/mysql-matrix.json)中直接入口和 `inContext` 自建入口均为一次查询，前置回调后的重新检查保持。

`run()` 保持原公开签名，转入私有 `owned()`；`inContext()` 的无事务分支仅在探测前后都满足原生门槛时把刚取得的证明传入该方法。证明只作为当前调用的局部参数，不写入实例、连接注册表或缓存。进入实际事务前仍检查期限及当前执行上下文；前置回调一律使原证明失效，重新探测。

原生门槛仍为原生PDO、原生语句类、`SystemClock`、异常模式、原生预处理、无守卫或核对过身份的纯原生守卫，且没有恢复上下文。自定义时钟、PDO／语句适配器、不透明守卫和SQLite继续原流程。语句适配器在探测中切回原生时，不追认此前的证明，仍执行新的完整检查；新检查后原生无回调区间可以去重。

事务归属、保存点、退出恢复、失败实例拒绝、宿主提交责任和共享预算保持。没有修改DDL、持久化格式、默认3000ms签发预算或公开契约清单。

## 本地验证

- PHP7.2—8.5：[MySQL162场景](sql-owned-entry-evidence-2026-10-24/mysql-matrix.json)全部通过。每版18场景覆盖两类原生入口、前置回调正常／拒绝／开启事务、自定义时钟及其开启事务、PDO／语句适配器、语句类切换、不透明守卫、宿主事务、SQL开始的宿主事务和主体失败回滚。除了计数，还验证实际业务执行、独立观察连接、宿主未提交及待提交写入保持。
- [九版SQLite18条程序](sql-owned-entry-evidence-2026-10-24/sqlite-matrix.json)全部通过，覆盖账号账本和81个忙碌／失败／入场改变状态场景。
- [两端相关MySQL](sql-owned-entry-evidence-2026-10-24/related-mysql.json)五条控制器命令全部通过，共194个场景：入口前置检查18、游标失败72、事务见证30、锁等待限制34、当前工作进程上下文40。最后一组只使用初始独立权限，不包含跨安全代际交接。
- [离线归档新消费者](sql-owned-entry-evidence-2026-10-24/consumer/consumer.json)8步骤全部通过，PHP7.2和8.5从实际安装的vendor执行SQLite入口相关测试与各18个MySQL专项。367个运行时／SQL文件逐一摘要相同，无符号链接，反射来源核对通过，自建临时目录与服务器已清理。
- [静态分析](sql-owned-entry-evidence-2026-10-24/phpstan.log)无错误，既有可选turbo扩展GLIBC警告保留；[API278](sql-owned-entry-evidence-2026-10-24/api.log)通过。`bin/check.sh` 只验证Shell语法，未运行完整脚本。

输入见[372文件摘要](sql-owned-entry-evidence-2026-10-24/inputs.json)，其中相对[修前367个运行时／SQL文件](sql-owned-entry-evidence-2026-10-24/before-inputs.json)仅 `SqlTransaction.php` 改变。最终摘要及归档核对见[交付记录](sql-owned-entry-evidence-2026-10-24/delivery.json)。消费者功能检查绑定同一运行时／SQL；文档完成后的最终归档另作内容核对。

## 首次签发与剩余范围

所有上述测试结束后，独立运行一次PHP8.5原生 `SystemClock`／PDO、默认3000ms首次签发。实际约3.222604秒失败，原因 `account.completion_unknown`，见证为pending，详见[时序](sql-owned-entry-evidence-2026-10-24/default/default-85-timing.json)、[原日志](sql-owned-entry-evidence-2026-10-24/default/default-85-run.log)及[清理记录](sql-owned-entry-evidence-2026-10-24/default/default-85-result.json)。其他八版默认签发本批未执行。没有续办未知结果，不用查询次数减少替代正常签发成功，不把不同源码的单次耗时当作性能提升比例。

默认首次签发、历史持续时间时钟倒退及最终非暂缓候选核对尚未全部关闭，goal保持active，本批不是完整项目或稳定版验收。暂缓的跨代交接、未知回执续办、恢复账号最终启用及完整F01未实现或测试，原有源码、审批和失败证据保持。生产数据库、外部投递、真实IdP／设备、远端CI和独立审查未执行。未提交、推送或部署，只清理自行创建的资源。
