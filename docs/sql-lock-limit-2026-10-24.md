# SQL锁等待的入口去重与SQLite零等待

本批继续处理非暂缓本地缺口，只修改 `SqlTransaction`。原生MySQL可以省去确定无效的入口同值设置，退出仍恢复原值；SQLite显式零等待不再被提高为1毫秒。公开API278、DDL、持久格式、默认时间预算及语句池上限保持。见[差异](sql-lock-limit-evidence-2026-10-24/runtime.diff)、[最终输入](sql-lock-limit-evidence-2026-10-24/inputs-delivery.json)。

## 确认与实现

原实现即使刚读到的innodb_lock_wait_timeout已经等于本次限制，仍在入口和退出各发送一次同值SET。私有MySQL实际记录2次，期望只保留退出恢复的断言失败，见[修前记录](sql-lock-limit-evidence-2026-10-24/before.log)。

现在只对SystemClock、准确原生PDO／PDOStatement、异常模式、原生预备语句及已知无宿主回调的入口守卫省去同值入口SET。读取前后均确认这些条件；实际配置仍每次重新读取、校验并关闭游标，超出本次预算时仍设置较小值。退出恢复不去重，因为业务回调可能改变连接配置。恢复专用单元、自定义时钟／PDO／语句和未知守卫保留原设置路径，不涉及暂缓的恢复实现或测试。

专项另让自定义语句在读取后把会话值改为11，并切回原生语句类；读取前已发现自定义类，因此仍强制设置1，业务实际读取1。这个样例说明不能仅检查读取后的类型。正常、加入／拥有事务、回调修改值及抛错后的恢复和复用均验证。

独立SQLite复现显示：调用方设busy_timeout=0，单元内却读到1，退出才恢复0，见[修前失败](sql-lock-limit-evidence-2026-10-24/zero-sqlite-before.log)。计算现在先限定预算，再取原设置与预算的较小值，拥有、加入及上下文选择路径均保留0，原已正确的借用路径保持。[SQLite文档](https://www.sqlite.org/c3ref/busy_timeout.html)说明非正值关闭等待处理器；这是保留调用方的更严格配置。

MySQL的零值检查最初预期错误：本机服务器在进入SDK前已把请求0规范化为1，官方[innodb_lock_wait_timeout](https://dev.mysql.com/doc/refman/8.0/en/innodb-parameters.html#sysvar_innodb_lock_wait_timeout)最小值也是1。它不是SDK将0提高为1的证据。原[错误预期](sql-lock-limit-evidence-2026-10-24/test.zero-oracle.php)、[日志](sql-lock-limit-evidence-2026-10-24/zero-mysql-before.log)及首轮矩阵保留；修正测试分别核对请求值、服务器实际值和SDK内值。没有把MySQL描述为支持零秒等待，也没有放宽产品保护。

## 最终候选的验证

- 九版MySQL17×9＝153场景通过，见[最终矩阵](sql-lock-limit-evidence-2026-10-24/matrix-delivery.log)。涵盖服务器规范化、原生拥有／加入／上下文选择、回调修改配置、回调失败、需要收紧的原值、各种降级及语句类型切换。原生同值路径只有退出的1次SET，自定义路径仍2次；结束后原设置及宿主事务归属保持。
- 九版SQLite36条程序通过，包括零等待5×9＝45场景、原配置读取故障216场景及原上下文／账本18条程序，见[结果](sql-lock-limit-evidence-2026-10-24/sqlite-final.json)。这些程序未执行MySQL测试文件；后者修正预期后，运行时、SQL及已执行SQLite文件摘要仍一致，见[核对](sql-lock-limit-evidence-2026-10-24/sqlite-input-verification.json)。
- 两端私有MySQL既有锁等待68、当前登记工作进程40、保存点见证30、锁定结构证明28场景通过，见[相关命令与结果](sql-lock-limit-evidence-2026-10-24/regressions.json)。仅使用当前进程／初始状态，不运行跨代交接。
- 两端真实ZIP／离线全新消费者原10步8通过／2步失败，失败均为上述MySQL零值预期。修正后仅重建安装及补验MySQL，补充6步通过；原SQLite账本与零等待步骤未重跑。两次安装的运行时及SQL资源摘要完全相同，vendor反射来源、非符号链接安装和自身清理均确认。原[消费者](sql-lock-limit-evidence-2026-10-24/consumer/consumer.json)、[补充](sql-lock-limit-evidence-2026-10-24/consumer-supplement/consumer.json)分别保留；不能写成一次完整重跑全绿。
- PHPStan无错误，既有可选turbo扩展GLIBC警告保留；公开API278契约通过，见[静态](sql-lock-limit-evidence-2026-10-24/static-final.log)、[API](sql-lock-limit-evidence-2026-10-24/api-final.log)。完整开发检查脚本只检查语法，不运行其中暂缓套件。

入口去重阶段的135场景及27条SQLite程序绑定其原输入；后续零等待修复和修正测试的最终结果以上述记录为准。没有提高预算、缓存配置／权限结论或删除失败测试。测试只操作自建临时资源、私有MySQL及自身进程。

## 兼容与未关闭范围

SQLite显式0现在在单元内保持0，可能更早返回SQLITE_BUSY，退出仍恢复原设置。MySQL原生同值入口减少一次SQL命令；退出恢复、故障拒绝、游标处理、权限／事务复核及其他配置行为保持。没有新增公开方法或改变候选契约。

所有相关测试结束后，准确当前候选的SystemClock／原生PDO默认首次签发仍约3.013090秒失败，预算3000ms；在issueInternal第二次actor的复核中到期，pending／account.completion_unknown保留，未续办。见[时序](sql-lock-limit-evidence-2026-10-24/default-85-timing.json)、[日志](sql-lock-limit-evidence-2026-10-24/default-85-run.log)、[输入及清理](sql-lock-limit-evidence-2026-10-24/default-85-result.json)。入口命令减少的专项结果不等于完整签发加速或成功，不能据单次耗时推导稳定性能提升。

这些是专项，不是全项目验收。历史时钟及其他未解释失败、默认首次签发和最终非暂缓候选核对仍未关闭；暂缓链路及外部验收未执行，goal保持active。未提交、推送、部署、访问生产数据库或外部投递。见[交付汇总](sql-lock-limit-evidence-2026-10-24/delivery.json)和[准确命令](sql-lock-limit-evidence-2026-10-24/commands.json)。
