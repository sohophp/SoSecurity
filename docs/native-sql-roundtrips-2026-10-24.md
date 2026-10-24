# 原生SQL往返合并与预算验证

本轮围绕默认首次签发超时连续完成两项内部优化：账本耐久性与当前上下文合并读取、借读入口的会话设置合并。保留每次新读、当前权限与工作进程检查、原值恢复、清理失败传播及默认3000ms预算。没有新增产品功能、公开参数、类型或存储格式；公开清单仍为278类／接口。

## 账本当前上下文与耐久性

准确原生PDO／SystemClock／默认语句／纯入口守卫下，固定双表当前上下文SQL同时读取`@@GLOBAL.innodb_flush_log_at_trx_commit`并验证为1，代替之前独立的耐久性SELECT。同一事务的两次账本检查，独立耐久性执行从2次降为0次；要求本身仍逐次验证，没有把它存进结构缓存。数据库名、主体、逐表权限、触发器、双别名物理表解析、完整账本认证及元数据锁保持。自定义时钟／PDO／语句的账本检查继续独立读取耐久性。

直接调用`SqlSchema::ledgerSchemaContext`现在同样要求耐久性配置有效，异常代码为原有`configuration.sql_durability`；签名及仅含`database`的返回结构保持。完整账本原先已要求这一条件，不把直接辅助方法的新检查描述为原有完整账本授权漏洞。多个配置同时损坏时，拒绝原因的先后可能变化。新增的非原生读取异常经脱敏；关闭不确定仍使单元失效。

首批源码快照在九版PHP7.2—8.5执行MySQL81程序／1503个定向检查节，通过；新检查8种配置或错误情况共72节，包含180次耐久性0／2拒绝及恢复为1后的正向检查。SQLite相关18程序、API九版278类型及静态分析通过。原型首轮测试没有清理嵌套witness目录而失败，两个本次创建的目录已逐一核对并清理，修正后原型通过，证据保留。

该批实际ZIP消费者22程序20通过／2个SQLite程序未执行成功，原因是运行器漏复制测试支撑文件`sql-enlistment-support.php`，不是发行包缺少运行时文件。补齐支撑后，重新离线安装，仅补验受影响的两个SQLite程序，通过；原7步骤5通过／2失败和补验6步骤通过分别保存。两轮367份SDK／SQL文件摘要相同。首批快照之后的事务入口又有改动，不能把该81程序声称为最终源码的整项目验收。

[首批输入与结果](ledger-durable-context-evidence-2026-10-24/delivery.json)、[MySQL](ledger-durable-context-evidence-2026-10-24/matrix.json)、[SQLite／API／静态](ledger-durable-context-evidence-2026-10-24/local-checks.json)、[原消费者](ledger-durable-context-evidence-2026-10-24/consumer/consumer.json)、[SQLite消费者补验](ledger-durable-context-evidence-2026-10-24/consumer-sqlite-corrected/consumer.json)。

## 借读入口设置与真实延迟

准确原生条件下，一次新读两个会话等待值，完整捕获并检查原值后，用一条`SET SESSION`设置两个收紧值。完成首次传输后重新计算元数据等待的剩余秒数；若跨秒，追加一次更紧的设置。自定义依赖与SQLite保留原逐项路径。退出继续完整恢复两个原值；恢复失败拒绝父子单元继续。

新增本地Unix套接字代理只对控制器自建MySQL原样转发数据，不保存认证数据；按固定命令延迟1.1秒或关闭该测试连接。PDO及SystemClock均为实际原生对象。五个场景验证：普通入口由两条设置变为一条；3秒子预算的第一传输跨秒后，主体看到行锁3秒／元数据2秒；1秒子预算到期不进入主体、恢复原值且父单元仍可合法继续；入口／恢复连接中断后无后续业务提交、失败实例拒绝复用。没有通过模拟PDO来假定原生传输行为，没有提高SDK预算。

最终执行代码的九版MySQL共54条驱动命令，触发90个PHP进程／738个定向检查节，通过，含45次真实延迟／断连案例；相关覆盖会话读取、0／1等待恢复、恢复错误、元数据等待和前述耐久性新检查。SQLite相关36程序及九版API278通过。PHPStan首轮报告引用参数输出类型，补充`@param-out int $row`后通过；输入仍允许null，捕获失败的清理逻辑保持。用法按[PHPStan官方说明](https://phpstan.org/error-identifiers/parameterByRef.unusedType)核对，没有加入忽略规则。

正式运行及消费者完成后，SDK末次仅补充类型与注释，PHP可执行token保持，其他366份运行时／SQL文件字节保持。实际ZIP全新离线消费者20条驱动命令／28个PHP进程通过，包含两端10次原生传输案例；7个准备／来源／运行步骤通过，367份运行时／SQL文件逐一匹配其实际源码快照，安装不是符号链接。所有本次进程、代理、数据库实例和临时目录已清理。

[最终专项与输入](native-wait-entry-evidence-2026-10-24/delivery.json)、[MySQL](native-wait-entry-evidence-2026-10-24/matrix.json)、[SQLite／API及首轮静态](native-wait-entry-evidence-2026-10-24/local-checks.json)、[最终静态](native-wait-entry-evidence-2026-10-24/static-final.log)、[执行代码核对](native-wait-entry-evidence-2026-10-24/token-equivalence.json)、[归档消费者](native-wait-entry-evidence-2026-10-24/consumer/consumer.json)。

## 默认调用仍失败与未关闭事项

首项优化后，实际SystemClock／PDO、默认3000ms首次符合授权签发仍约3.005秒失败，pending／`account.completion_unknown`，未续办。包含入口优化的最终执行代码约3.119秒失败，状态为current，原因改为`account.operation_timeout`；已走完首次工作后的完成阶段，在进入只读`api.credentials.audit_check`的期限检查处拒绝，未向调用方返回凭据。current不代表整个接口成功，最终审核仍未通过。两次检查前均有一次明确准入拒绝，位置提示数为1，不声称完全无预热冷路径。

见[首项默认失败](ledger-durable-context-evidence-2026-10-24/default-85-timing.json)、[最终默认结果](native-wait-entry-evidence-2026-10-24/default-85-timing.json)及[最终异常栈](native-wait-entry-evidence-2026-10-24/default-85-run.log)。预算失败截断了剩余工作，不把两次耗时直接当成完整耗时的性能对比。没有重试或续办该操作，没有删除安全检查来获得绿色结果。

默认预算下的完整签发、历史PHP7.2时钟／预算失败、其他未解释失败及最终非暂缓候选验证仍开放。goal保持active；上述均为限定专项，不是全项目或稳定版验收。跨安全代际交接、未知回执续办、最终账号恢复启用、完整F01及外部验收未执行；未提交、推送、部署。
