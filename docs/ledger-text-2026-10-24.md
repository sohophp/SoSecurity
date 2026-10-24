# 固定文本投影与旧驱动账本语句复用（2026-10-24）

本批继续非暂缓本地产品工作，不改变goal范围。默认签发仍失败，时钟与聚合内存检查仍有失败，不是稳定版或全项目验收通过。

## 修复依据与实现

上一批旧驱动在无法读取STRINGIFY_FETCHES时逐次准备语句。已先逐文件核对：当前修复前367个运行时／SQL文件与上一批准确输入一致，故其PHP7.2准备2次、执行2次的记录仍适用于修复前代码，见[摘要及证据核对](ledger-text-evidence-2026-10-24/before-reuse-verification.json)。本批新的PHP7.2前置复现在初始化时遇持续时间时钟倒退，未测到准备次数，原[失败](ledger-text-evidence-2026-10-24/before-72.log)保留，不伪称测量成功。

[PHP8.5修复前原始类型](ledger-text-evidence-2026-10-24/before-format-85.log)确认关闭STRINGIFY_FETCHES时返回整数／字符串混合字段。最初测试从服务器日志恢复语句时遗漏了问号与命名参数之间的转换，被内部固定查询校验拒绝，见[原失败](ledger-text-evidence-2026-10-24/before-85.log)；只修正测试占位符后才取得上述类型证据，没有为测试放宽校验器。

`SqlSchema::boundedProjection`增加仅MySQL使用的内部文本整数选项：原整数上下界判断保持，判断通过后才CAST AS CHAR。仅已登记、受限原生、且刚完成本次结构／权限复核的账本首屏采用它；正文长度与存在标记也显式输出文本。SQLite及其他默认调用生成的SQL字节保持不变。

`SqlStateAccess`完整匹配这一固定文本查询后，才按已知文本／NULL结果格式复用已关闭的原生语句。结果不再受STRINGIFY_FETCHES影响，因此该专用路径只需核对其仍相关的CASE／ORACLE_NULLS属性；其他元数据查询继续执行原有全部属性检查，旧驱动的通用元数据缓存仍保持降级。专用能力失败另作有界标记，没有把未知属性视为已知，也不对任意SQL启用缓存。

仍每次绑定namespace、执行、读取及关闭游标；不缓存行、正文、账号或授权结果。本次刚读取的数据库名仍直接传给紧接着的私有读取，没有保存跨调用上下文。8条已关闭语句／连接、128个已登记连接及原输入、行数、长度、期限、回调和权限边界保持。公开契约仍278类型，签名数据及SQL资源不变，无数据迁移。三个源码差异：[Ledger](ledger-text-evidence-2026-10-24/Ledger.diff)、[SqlSchema](ledger-text-evidence-2026-10-24/SqlSchema.diff)、[SqlStateAccess](ledger-text-evidence-2026-10-24/SqlStateAccess.diff)。

## 已执行结果

- [九版功能覆盖](ledger-text-evidence-2026-10-24/coverage.json)：162个版本／场景组合中161通过，PHP7.2 permission场景因持续时间时钟倒退失败，未重跑。通过来源是初轮结果与针对修改／未执行场景的补充，不是一次整轮全绿。
- 每版真实MySQL均执行有界文本投影检查：两种STRINGIFY_FETCHES设置下，0、1、PHP_INT_MAX返回文本，超界及负数返回NULL，16／17字节标签边界保持。原生受保护账本的全部25列原始值均为字符串或NULL；公开检查点仍规范化为原整数类型。PHP7.2首次两次读取已实际准备1次、执行2次；两种获取设置下不增加准备或独立数据库名查询。
- 新增65条受保护分页验证，首屏文本投影和后续原路径元数据共同完成全部认证，最后一条正文正确返回。已有篡改、有效写入、撤权、临时表、同结构数据库切换、参数变化、自定义依赖和事务边界场景保留。
- [初轮](ledger-text-evidence-2026-10-24/mysql-matrix.json)六项控制器命令失败、其余通过：PHP7.2时钟倒退、PHP8.3聚合分配峰值断言、四版旧驱动淘汰测试预期问题分别保留。准确退出码以JSON为准。
- 淘汰预设原用普通元数据查询填池，旧驱动该路径不缓存，因而未实际淘汰账本语句。修正为八条符合固定形状、各自完成复核的账本查询，原64条上限查询实际重新准备；没有增加池上限或修改运行时求绿。[补充选择](ledger-text-evidence-2026-10-24/supplement-selections.json)只重测修改的淘汰项及此前未执行项，[28项补充](ledger-text-evidence-2026-10-24/supplement.json)均通过。已通过的普通场景没有重跑；相同输入的SQL投影证据经摘要核对复用，并明确标注未再次执行。
- PHP8.3原聚合进程在eviction后达到8MiB峰值断言失败，见[原日志](ledger-text-evidence-2026-10-24/mysql-php83.log)。补充的独立eviction场景通过，**不能据此关闭原聚合失败或宣称其已通过**。原入口和严格内存断言仍保留，未提高内存限制；具体分配来源尚未定位。
- [九版SQLite及投影53条程序](ledger-text-evidence-2026-10-24/sqlite-matrix.json)全部通过；包括修复前保存的四组完整默认SQL向量、类型家族／别名、SQLite拒绝文本选项、原账本，以及两端初始读取与检查点读取。
- [两端相关MySQL10条命令](ledger-text-evidence-2026-10-24/related-mysql.json)均通过，覆盖原首屏读取、通用元数据缓存、耐久语句、因子首次读取及锁定结构。该结果不关闭本批核心组和消费者中的时钟失败，也不关闭历史失败。
- [原ZIP／离线新消费者](ledger-text-evidence-2026-10-24/consumer/consumer.json)10步骤9通过／1个淘汰预设失败；PHP8.5原18场景均通过。修正后[补充重建](ledger-text-evidence-2026-10-24/consumer-supplement/consumer.json)6步骤5通过／1失败：PHP7.2淘汰、非法上下文通过，事务边界在见证持久化时遇持续时间时钟倒退，未续办、未重跑；PHP8.5修改后的淘汰案例通过。两次全部运行时／SQL摘要匹配、安装无符号链接、vendor反射来源正确、自身资源清理完成。不能称作消费者整轮通过。
- [静态分析](ledger-text-evidence-2026-10-24/phpstan.log)无错误，既有可选turbo扩展GLIBC警告保留；[API278](ledger-text-evidence-2026-10-24/api.log)通过。完整检查脚本只验证Shell语法，不运行其中暂缓套件。

输入：[372文件摘要](ledger-text-evidence-2026-10-24/inputs.json)；测试修正前输入和脚本单独保存。最终核对见[交付记录](ledger-text-evidence-2026-10-24/delivery.json)。所有结论均为定向检查，不是全项目或全部R1—R6验收。

## 默认签发及未执行项

全部相关测试结束后，仅执行一次当前PHP8.5原生SystemClock／PDO默认首次签发：预算3000ms，约3.114980秒失败，状态pending、原因account.completion_unknown。见[时序](ledger-text-evidence-2026-10-24/default-85-timing.json)、[日志](ledger-text-evidence-2026-10-24/default-85-run.log)、[输入及清理](ledger-text-evidence-2026-10-24/default-85-result.json)。没有续办；其余八版默认签发本批未执行，不用旧失败替代当前验证。准备次数减少不能代替签发成功，也不能用不同源码的单轮耗时证明性能提升。

默认签发、时钟倒退、聚合内存断言及其他历史未解释失败、最终非暂缓候选核对仍开放，goal保持active。暂缓的跨代交接、未知回执续办、恢复账号最终启用及完整F01不实现或测试，原有源码、审批和限制保留。生产数据库、外部投递、真实IdP／设备／宿主、远端CI和独立审查未执行。未提交、推送或部署；只清理自行创建的进程和资源。
