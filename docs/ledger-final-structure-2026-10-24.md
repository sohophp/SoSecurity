# 账本结构证明的类型隔离与最终回调复用

本批继续处理默认签发缺口，完成两个相关内部修复：区分固定账本证明与通用结构证明；在准确原生MySQL、同一活跃事务和原事务见证仍有效时，让固定账本的结构证明保留至提交／释放前的最后回调。每次仍重新读取当前数据库、主体、直接元数据权限、触发器、耐久性并重新解析两表双别名；事务见证、完整账本历史认证及超时检查保持。没有缓存权限、账号、会话、工作进程或根记录。

原实现仅以缓存键和上下文识别证明。通用`verifySchema`使用同一`account-ledger-v1`键及数据库上下文时，固定账本校验可能误用该通用证明。新增测试将根表字段改为错误类型并提供通用证明，修前在本应拒绝的位置仍进入后续阶段；修后在该阶段前拒绝。此处是内部证明隔离缺陷，不将其夸大为已经复现的远程攻击或凭据泄露。

缓存条目现在带固定／通用类型标记，命中时要求类型一致。最终回调前后只保留本事务见证下的固定账本条目，通用证明仍失效，缓存仍限8项。回调切换数据库、改变语句类型、引入临时表、撤销有效权限、关闭耐久性或结束事务时继续拒绝或执行完整校验。SQL提交／回滚、普通写入及失败清理边界不变。

SDK仅修改`src/Support/SqlTransaction.php`，其他366份SDK／SQL摘要保持。公开API278、签名、DDL、存储格式及默认3000ms凭据预算保持。兼容变化是同键通用证明不能再替代固定证明，错误结构会更早拒绝；合法固定账本的完整结构观察在最终回调中由2次减为1次，权限观察仍逐次执行。

[源码差异](ledger-final-structure-evidence-2026-10-24/source-change.diff)、[类型标记原型](ledger-final-structure-evidence-2026-10-24/probe-marker.json)、[修前记录](ledger-final-structure-evidence-2026-10-24/before-marker.log)、[候选记录](ledger-final-structure-evidence-2026-10-24/candidate-marker.log)。原型30场景通过；伪装证明的负向断言同时核对后续阶段计数为0，不能只看最终异常。

## 专项及测试修正

新场景覆盖自有／宿主事务、原生／自定义时钟或语句、通用证明失效、错误数据库结构、两种临时表、两表SELECT有效撤销、TRIGGER元数据权限、耐久性、事务被结束及证明类型混用。九版MySQL初轮74程序65通过／9项旧locked-schema初始化失败；专用控制器补验这9程序全部通过，按74程序范围取得通过覆盖。新增30场景在九版共270项通过；SQLite相关27程序、九版API及静态分析37步通过。

首轮测试错误地假定数据库级SELECT撤销立即改变既有连接的执行权限；原源码和候选均未拒绝该连接。按[MySQL8.0官方生效规则](https://downloads.mysql.com/docs/mysql-security-excerpt-8.0-en.pdf)，表／列权限变更于下一次请求生效，数据库权限变更则在下一次USE时生效。修正测试先给两表直接SELECT，再于最后回调撤销目标表权限，继续要求立即拒绝。没有给SDK额外权限，也没有要求它改写宿主连接状态。首轮异常预期也修正为已有清理状态不确定的`sql.cleanup`；原失败和测试源码均保留。

另一个运行器问题是把旧`locked-schema`测试放进普通上下文控制器，缺少其专用第二临时库及账号权限，导致初始化失败。已使用它原有的专用控制器补验九版，通过；失败未覆盖。实际ZIP消费者原14程序12通过／2项相同初始化失败，另一次全新离线安装仅补验受影响的两个端点，通过，按14程序范围取得覆盖。原7步骤6通过／1失败和补验5步骤全通过分别保留。每轮安装均非符号链接，367份SDK／SQL逐项匹配，临时资源已清理。

[初轮原型](ledger-final-structure-evidence-2026-10-24/probe.json)、[修正后原型](ledger-final-structure-evidence-2026-10-24/probe-corrected.json)、[相关MySQL](ledger-final-structure-evidence-2026-10-24/matrix.json)、[专用控制器补验](ledger-final-structure-evidence-2026-10-24/locked-only.json)、[SQLite／API／静态](ledger-final-structure-evidence-2026-10-24/local-checks.json)、[原消费者](ledger-final-structure-evidence-2026-10-24/consumer/consumer.json)、[消费者补验](ledger-final-structure-evidence-2026-10-24/consumer-locked-corrected/consumer.json)。

## 未采用的合并查询与成本诊断

先验证了当前上下文和根记录首屏的UNION ALL合并。PHP7.2／8.5修正后各668项断言通过，比较空根、3条／65条历史、根缺失、两种取数及缓冲模式、临时表遮蔽，并在仅执行候选查询的新事务中验证行／间隙及两表元数据锁。首轮锁测试被基准查询预先持锁影响，不能证明候选自身持锁；PHP8.5还遇到测试使用弃用PDO常量，均修正后重新验证并保留失败。

合并查询的交替计时没有证明收益：PHP8.5两组32次分离读取约0.079／0.083秒、合并约0.080／0.083秒；PHP7.2分离约0.077／0.074秒、合并约0.084／0.080秒。因此没有接入SDK，不根据首轮单向计时选择性宣称优化完成。该原型不是完整权限／预算／接口验收。

[原型首轮](ledger-context-root-prototype-evidence-2026-10-24/matrix.json)、[修正结果](ledger-context-root-prototype-evidence-2026-10-24/corrected/matrix.json)、[PHP7.2](ledger-context-root-prototype-evidence-2026-10-24/corrected/php72-prototype.log)、[PHP8.5](ledger-context-root-prototype-evidence-2026-10-24/corrected/php85-prototype.log)。

随后在只添加计数器的副本中观察完整结构校验：默认首次符合条件的签发到超时前共83次，59次来自普通目录读取中的借读，24次来自物理因子权限入口的自有事务。该诊断约3.004秒失败、pending，保持实际时钟、PDO和3000ms预算，没有续办。结构计数与其包容时间均不能直接当作端到端性能收益。

[计数来源](nested-ledger-schema-profile-evidence-2026-10-24/instrumentation.json)、[实际调用栈计数](nested-ledger-schema-profile-evidence-2026-10-24/schema-misses.json)、[诊断结果](nested-ledger-schema-profile-evidence-2026-10-24/default-85-timing.json)、[输入与清理](nested-ledger-schema-profile-evidence-2026-10-24/default-85-result.json)。

## 仍未关闭

所有相关测试结束并清理后，修复后的串行默认调用仍约3.251秒失败：状态current、`account.operation_timeout`，在进入最终只读`api.credentials.audit_check`的期限检查处拒绝，没有向调用方返回凭据。实际SystemClock／PDO、3000ms预算及一次先行明确拒绝后的1个位置提示保持；没有重试或续办。上批约3.006秒／pending的失败仍保留，不能把局部结构检查次数下降或状态变化当作完整签发成功。[串行默认结果](ledger-final-structure-evidence-2026-10-24/default-85-timing.json)、[异常栈](ledger-final-structure-evidence-2026-10-24/default-85-run.log)、[输入与清理](ledger-final-structure-evidence-2026-10-24/default-85-result.json)。历史PHP7.2时钟／预算、其他未解释失败与最终非暂缓候选仍开放。

goal保持active；上述都是限定专项，未称为整项目或稳定版验收。跨安全代际工作进程交接、未知回执续办、最终账号恢复启用、依赖它们的完整F01及外部验收未执行。没有提交、推送、部署或删除既有数据。
