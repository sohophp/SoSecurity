# 原生首次认领：写 pending 前的预算复核

上一批的 MySQL 首次认领正常测试显式设置 io_milliseconds=1000。产品 Outbox\Policy 的既有默认值是10000，本批未修改默认值、配置范围或测试的1秒预算。两端1秒失败应准确描述为该本地完整来源配置无法满足此时限，不能把它扩展成默认配置已失败。

## 已确认问题与修复

隔离源码副本的定点观测记录了同一 Deadline 的剩余时间，不记录参数或私密数据。一次观测显示 admitted 阶段尚余约0.37秒，效果回调检查时已耗尽。该路径在准入后仍须执行真实权限与完整来源复核，却只在写入 pending 后检查调用方预算。保留原始测量及失败于 [前批证据目录](outbox-initial-claim-evidence-2026-10-22/)的 mysql85-profile.log、profile.json 和 deadline-before.log。

确定性反例在准入后来源检查中等待300毫秒，调用方预算250毫秒。旧实现仍执行效果回调，预期拒绝断言失败。现在通过 StateAccountConnection::outboxInitial、StateBoundary::run 将同一个 Deadline 传入 LocalStateWitness::work；在最初进入和所有准入来源检查完成后、写 pending 之前检查，已耗尽则返回 account.operation_timeout。完整来源、当前权限、事务、持久化及未知结果保护均未删除。

只要尚未写入就已超时，此拒绝不修改见证，不执行效果回调；测试随后执行新的合法操作，证明不是复位未决状态。写入 pending 后发生的超时／权限变更仍按原规则保留未决状态，绝不清除或续办。本改动不是对每次1秒请求都可完成的承诺，也不能保证预算在最后检查与持久化之间不会耗尽。

实际工厂测试在 admitted 之后的真实权限时钟观察中注入等待，验证 account.operation_timeout、SQL记录和见证均不变。测试不恢复账号、不接管租约、不投递消息。只使用新建账号及其首次认领。

## 兼容与证据

公开类型保持272；仅三个既有方法增加末尾可选 ?Deadline $operationDeadline=null，原参数前缀和返回类型逐项保持，见 [API审核](native-operation-deadline-evidence-2026-10-22/api-review.json)。不传参的既有调用保持原路径。此参数补充写入前的预算门槛，业务效果和返回阶段仍须执行各自预算检查，不能将它当作中断任意宿主代码的机制。

[本批证据目录](native-operation-deadline-evidence-2026-10-22/)记录九版定向检查、MySQL两端确定性拒绝、原始默认配置的首次认领、静态分析及离线归档消费者。默认配置测试独立命名 defaults，保留原1秒 normal场景及失败记录，不以默认配置通过覆盖1秒失败。旧历史超时、完整Dispatcher发送与处置、暂缓功能和外部验收仍未关闭；goal保持active。

最终结果：九版主专项54/54、既有原生轮换兼容9/9通过；两端 MySQL 写入前拒绝4套与产品原始默认配置2套通过；全新离线消费者10/10通过，四个运行时文件的摘要与最终源码一致；语法／shell／Python入口及空白检查17/17通过。PHPStan无错误，可选 turbo 扩展 GLIBC 警告保留。详细命令与退出码见 matrix.json、compatibility.json、archive.json、completion.json；MySQL日志为 mysql.log／mysql-defaults.log。本批没有执行完整项目门禁，也没有关闭历史1秒失败或其他历史超时。
