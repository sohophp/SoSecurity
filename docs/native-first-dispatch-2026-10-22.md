# 当前账号权限下的原生首次通知发送

## 缺口与实现

前一批已将发送预算纳入完整状态来源，但发送仍需宿主自行提供外层StateBoundary。本批源码核对确认Dispatcher原先没有sendInitialFor（见证据目录api-before.json），新增initialTarget与sendInitialFor，将指定消息的首次认领、通知读取、预算、模拟传输及结果结算置于同一个原生outbox.dispatch操作内。

只选择pending、从未尝试过、无人工重试且满足聚合顺序的准确消息。已认领、曾尝试、已完成或终止的消息不能借此再次发送。目标绑定消息、站点、生产者、工作进程、队列密钥和策略、发送预算配置摘要、模板配置摘要、传输名称和调用时限。预算存储仍要求同一StateBoundary，模板与预算摘要不是对任意宿主存储路径的认证。

宿主用initialTarget($id)构造当前真实会话的outbox.dispatch权限，然后调用sendInitialFor($policy, $permission, $id)。工作进程授权新增claim_initial准入动作；五种通知工厂已支持它。SqlOutbox::dispatchInitialFor及StateAccountConnection底层操作回调属于可信服务器配置，不能接收请求提供的回调。

正常返回submitted／discarded／deferred／rejected沿用既有发送流程；无权限、无候选或工作进程拒绝返回idle。每次内容放行前，在队列回调之后重新验证实际当前账号权限，防止最后一次回调撤权后仍然放行。发送前撤权阻止模拟投递；投递后失权、未知结果或完成不确定保留pending，不返回成功，不提供续办。

Dispatcher重入被拒绝。传输名称异常脱敏，不附带原异常。Deadline新增内部预算交集方法，队列与发送共用较早的截止点，不因进入子操作重启预算。现有sendNext复用同一发送实现；其原有保护模式原始入口限制保持。

公开类型保持272，逐项对比确认既有公开方法签名未变，候选新增8个方法（api-additions.json）。MailTemplates及SendBudgets提供配置fingerprint；没有改变已有数据命名空间或清空额度。普通模式传输名称异常现在统一脱敏，并拒绝非UTF-8名称。

## 测试边界

新增测试使用实际新账号、会话、角色和完整SQL／文件来源，发布一条新因子通知，传输是进程内模拟对象。覆盖正常首次提交、已知永久拒收、发送前／后撤权、最后一次内容门禁回调撤权、未知结果、慢传输名称查询、准确目标和传输身份绑定、重入及异常隐私。恢复类只构造工厂，其执行使用禁止调用的桩实现。未恢复旧工作进程、未知结果或最终恢复启用链路。

首次预算测试在前置无角色检查中已经超过其刻意设定的100毫秒，未进入预定慢名称场景；失败保留initial-budget.log。修正测试仅跳过该模式的重复无角色检查，实际产品预算未增加、超时保护未放宽。其余模式仍执行无角色检查。

证据目录：[native-first-dispatch-evidence-2026-10-22](native-first-dispatch-evidence-2026-10-22/)。最终结果以matrix.json、archive.json、mysql.log及result.json为准。PHP7.2已有未解释的提前超时仍开放，不用其他版本或使用单调时钟包装的MySQL通过覆盖默认运行结果。

已知可重试拒绝后的原生再次发送、其他未核对产品入口、真实SMTP／宿主集成及独立验收仍未由本批完成。未知结果续办、跨安全代际交接和最终恢复启用继续暂缓；本批不是完整稳定版验收，goal保持active。没有提交、推送、部署、外部投递或生产数据库访问。

最终本批结果：九版源码定向矩阵98/99通过；PHP7.2拒收场景约3.683秒触发sql.timeout，日志保留php72-rejected.log。两端私有MySQL14/14通过（PHP7.2使用单调时钟包装）。归档与消费者13/14通过；PHP7.2未知结果场景约2.776秒触发sql.timeout，日志保留consumer72-unknown.log。12个运行时文件归档摘要一致，消费者临时目录已清理。两端语法32/32通过；PHPStan无错误，可选turbo扩展GLIBC警告保留。精确范围和结果见result.json；这两个超时失败未重跑覆盖，根因仍未确认。

> 后续已知可重试拒收接入：见[原生再次发送专项](native-rejected-dispatch-2026-10-22.md)。同一代际、同一工作进程且保留已校验拒收记录；不提供未知结果续办或过期租约接管，具体测试失败仍保留。
