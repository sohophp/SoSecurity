# 已知可重试拒收后的原生再次发送

## 缺口与行为

此前原生Dispatcher只有首次发送入口；既有普通sendNext虽然可处理拒收后的重试，但不能作为当前账号权限下的原生入口。源码核对保留在[api-before.json](native-rejected-dispatch-evidence-2026-10-22/api-before.json)。本批新增rejectedTarget与sendRejectedFor，保留原始通知、同一安全代际及同一工作进程，调用时绑定准确消息ID、上一次队列尝试次数和错误码。

原生动作是outbox.dispatch_rejected。除已有站点、来源、策略、密钥、模板、传输和发送预算配置外，权限目标还绑定previousAttempt与error。次数限1—99、错误码最多64字节且使用固定ASCII格式；lease_expired、expired、attempts_exhausted直接拒绝，不能把租约过期或耗尽后的处置当成此入口。

只读SQL准入要求消息为pending、原工作进程相同、尝试次数准确、没有人工重试、周期次数未耗尽、租约已明确结束、退避期已到、通知未过期，且较早聚合消息没有阻塞。不认领leased消息，不重置计数、不重新初始化账本、不改变安全代际，也不提供通用接管。

```php
$target = $sender->rejectedTarget($messageId, $previousAttempt, $knownErrorCode);
// 由宿主用实际当前会话与角色构造 outbox.dispatch_rejected 权限。
$result = $sender->sendRejectedFor($policy, $permission, $messageId, $previousAttempt, $knownErrorCode);
```

队列pending本身不是拒收证明。发送预算新增reserveRejected：对原通知、原交付ID和准确邮件内容校验已有带签名状态，必须是较早尝试的rejected；在准备和实际预留两个原子步骤均检查。缺失、reserved、started、accepted等状态不能被解释为可重试拒收。额度继续累计，最大实际发送次数不增加；发送预算不足时返回deferred并沿用有界队列退避，不凭此重置为首次发送。先前已知拒收后仅因额度不足而推迟的队列尝试可以继续检查，但不能绕过每通知次数上限。

预算证明在受保护操作内、实际传输之前校验。若此时发现不一致，会失败并保留pending，而不是把来源异常伪装成无候选；调用方不能把未知结果交给本入口尝试恢复。已有未知结果所留下的见证pending也没有新增解除方式。

首次发送和再次发送共用内容读取、当前权限复核、共享时限、内容门禁及结果结算。末次队列回调撤权会阻止内容放行；模拟投递后撤权保留pending。本批没有执行未知回执续办、过期租约接管、跨代交接或最终恢复启用。

## 兼容与验证

公开类型仍为272，逐项核对新增7个公开方法、原有方法签名不变，见[API增量](native-rejected-dispatch-evidence-2026-10-22/api-additions.json)。五类通知工厂新增claim_rejected工作进程授权动作，默认仍要求宿主回调明确允许。普通sendNext及原reserve语义保持；新reserveRejected使用更严格的拒收证明。

测试使用新账号、实际角色和会话、完整SQL与文件来源以及进程内模拟传输。先完成一次明确可重试拒收，再检查准确重发、退避期、消息字节不变、上限不重置、永久拒收、准入期间到期、最后内容门禁撤权及投递后撤权。另有纯内存预算测试验证缺失状态、预留／开始状态、旧尝试、内容变化和已接受状态的拒绝，以及累计次数上限；没有调用旧的包含未知结果续办的整套发送测试。

到期测试把时间推进安排在claim_rejected的admitted回调，并断言实际走到该阶段，避免仅由会话先过期造成表面通过。退避期未到、错工作进程、错误尝试及配置错配的拒绝不改变队列与见证。

证据位于[native-rejected-dispatch-evidence-2026-10-22](native-rejected-dispatch-evidence-2026-10-22/)。结果仅覆盖本批及相关首次发送兼容性，不代表全项目验收；PHP7.2默认时钟的历史提前超时、其他产品入口和外部验收仍开放，暂缓范围不恢复。没有提交、推送、部署、外部投递或生产数据库访问。

最终本批结果：九版源码定向矩阵97/99通过。PHP7.2的retry-normal在约6.041秒失败，异常已脱敏为提交结果不确定，底层原因未确认，不能直接归为SQL超时；首次发送兼容场景normal在约2.778秒触发持久化超时。两端私有MySQL12/12通过，PHP7.2明确使用单调时钟包装。归档消费者11/12通过，PHP7.2重发正常场景约2.826秒触发SQL超时；三个首次失败日志均保留，未反复重跑覆盖。10个修改运行时文件摘要与归档一致，消费者临时目录已清理。语法26/26通过，PHPStan及最后变更文件复核无错误；可选turbo扩展GLIBC警告保留。完整结果、命令和摘要见result.json、matrix-driver.py、archive-driver.py、api-review.json及source-sha256.json。goal保持active，不能据此宣称稳定版通过。
