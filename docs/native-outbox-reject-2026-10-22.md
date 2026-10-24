# 已知拒绝结果的原生终止处置

原SqlOutbox::fail只有原始状态边界入口，并且可重新排队；本批不把它直接作为原生未知结果续办入口。源码API核对见 [api-before.json](native-outbox-reject-evidence-2026-10-22/api-before.json)。新增rejectTarget／rejectFor，仅用于当前原租约下已知拒绝结果的终止处置，内部明确调用fail(..., false)。

权限动作是outbox.reject，目标绑定来源、站点、scope、代际、策略和密钥配置、生产者、工作进程、完整令牌摘要以及准确错误码。错误码最多64字节，先限长，再要求固定ASCII格式；不能把已批准的错误码换成另一个码。公开类型保持272，四个新增方法及全部既有方法签名已逐项核对，见 [api-review.json](native-outbox-reject-evidence-2026-10-22/api-review.json)。

```php
$target = $queue->rejectTarget($scope, $producer, $worker, $originalToken, $errorCode);
// 使用实际当前会话和角色构造 outbox.reject 权限；宿主必须已确认拒绝结果。
$terminated = $queue->rejectFor($policy, $permission, $scope, $producer, $worker, $originalToken, $errorCode);
```

只读准入检查实际当前账号权限、签名账本、正文、准确工作进程及有效原租约。工作进程授权回调使用原fail动作；在新增admission／admitted阶段收到有限元数据及outcome=rejected、error_code、retryable=false，回调在观察事务外执行，参数和元数据为局部副本。其他既有动作不增加这些字段。

无角色、授权拒绝、错令牌、错误码错配、过期或已经终止的消息不进入pending。合法操作复用原事务，把目标消息变为dead，结束租约并保存准确错误码；不增加尝试次数或手动重试次数，不重新排队，不发送。正文按原dead状态保留规则保持，其他消息不变；原聚合顺序阻塞规则保留，不将拒绝伪装为成功以跳过顺序约束。之后的首次认领仍拒绝该dead消息。

当前／提交／返回授权、完整来源检查、同一调用预算和pending前时限复核继续有效。提交后撤权或到期时，不报告成功；已提交dead状态及pending保留，不恢复、不续办。原始fail入口及其旧重试语义未改变，保护模式原始入口仍受限。

此API不证明远端拒绝，调用方和工作进程授权回调必须依据已知结果使用它；不能用固定错误码推断未知传输结果。它不提供重投、接管、对账或未知回执续办能力，也不替代完整Dispatcher的发送结果与预算关联。

## 本地测试与剩余项

[证据目录](native-outbox-reject-evidence-2026-10-22/)使用真实新账号、会话、完整SQL／文件来源及第一次认领的自建消息。覆盖正确终止、无权限、错误码格式与错配、错误令牌／工作进程／生产者、原始入口拒绝、嵌套调用、按引用修改回调参数、异常脱敏、重复终止和再次首次认领拒绝、准入过期及完成阶段失权／到期。完成失败只检查已提交状态和pending保留，没有调用续办。全程不调用网络传输。

九版矩阵包含成功确认作为不同动作的兼容检查；两端MySQL使用产品既有10秒默认预算；归档消费者采用离线非链接Composer安装，核对实际vendor路径和源码摘要。所有历史失败仍保留，本批通过不关闭此前PHP7.2持久化／时钟问题或自定义1秒配置失败。

完整原生Dispatcher发送、发送预算关联、其他产品余项以及外部验收尚未因本批完成。暂缓功能不恢复，goal保持active。无提交、推送、部署、真实投递或生产数据库访问。

最终本批结果：九版源码定向矩阵53/54通过。PHP7.2的reject-late-expiry在约2.326秒时于SqlStateSnapshot读取触发sql.timeout，未完成。两端私有MySQL八套全部通过。归档消费者9/10通过，PHP7.2完成到期场景在约1.723秒时于LocalStatePersistence触发持久化时限失败；原始失败保留在php72-native-reject-late-expiry.log及consumer72-native.log。正常终止场景127、准入到期70、完成阶段失权／到期各78断言；未执行完成的场景不得计为通过。

随后只在独立源码副本执行固定两次诊断，在Deadline检测到时间回退时记录数值和无参数调用位置；两次均通过且未捕获回退，见clock-diagnostic.json及clock-*.log。因此根因仍未确认，不能用诊断通过关闭原失败，也没有增加预算或修改正式源码的时限规则。语法与入口检查13/13通过；PHPStan无错误，可选turbo扩展GLIBC警告保留。四个核对运行时文件的最终源码与归档消费者SHA256一致。精确汇总见result.json。

已知可重试拒绝的原生流程也仍未由本批终止接口覆盖；不把永久终止等同于完整失败处理。无全项目或稳定版验收结论。
