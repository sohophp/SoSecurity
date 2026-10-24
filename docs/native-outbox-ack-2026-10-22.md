# 已知成功结果的原生 Outbox 确认

原 SqlOutbox::acknowledge 只能在已激活的状态边界内执行，没有独立的原生当前账号权限入口。源码 API 核对见 [api-before.json](native-outbox-ack-evidence-2026-10-22/api-before.json)。本批新增 acknowledgeTarget／acknowledgeFor，补齐持有当前原租约的工作进程确认已知成功结果的能力。

权限动作固定为 outbox.acknowledge，目标绑定准确来源、站点、scope、代际、策略和密钥配置、生产者、工作进程和完整规范令牌摘要。只有实际当前账号、会话及维护角色有效，且工作进程授权回调允许，才进入操作。原令牌先限长并验证格式，私密令牌和正文不进入意图记录。

准入使用只读观察检查签名账本、正文、原工作进程、令牌及有效租约。缺少角色、授权拒绝、错误或已失效令牌、已经结算的消息均返回false，不写pending、不更新消息。admission／admitted 回调在观察事务外执行，仅使用局部参数和有限元数据。整个入口沿用策略预算及写pending前的时限复核。

```php
$target = $queue->acknowledgeTarget($scope, $producer, $worker, $originalToken);
// 只有宿主已确认成功结果，才以实际会话和角色构造 outbox.acknowledge 权限。
$confirmed = $queue->acknowledgeFor($policy, $permission, $scope, $producer, $worker, $originalToken);
```

SDK不会凭空证明远端已收到消息。调用方及其工作进程授权回调须拥有已知成功结果；本入口不查询、推断或续办未知回执，也不替代Dispatcher的传输结果验证和发送预算记录。

成功时复用已有acknowledge事务，将目标消息标记sent、记录sent_at、清除待投递正文、结束租约；不增加尝试、不接管、不发送，其他消息保持。原始入口保护模式限制仍在。重复调用新入口返回false而非重新写入；旧原始acknowledge的幂等行为不变。提交／返回期间失权、预算耗尽或原租约过期时，不报告成功；已提交消息和pending保留，不回滚已确认状态、不重新排队、不自动续办。

StateAccountConnection增加outboxAcknowledgeTarget／outboxAcknowledge，见证仅新增准确动作白名单。公开类型保持272，四个新增方法及全部既有签名已复核，见 [api-review.json](native-outbox-ack-evidence-2026-10-22/api-review.json)。

## 验证范围

[本批证据目录](native-outbox-ack-evidence-2026-10-22/)使用新建账号、会话、完整来源、第一次认领的自建消息，不调用任何网络传输。测试覆盖正常确认、无角色、授权拒绝、错令牌／工作进程／生产者、原始入口拒绝、嵌套调用、私密异常脱敏、按引用修改授权参数、已结算消息拒绝、准入过期、提交后角色撤销及完成过期。最后两者仅检查已提交状态和pending保留，不执行未知结果续办。

九版矩阵还覆盖上一批当前租约入口作为不同动作的兼容检查；此次通过不能关闭上一批PHP7.2持久化超时。MySQL使用产品既有10秒默认预算，原自定义1秒失败继续保留。归档消费者使用离线、非链接Composer安装并核对实际vendor路径及源码摘要。没有生产数据库、外部投递、提交、推送或部署。

完整原生Dispatcher发送及发送预算关联、已知拒绝结果处置、历史未解释超时和其他剩余入口仍开放。暂缓能力和外部验收不写成已完成，goal保持active。

最终本批结果：九版源码定向矩阵54/54通过（正常确认98、准入到期64、提交后失权／到期各70断言，并包含当前租约和API兼容检查）；两端私有MySQL八套通过；归档／安装／来源及两端三场景10/10通过；语法与入口检查13/13通过。PHPStan无错误，可选turbo扩展GLIBC警告保留。四个核对运行时文件与最终归档消费者SHA256一致。精确命令与退出码见matrix.json、archive.json、completion.json和result.json。历史自定义1秒失败及PHP7.2持久化／时钟失败仍未关闭，不称为全项目或稳定版验收。
