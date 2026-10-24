# Outbox 独立密钥轮换及原生权限接入

代码核对确认：原 SqlOutbox 只有 maintain，没有独立 rotate。maintain 同时执行密钥重签、过期正文处置、历史删除及到期租约转为待发送状态。因此不能把该入口作为“只轮换密钥”的操作接入本次非暂缓范围。旧候选方法清单与新增 API 差异记录在 [api-review.json](outbox-rotation-evidence-2026-10-22/api-review.json)；这是缺失行为的源码／契约证据，不是假称执行了旧维护链路的失败实验。

## 实现

新增 SqlOutbox::rotate(scope, producer, actor, limit, afterKey)，在自己的短事务内按 key_hash 分页验证完整账本、逐条限量读取正文，并仅重签需要轮换的记录。消息的所有字段及正文保持，只有 seal_key／seal 变化；根的签名、摘要、观察时间和修订正常更新。它不删除消息、不改变租约／投递状态、不增加尝试、不清除正文、不重投、不调用 reconcile，也不访问网络。原 maintain、retry、reconcile 的行为及限制保留。

普通操作继续检查 managementGuard 的 request／current／commit／return 阶段。提交前拒绝回滚；提交后的轮换权限失败固定为 outbox.completion_unknown，无底层异常链，已经提交的签名不撤销、不自动重做。其他既有 Outbox 动作的错误原因保持原样。

## 原生接口

SqlOutbox 构造函数和 Security::outbox 增加末尾可选 StateAccountConnection。连接必须是准确 PDO、站点、代际及同一时钟，已覆盖实际账号、整个账本和 Outbox 来源。保护模式工厂还核对相同 StateBoundary。

```php
$queue = $security->outbox($accountConnection);
$target = $queue->rotationTarget($scope, $producer, $operator, $limit, $afterKey);
// 从实际当前会话构造 permission；action 为 outbox.rotate，target 使用上面的值。
$page = $queue->rotateFor($accountPolicy, $permission, $scope, $producer, $operator, $limit, $afterKey);
```

权限目标绑定来源边界、站点、scope、代际、生产者、Outbox 操作者、准确当前密钥配置摘要、策略、页大小及游标。维护角色、账号映射、当前会话、时钟和完成权限复核沿用 StateAccountConnection 的真实账号准入。修改任何目标参数或把权限移用到旧密钥配置都会拒绝；不能用自助权限代替维护角色。

managementGuard 增加只读 admission 阶段，收到现有六个参数的局部副本；不得执行外部效果。缺少角色或管理拒绝时尚未写 pending。合法操作持久化准确 outbox.rotate 意图；最终角色失效则保持 pending／account.completion_unknown，没有续办入口。原始同 PDO 入口仍由 SqlStateAccess 拒绝，不能借原生连接绕过。

公开类型保持272；新增 StateAccountConnection 的三个方法、SqlOutbox 的三个轮换方法，以及两处末尾可选参数。候选差异已核对，原参数前缀及返回类型不变。

## 验证范围

[本地证据目录](outbox-rotation-evidence-2026-10-22/)记录逐条退出码。普通专项使用两个过期但未投递的 pending 消息，验证分页重签、提前撤旧密钥拒绝、完成轮换后仅新密钥读取、业务字段及正文不变、提交前拒绝回滚、提交后失权／异常和按引用接收的管理回调。没有制造或续办未知投递回执。

原生专项复用真实新账号、会话和完整 SQL／文件来源，使用公开工厂；覆盖无角色／管理拒绝、生产者／操作者／分页／密钥配置错配、嵌套调用、原始入口拒绝、其他生产者不被重签、完成时角色失效且 pending 保留。首轮测试误查询不存在的 producer 列，native-initial.log 保留；后续只按实际存储的 namespace／受控正文测试数据核对隔离，没有修改产品表结构。

matrix.json 包括 PHP7.2—8.5 的新普通／原生轮换、因子通知维护及注册／地址维护的共享权限回归、既有通知与进程内模拟传输，以及 API 反射。mysql.log 为独立无 TCP MySQL 的两端专项，不访问业务库。archive.json 记录全新归档、离线非链接 Composer 消费者、实际 vendor 来源和运行时摘要。最终结果以这些退出码及后续完成记录为准，不把历史通过视为当前整版验收。

本批最终结果：matrix.json 为53/54命令通过；所有九版新普通轮换（每版35断言）和原生轮换（每版47断言）通过。PHP7.2 的因子通知回归在发布测试数据、调用 Ledger::capacity 时触发 sql.timeout，进程持续3.13秒，保留在 php72-sodium-factor.log；没有执行完该回归，不标记通过，也没有由后续消费者通过覆盖它。尚未证明其根因。

私有 MySQL 控制器退出0，两端普通／原生轮换共四套通过。archive.json 的归档、安装、两端 vendor 来源及普通／原生／因子通知三套场景10/10通过，四个运行时文件与最终源码摘要逐项一致。共享维护辅助方法保留先校验参数、再构造动作字符串的顺序，最终消费者包含此调整。static-final.log 的 PHPStan 退出0，环境可选 turbo 扩展 GLIBC 警告保留。completion.json 的两端语法、shell／Python入口和空白检查17/17通过。

## 未关闭事项

原 Outbox maintain 包含到期租约重新排队，不能由独立 rotate 的测试替代；Dispatcher／Outbox 原生认领、发送及处置链尚未由本批补齐。跨代交接、未知回执续办、最终账号恢复启用、完整 F01 和外部验收继续保留。此前时限失败未解释或关闭。本批无提交、推送、部署、真实投递或生产数据库访问，goal 保持 active。
