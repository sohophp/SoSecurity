# 旧邮箱丢失后的地址恢复核心

`Account\MailboxRecovery` 已接入 SDK，接入后的主工作区专项已通过。它用于旧邮箱不可用时迁移已验证的登录地址，必须同时取得新邮箱证明和独立强审批。成功保留密码、角色、账号状态及 MFA，推进地址／凭据版本，使旧会话失效；不自动登录，不替换或移除因子。完整账号恢复、运维和原生 HTTP 入口仍按[完整契约](account-lifecycle-design.md)继续。

## 配置与调用

`Security::mailboxRecovery()` 使用既有账号 PDO、`IdentityRepository`、账本／Outbox 密钥、通知编解码器、正式共享请求预算及策略，另要求 `accounts.mailbox_authority` 和 `accounts.mailbox_approval` 两个显式服务名称。可以单独启用，不要求普通登录／操作授权工厂同时启用；宿主的强审批实现仍须验证真实审批人。管理和工作端权限分别使用 `management_guard`／`delivery_guard`，没有服务时对应操作拒绝。诊断只检查结构，不能证明审批强度或生产恢复能力。

```php
$service = $security->mailboxRecovery();
$service->request($currentAddress, $newAddress, $serverDerivedSource);
// request() 不返回账号是否存在、选择器或证明秘密。
$completed = $service->confirm($selector, $newMailboxToken, $serverDerivedSource, [
    'type' => 'approved',
    'code' => $opaqueApprovalCredential,
]);
```

申请只针对活跃、已验证的当前账号。通知秘密保存在私有认证加密信封中，Outbox 仅引用通知编号；新地址不以明文写入流程正文。首次申请向旧地址提交无秘密的安全提醒，向新地址提交恢复挑战；成功后向两个地址分别提交安全通知。旧地址接收提醒不代表必须取得它的所有权证明。目的端、类型和期限均由服务固定。

同一窗口只允许原目标的有限重发，保留原期限及已消耗尝试；重发更换挑战秘密，旧证明和旧审批上下文失效。不同目标、取消、锁定或已完成状态不能用普通重发清零预算。默认恢复窗口取 `recovery_seconds`，当前默认900秒；请求及发送另受共享预算约束。`cancel()` 消耗有效新邮箱证明取消当前流程，不产生新的改密、登录或因子权限。

## 真实强审批契约

`approvalRequest(selector, source)` 供受管理权限保护的私有审批入口读取当前审查数据。它不消费审批，也不返回邮箱秘密。宿主向审批人展示目标账号、版本和新地址，使用当前身份、要求的重新认证／MFA及明确操作确认签发一次性审批凭据。审批预览数据不是身份或权限证明。

审批服务签名为 `(phase, RecoveryApproval $request, array $proof): bool`：

- `verify` 在 SQL 事务外执行，验证并原子消费本次审批；必须严格返回 `true`。上下文绑定站点／代际、作用域、选择器、当前账号及实际密码身份、因子代际、新地址、原邮箱挑战摘要和期限。
- `current`、`commit`、`complete` 复核已消费凭据的原绑定、期限及审批人的当前权限，不再次消费。前两阶段不能执行网络或新的外部写入，`complete` 在提交后执行。
- 其他账号、目标、用途、代际或重发后的审批不能复用。地址恢复审批不能作为因子替换审批。邮箱证明、普通登录或一个 `RecoveryApproval` 对象均不能代替独立审批。

可以将预览转换为已有[操作授权](operations.md)的 `Intent`，把用途、完整上下文、新地址和账号有效身份指纹纳入资源／参数绑定；验证时消费对应授权，后续阶段读取有期限的消费凭据并复核审批人。SDK 不替宿主决定人工审查流程、审批人权限或恢复凭据保留策略。本地测试已使用独立操作员的真实密码、TOTP 和一次性操作授权组合，并另行拒绝目标／用途不符的授权，不能据此声称生产审批服务已验收。

启用 MFA 的账号在确认时必须能通过 `SecondFactor` 读取当前因子绑定。强审批不会将 MFA 标志清零，也不会生成新因子；原因子不可用时，需要后续独立的因子恢复流程。申请后身份或因子代际变化会使原挑战失效，不自动采用新绑定。

## 事务、投递与维护

证明尝试在独立短事务提交；强审批在事务外消费。最终事务重新核对当前账号、身份、因子、指针、流程及原期限，条件替换地址、消费挑战和两个通知意图使用同一 PDO 原子提交。SQL失败不退还已消耗的审批、尝试或共享预算。提交后复核失败报告 `account.completion_unknown`，不能声称地址已回滚或直接再次执行。

流程具有独立账本命名空间、固定用途和 `account-mailbox-recovery` 生产者，不读取普通双地址变更或密码恢复的挑战。显式 `initialize()` 需要管理权限，构造不建表、初始化、启动会话或发信。沿用现有账号／Outbox DDL，无自动结构迁移。

`dispatcher()` 复用[通知投递](account-notifications.md)的当前领取证明、独立通知权限、发送预算与有界SMTP。模板需显式提供第六个 HTTPS 操作地址 `recover_address`；缺失时工厂在 SQL／网络之前拒绝。旧五地址模板配置继续适用于原有流程，不能用于此恢复工作端。原生页面仍须显式 POST、CSRF、统一响应和缓存控制；邮件链接本身不完成地址变更。

`maintain()` 有界清理到期私有记录及配对指针，不删除宿主账号、因子或 Outbox；`rotate()` 重封存／重加密并保留原证明和期限。旧写进程与不支持新通知类型的工作端应先停止，再启用新流程；退役旧键前核对全部在线命名空间及备份。可信代际必须在备份之外保留，完整有效旧备份和审批存储一起回滚仍需宿主独立恢复权威处理。

安全设计参考 [OWASP 密码恢复](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) 与 [MFA 恢复／因子变更](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)。本地 SQLite、禁用TCP的独立 MySQL、临时 SMTP 和真实进程证据分开记录；没有生产、真实收件箱或完整R2.7验收结论。
