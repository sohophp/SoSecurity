# F01 生命周期公开请求的前置准入

日期：2026-10-21（Asia/Shanghai）。本组继续既定 P1，不增加预算。范围为注册、密码找回、邮箱丢失恢复三个服务的 `request`／`confirm`／`cancel` 公开请求；修正后 18 条定向检查及 4 条测试环境依赖检查均已执行并通过，准确输入及清理复核见[交付核对](state-request-evidence-2026-10-21/delivery-check.json)。完整 G1、最终恢复及 R1—R6 保持开放。

## 入口和执行顺序

`accounts.state_request_guard` 配置一个 `StateRequestGuard` 服务编号。它与地址变更原有的 `accounts.request_guard` 不同，不能注入一个无参数、永远允许的回调来替代分阶段请求守卫。手动构造三个服务时，在原有 `state` 参数之后追加可空 `requests` 参数；未选择新能力时保留之前的显式外层调用方式。

新模式由服务自身处理外层操作，不再由调用者先包一次 `StateBoundary::run()`。顺序是：

1. 检查准确调用上下文及公开请求守卫。守卫负责目标宿主的请求方法、传输、来源和 CSRF 等请求条件，不授予账号／管理员权限。
2. 校验邮箱、证明编号、来源、密码基本字节限制和恢复证明结构；恢复证明只复制固定的标量字段，避免调用者使用引用数组在锁内检查时更换证明。
3. 通过原有正式 `RequestBudgets` 预留一次公共额度，生成本次操作编号。
4. 进入准确边界，锁内核对完整来源和独立见证，再调用 `current()` 重新检查相同固定动作和作用域。没有通过之前不写 pending。
5. 写入 pending，执行原业务方法，复用同一预算操作编号进入账号及最终阶段；完整操作成功后写入新 current。

固定请求动作是 `registration.request/confirm/cancel`、`recovery.request/confirm/cancel`、`mailbox_recovery.request/confirm/cancel`，作用域来自准确连接声明。不能从客户输入拼接管理动作、目标或可执行回调。`initialize`、通知查询／投递、维护和私有审批预览不从这些公开入口暴露，仍须准确管理／投递权限和显式边界。

构造、配置和诊断不读取当前见证、不初始化业务表、不调用请求守卫。诊断只把正确类型标为 `manual`，把普通回调等错误依赖标为 `fail`，不能据此声称真实 HTTP 已验收。

## 接入示意

以下变量均由服务端可信配置／路由提供；先构造准确来源、见证、认证策略及请求保护，再调用公开操作。公共预算存储继续位于认证来源域之外。

```php
$config['accounts']['state_request_guard'] = 'lifecycle_requests';
$services['lifecycle_requests'] = new SoSecurity\Account\StateRequests(
    $publicProtection, $currentProtection
);
$security = SoSecurity\Security::fromArray($config, $services, $clock);
$policy = $security->stateAccountPolicy(
    $witness, $source, $sqlSource, $fileSource,
    $sqlName, $fileName, $accountTable, $columns
);
$security->stateAccountConnection($policy, $addressColumn, $addressVersionColumn);
$security->registration()->request($email, $serverDerivedSource);
```

同样配置下，`recovery()` 和 `mailboxRecovery()` 的三个公开方法也使用该顺序。请求守卫不是业务 `authority`、受管理恢复码或独立邮箱恢复审批的替代品；这些依赖和原业务再验证继续保留。

## 验收与剩余工作

准确运行结果以[固定执行记录](state-request-evidence-2026-10-21/execution.json)为准。测试使用真实 SQL、FileStore、正式共享预算和受管理恢复码，完成注册、密码找回和邮箱丢失恢复；测试中的邮箱独立审批回调只代表受控测试预设，不能算作外部审批或真实宿主验收。新测试还检查格式错误、公开／锁内守卫拒绝、公共预算耗尽均不写 pending；错误验证码及弱密码正常返回后仍 current；引用证明字段变动不能替换已准备的证明；进入业务后的依赖故障保持未知结果及 pending，后续业务继续拒绝。

开发过程中修正了诊断检查错误地放进因子依赖分支、未使用闭包捕获；测试预设的连接声明、异常类型捕获和未知结果预期也已更正。原始失败日志保留，不与最终快照的断言累计。公开接口兼容性见[接口核对](state-request-evidence-2026-10-21/api-compatibility.json)。

本组首次 20 条固定检查中，19 条通过，私有 MySQL 检查失败；控制器在 PHP 7.2 失败后停止，不能算 PHP 8.5 已执行。隔离诊断副本只恢复内部异常链并输出原因／位置，确认密码恢复提交后的完成核对触发 `sql.timeout`。没有修改主 SDK 的错误脱敏行为，也没有放宽默认 10 秒预算。

随后 `Ledger` 和内部 `SqlTransaction` 对 MySQL 同一事务中连续的 SDK 读取复用表结构验证；每次使用仍核对事务见证。宿主回调、写入及事务边界清空结果，提交后和 SQLite 不使用复用；耐久性条件每次检查。依据是事务持有的元数据锁会阻止其他连接修改正在使用的表结构；自动提交下锁只覆盖单条语句，因此提交后不能沿用。[MySQL 8.0 元数据锁文档](https://dev.mysql.com/doc/refman/8.0/en/metadata-locking.html)。这是实现边界的依据，不是生产性能验收。

新增真实 DDL 检查验证回调添加触发器时仍拒绝，另验证回调后、写入后、新事务及提交后重查。修正后的准确输入和有限复验见[后续执行记录](state-request-evidence-2026-10-21/followup-execution.json)。早期失败、诊断与后续检查保持不同源码身份，不拼成一次整轮通过。

SQL 表结构测试最终去掉了原先借用的 sodium／TOTP 预设环境，改为只创建明确账号 SQL 表；普通 PHP 7.2 与 PHP 8.5、两端私有 MySQL 及公共入口脚本语法共 4 条检查通过。该变化只涉及测试数据准备，不改变 SDK，准确差异见[依赖检查](state-request-evidence-2026-10-21/fixture-execution.json)。两端 MySQL 使用 8.0.46；PHP 7.2 的完整生命周期检查仍使用私有 sodium／原生单调时钟，不能写成未增强系统 PHP 的完整通过。静态分析无错误，保留可选 turbo 扩展 GLIBC 不匹配警告。

本组固定停止条件已达到：三个实际 SDK 流程、前置拒绝无 pending、故障仍隔离、表结构复用边界、受影响既有回归及接口核对有准确证据；六个临时 MySQL 实例及诊断副本已清理。停止本组扩测，继续下述原定缺口，不新增阶段或延长周期。

尚未完成：地址变更的当前账号／一次性操作授权在 pending 前的纯判断；账号及最终预算阶段拒绝的安全收口；全部后台入口及其他状态后端；未知结果后的完整恢复和安全重新可用。后两类预算目前仍可能留下 pending，不能把本组有限检查描述为“全部普通拒绝已经解决”。

本组未执行真实 HTTP／浏览器／CSRF 联合流程、SMTP、第三方 OIDC、实体 WebAuthn、目标代理／WAF、远端 CI 或独立安全复核，也未执行最终冻结候选的九版本整轮。它们继续属于完整计划，不改为不适用或无限后延。未提交、推送或发布。

> 后续地址邮箱证明接入：见[原生确认／取消与守卫异常脱敏](native-address-proofs-2026-10-22.md)。只覆盖公开证明入口；申请／完成的前置授权、历史失败、暂缓功能及外部验收仍未关闭。

> 后续地址原生申请及改址：见[真实会话、一次性授权与只读账本准入](native-address-actions-2026-10-22.md)。此前“地址申请／完成仍缺原生准入”的描述为历史状态；具体通过、失败和未执行范围以该批证据为准，暂缓及外部验收未关闭。
