# 注册与双地址变更核心

当前 SDK 工作树已纳入 `Account\Registration`、`AddressChange`、宿主账号适配契约、内部事务账本、正式请求预算及显式公共工厂。[密码恢复核心与强恢复审批](account-recovery.md)也已接入；旧邮箱丢失／因子替换等完整恢复编排、原生页面、邮件工作进程和完整 R2.7 验收仍在实施。历史设计和阶段证据见[生命周期契约](account-lifecycle-design.md)。

## 显式部署与依赖

私有账本使用 `resources/sql/account-sqlite.sql` 或 `account-mysql.sql`，与宿主账号表和 Outbox 使用同一实际数据库、同一个 PDO 对象。DDL 由受控部署安装；组件不建表、不清空旧记录，也不接受缺失或损坏历史。示例宿主表另见 `account-example-*.sql`，真实项目应实现自己的 `Repository`；双地址变更需要 `IdentityRepository`。这些接口不要求改用示例账号表。

[SqlAccounts](../examples/SqlAccounts.php) 展示有界读取、唯一约束和条件更新。原始凭据版本用于业务条件更新；`identity()` 额外绑定当前密码哈希，不能把未经认证的 `AccountRecord` 快照当作登录证明。修改账号必须推进版本，并保留原角色和 MFA 约束；宿主须确保所有登录来源都读取当前版本。

构造服务时显式注入站点、作用域、外部可信 epoch、用途独立的封存／Outbox／通知密钥、账号适配、当前权限回调及共享预算。注册还需要密码哈希器与密码策略；地址变更需要真实的 `SessionRegistry` 和 `Operation\Grants`。省略管理或通知读取回调时默认拒绝，不从公开申请权限继承。依赖与回调参数见[公开 API](public-api.md)及构造函数。

公开请求预算的 `public` 阶段覆盖站点、可信来源和目标地址假名，已知账号另有 `subject` 阶段；`final` 阶段复核先前扣减的有效窗口。宿主回调必须严格返回布尔值，来源由服务器推导，不能直接信任客户端自报 IP。计数使用共享持久存储，SQL 失败不能自动退还已消耗的外部预算或操作授权。注册申请有待提交写入时也会在当前权限检查后调用 `request/final`，拒绝／异常／预算过期会回滚申请和通知，回调后的账号变化同样拒绝；自定义预算回调必须实现这一阶段。正式预算及显式工厂见下一节；直接构造核心时，自定义预算回调仍必须严格实现全部阶段。

## 正式请求预算与 SDK 工厂

`Account\RequestBudgets` 接收共享 `AtomicStore`、站点、专用稳定假名密钥及四份显式 `BudgetPolicy`，策略键名恰为 `site`、`source`、`target`、`subject`。站点、来源、目标地址维度在同站点不同作用域／操作间共享；账号维度额外绑定作用域。来源必须由服务器推导。密钥32—128字节，邮箱、来源、账号以HMAC假名写入计数状态；额度由宿主按实际成本配置，没有通用默认值。

工厂的 `accounts` 配置必需 `connection`、`scope`、`epoch`、`repository`、`integrity_keys`、`outbox_keys`、`notifications`、`request_budget`，除作用域及epoch外均是注入服务名称。`registration_authority` 启用 `$sdk->registration()`；`request_guard` 启用 `$sdk->addressChange()`，后者还需配置已有 `authentication`、`authorization`、`operations` 及同一当前身份的 `IdentityRepository`。至少启用其中一种操作。管理和通知读取另使用 `management_guard`／`delivery_guard`，省略默认拒绝。可选 `policy` 使用账号策略，密码配置沿用 SDK 的 `password`。

```php
$budget = new \SoSecurity\Account\RequestBudgets(
    $sharedStore, $site, $budgetKey, $fourBudgetPolicies, $clock
);
$sdk = \SoSecurity\Security::fromArray([
    'site' => $site,
    'accounts' => [
        'connection' => 'db', 'scope' => $scope, 'epoch' => $epoch,
        'repository' => 'accounts', 'integrity_keys' => 'ledger_keys',
        'outbox_keys' => 'queue_keys', 'notifications' => 'notices',
        'request_budget' => 'budget', 'registration_authority' => 'public_guard',
    ],
], [
    'db' => $pdo, 'accounts' => $repository,
    'ledger_keys' => $ledgerKeys, 'queue_keys' => $outboxKeys,
    'notices' => $notifications, 'budget' => $budget,
    'public_guard' => $registrationGuard,
], $clock);
$registration = $sdk->registration();
```

状态变更为每次调用生成独立操作编号，作为预算回调第七个参数贯穿 `public`、`subject`、`final` 阶段；原六参数 PHP 用户回调继续兼容。相同参数的调用不能借用或重放许可，最终检查不延长原期限。只读提案也扣减公开预算，但不保留后续许可。最多保留32个在途上下文，可配置1—64；每个请求重新构造适配器，以相同站点、后端、私钥和策略共享计数。

活跃窗口内的私钥／策略漂移拒绝处理。变更配置须停止旧写进程，并等待原最长窗口／完整令牌恢复期排空；不能通过换密钥、换存储命名空间或删除状态重置额度。配置锚点不提供独立的备份回滚防护。按顺序扣减的额度在后续维度或SQL失败时不退款；请求预算不能代替身份、CSRF、当前权限或SMTP发送额度。

工厂拒绝已知的 `MemoryStore`／`SessionStore` 及其命名空间包装，自定义存储的持久性仍由宿主证明。预算与通知对象必须匹配生命周期时钟；启用SMTPUTF8策略时，通知编解码器也须明确启用对应能力。结构校验和 `diagnose()` 不读取时钟、不调用业务回调或连接数据库；数据库结构、时钟、密钥用途、传输及恢复的实际部署责任标为待人工核验。

专项测试为 `tests/account-budgets.php`、`account-budget-sql.php`、`account-factory.php`，已接入常规SQLite及自建MySQL流程。候选及写入SDK后的两后端组合复验均已通过，范围见[最新验证记录](verification.md)。

## 注册与所有权确认

`initialize()` 仅供有当前管理权限的显式初始化流程使用。公开申请调用 `request(address, source)`，统一返回受理结果，不返回选择器、秘密或账号存在性。待验证账号没有密码，所有者在邮件证明通过的明确确认步骤提交自己的密码；不能预装申请人选择的密码。

`confirm(selector, token, password, source)` 持久扣减证明尝试次数，在 SQL 事务外检查密码策略与计算哈希，再复核当前账号、地址版本、最新申请、用途、期限和权限。账号激活、证明消费及安全通知意图在同 PDO 提交，不创建登录会话。`cancel(selector, token, source)` 只取消当前注册证明，不激活账号或改密码。

重发受冷却、累计次数和原有效期限制；更换秘密不会延长旧窗口。公开路由仍需宿主提供统一响应、Cookie 写操作的 CSRF、禁止缓存及方法限制，GET 不得直接消费证明。本阶段未交付这些原生路由。

## 双地址变更

1. 调用 `proposal(subject, newAddress, sessionToken, source)` 生成服务器提案。
2. 通过真实 `Grants.begin()`、重新认证和 `Grants.confirm()` 获取一次性授权，再调用 `request(...)` 消费授权。
3. 旧、新邮箱分别以明确 POST 调用 `confirm(selector, side, token, source)`；`side` 只能为 `old` 或 `new`。这两份证明只推进准备状态，不修改邮箱。
4. 调用 `completionProposal(...)`，再次重新认证并明确确认新的操作授权，再调用 `complete(...)`。

保护模式可改用 `proposalFor($policy, ...)`、`requestFor($policy, ...)`、`completionProposalFor($policy, ...)`、`completeFor($policy, ...)`：首参数是该实例准确的 `StateAccountPolicy`，随后沿用对应旧方法的参数。这四个入口自行管理外层边界，不能嵌套在 `StateBoundary::run()` 中。当前账号、会话、对象／字段权限及一次性授权先在只读准入阶段核验；原业务守卫还会收到只读 `admission` 阶段。一次性授权的准备、重新认证和确认步骤仍不可省略；地址服务内部使用同图的普通 `Grants` 实例。邮箱 `confirm`／`cancel` 的原生入口另需配置 `accounts.state_request_guard`。详细限制及本地验证范围见[地址原生准入专项](native-address-actions-2026-10-22.md)。

原生地址入口支持显式捕获事实策略：先在同一 `Security` 实例建立准确的 `StateAccountPolicy` 和 `StateAccountConnection`，再使用 `$address = $sdk->addressChange($policy)`；一次性操作的准备与确认仍使用 `$sdk->operations($policy)`。`SnapshotPolicy` 必须绑定同一个 SQL 来源、当前身份提供器和经过审查的纯计算评估器，不能附带有副作用的审计提供器。无参 `addressChange()` 保留原有纯 `RolePolicy` 路径，不会因为边界处于活动状态就获得捕获策略权限。

捕获权限在只读准入、消费凭据前后及业务事务结束后分别复核，并共用请求最初的时间预算。返回检查重读当前实际账户并保留原始 `Intent`；改址完成后旧会话按设计失效，不会为通过检查而恢复。若业务已提交但在原状态边界内撤权、依赖失败或到期，会返回 `account.completion_unknown`，保留已提交结果和 `pending`。外层边界完成后还会只读复核当前账户、最终 `complete` 守卫与原始期限；此时拒绝保留已完成的current见证。两者都不重放操作或恢复已消费凭据。宿主守卫须允许重复只读调用，重发申请仍受原流程更早的到期时间限制。快照观察要求独立事务；事务内的最终权限与条件更新仍由宿主请求守卫和账号适配契约负责，不能把返回复核理解为提交前回滚保证。接入及本地证据见[地址捕获策略专项](address-captured-policy-2026-10-23.md)。

启用 MFA 的账号要求 TOTP／WebAuthn 对应强度；恢复码会话不能直接作为普通地址变更的认证方式。完成时重新读取当前账号和密码绑定身份，并使用宿主唯一约束及原版本的条件更新；保留密码、角色、MFA，推进凭据和地址版本，使旧会话失效。旧地址另有独立取消秘密，取消不产生新权限。旧地址不可用时不能略过确认；密码恢复核心只面向仍可证明当前邮箱的场景，旧地址丢失的迁移编排仍待交付。

SQL 提交前拒绝会回滚本次 SQL 修改，但已消费的外部操作授权保持失效。提交后复核失败返回 `account.completion_unknown`，此时不能假设业务未提交或自动退款重做；宿主应重新查询当前业务事实。两份证明并发完成时也可能出现此结果，测试分别记录提交事实和响应结果。

## 通知、维护与恢复边界

挑战秘密仅保存在私有认证加密通知中，Outbox正文引用稳定通知编号。`notification(id)` 要求当前独立工作进程权限，但不验证队列租约、不连接 SMTP，不能直接当作完整发送器。成功变更后的旧、新地址安全通知不含挑战秘密，后续凭据变化不会自动取消已提交通知。加密与轮换基础见[通知指南](account-notifications.md)。

`maintain(limit, after)` 和 `rotate(limit, after)` 每页最多50个物理记录页头。清理认证待删除正文，并成对处理当前指针与挑战，最多删除两倍页头数；旧申请不会删除较新的当前指针。轮换保留通知编号和期限，活跃安全通知的收件标签也重新签名；已过期历史不会重新获得投递能力。宿主账号与 Outbox 由各自生命周期管理。

管理回调之后再次核对成员检查点及本批保留正文，提交前发现旧账本恢复或等长正文篡改会拒绝并回滚。检查点不认证每个未选中正文，也不提供独立防回滚锚点。分页完成不等于全局密钥退役成功；仍须停止旧写进程并核对在线命名空间及备份。备份恢复／epoch 运维编排仍待交付，不得通过清空账本绕过异常。

仓库测试默认使用私有临时 SQLite；`python3 tests/mysql_check.py --accounts <PHP运行时>` 自建禁用 TCP 的临时 MySQL，仅使用合成数据。SDK 核心及正式预算／工厂的选取组合复验均已通过，以[最新验证记录](verification.md)区分通过、失败和未执行；当前没有生产或实际邮件投递验收。

真实并发运行框架已纳入仓库：`python3 tests/account_change_concurrency.py <PHP运行时> sqlite` 每次执行九个场景，包含168个并发进程和提交前后SIGKILL。MySQL由上述 `--accounts` 控制器自建私有实例后运行同一框架；直接选择MySQL而未提供受控测试实例时拒绝，不能降级为其他数据库测试。默认结果日志位于新建的私有临时目录，路径在最终报告中输出。

### 维护完成时的权限复核

注册和地址变更的 `maintain`／`rotate` 会在 SQL 提交、连接超时设置恢复后，再调用管理权限回调的 `complete` 阶段。回调须保持只读、可重复并判断当前权限，不能只允许 `before`／`commit` 两个阶段。提交前拒绝会回滚；提交完成后拒绝或回调异常返回 `account.completion_unknown`，保留已经提交的修改，不自动重试，也不恢复旧记录。异常不包含原权限回调的消息或异常链。

这项完成阶段检查不等于原生保护维护接入，也不提供跨外部权限服务的原子事务。证据及未通过项见[维护完成权限专项](maintenance-completion-authority-2026-10-22.md)。

### 原生维护

准确声明StateAccountConnection的注册／地址变更服务提供maintainFor与rotateFor，接收同图StateAccountPolicy及显式当前管理StatePermission。使用连接的maintenanceTarget绑定用途、动作和准确页参数；缺少权限或admission拒绝返回null且不写pending。管理回调的admission阶段必须只读且可重复，原普通方法契约保持。提交后失权保留pending并报告完成未知，禁止自动重试。配置示例、权限要求及未通过项见[原生维护专项](native-maintenance-2026-10-22.md)。

原生维护的权限策略还必须与StateAccountConnection使用同一SqlStateSnapshot对象、准确账号表及认证字段映射；同一完整来源中的另一张账号表不能代替真实账号。错配在pending前返回configuration.state_connection。公开工厂应先在同一Security实例建立stateAccountPolicy／stateAccountConnection，再取得registration／addressChange；完整接线与影子表反例见[工厂专项](native-maintenance-factory-2026-10-22.md)。

密码恢复与邮箱恢复的过期请求也可通过maintainFor／rotateFor执行原生管理维护，须绑定准确账号来源、当前管理会话／角色和页参数。普通维护的管理回调新增complete阶段；提交后拒绝报告完成未知，不自动重试。该能力不确认恢复、不启用账号、不执行未知回执续办，详见[过期请求维护](expired-request-maintenance-2026-10-22.md)。
