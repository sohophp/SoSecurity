# 受管理 MFA 接入

状态：已接入本地工作树的可选能力，公开接口仍为候选。当前整合复验与完整 R2.7 分别跟踪，不能据此宣称完整账号恢复或生产验收完成。设计、历史失败及隔离候选证据见[因子设计](account-factor-recovery-design.md)和[验证记录](verification.md)。

## 显式服务与配置

宿主保留账号、当前权限、独立强审批、请求预算、数据库迁移、通知及外部权威的控制。服务容器中的 `totp` 是原始 `Mfa\TotpFactors`；`repository` 实现 `Account\FactorRepository`，并使用与配置完全相同的 PDO。`Account\LocalEpochFence` 由宿主提前构造，绑定规范化私有本地目录、site／scope／epoch 和真正同步持久化的回调。

```php
$config = [
    'site' => 'my-service',
    'storage' => ['driver' => 'file', 'directory' => $privateSharedState],
    'authentication' => [
        'identity_provider' => 'current_identity',
        'request_guard' => 'protected_login_request',
        'managed_factors' => true,
    ],
    'account_factors' => [
        'connection' => 'account_pdo',
        'scope' => 'tenant',
        'epoch' => $trustedEpoch,
        'repository' => 'factor_accounts',
        'integrity_keys' => 'factor_keys',
        'totp' => 'raw_totp',
        'fence' => 'factor_fence',
        'worker_guard' => 'current_factor_worker_permission',
        'read_guard' => 'current_factor_read_permission',
        'management_guard' => 'current_factor_management_permission',
        'policy' => ['io_milliseconds' => 10000],
    ],
];
$security = SoSecurity\Security::fromArray($config, $hostServices, $clock);
$directory = $security->accountFactors();
$secondFactor = $security->managedSecondFactor();
$authentication = $security->authentication();
$sessions = $security->sessions();
```

权限服务必须根据真实当前身份和对象授权作决定，不能直接使用固定放行回调。`authentication.managed_factors=true` 让认证和会话工厂自动采用受管理目录；它要求 `account_factors` 配置，且不能同时配置 `authentication.second_factor` 或顶层 `mfa`，防止同一 `Security` 工厂继续暴露原始因子操作入口。宿主仍须关闭其他自行构造的旧入口和工作进程。未显式启用时保持原有认证适配方式。`managedSecondFactor()` 也可单独返回认证所需的 `Auth\SecondFactor`；缺配置或缺服务时拒绝，不回退到原始 TOTP。工厂创建强类型 `FactorWorkerAuthority`，通过 `managedRegistered()` 保留同 PDO 的注册检查、锁顺序及显式 SQL 预算；不接受通用 callable 代替这条登记链。物理权限、目录读取权限和管理权限分别注入，任何一条失败均拒绝，不退回原始因子读取。

工厂和 `diagnose()` 不自动建表、初始化权威或业务根、采用旧因子、读取当前数据库权限或触发通知。诊断中的 `manual` 表示有对应类型／能力，需要宿主另行验收；同 PDO、时钟、旧工作进程停用、注册权威、独立审批和备份新鲜度不会因构造成功而被判定通过。

## 首次启用与旧状态迁移

1. 通过宿主迁移安装现有账号账本及 Outbox 表，验证持久化和权限。准备数据库之外的可信 epoch 与权威目录；这些不能随旧业务备份一起恢复为旧授权。
2. 由受控部署流程显式创建一次栅栏。`LocalEpochFence::initialize()` 不能用来修复运行中丢失的权威文件。PHP 7.2 的 `fflush()` 本身不证明稳定存储同步，宿主必须提供实际可验证的同步持久化能力。
3. 通过 `$directory->migration(...)` 注入原始因子、准确栅栏、当前权限、预算、独立强审批、停旧进程证明、同 PDO 审计及通知回调。受控首次登记使用 `FactorMigration::initialize($source)`；不要在请求中自动初始化，也不要从业务代码直接操作内部 `Ledger`。
4. 对每个账号获取准确旧状态的短期签名预览，独立审批后执行迁移；只有目录、账号版本、审计及通知意图提交，物理迁移完成后，才能切换认证适配器。未知结果使用保留意图和新的审批明确续办，不自动重复业务。
5. 将认证流程显式连接到上面的 `ManagedSecondFactor`。原始 TOTP、已迁移目录及其他应用实例不能并行充当备用认证来源；宿主仍负责停旧进程和全部入口切换的验收。

## 正常操作与独立替换

`FactorRegistry::operations(...)` 生成普通操作服务，支持 `review()` 后的 `disable`、`regenerate`、`reencrypt` 以及 `enroll`。执行需要准确当前账号／目录及独立管理审批；禁用和恢复码轮换还要求当前因子证明。首次／再次绑定通过 `beginEnrollment()`、`confirmEnrollment()` 完成，签名预览固定独立槽位，先提交意图，再创建敏感绑定资料。

禁用先更新账号版本及逻辑目录，再定向清理旧物理因子。绑定、禁用、恢复码轮换和独立替换的恢复码交付均不可重放；提交结果未知时不能自动重试并声称恢复码仍可取回。`inspect()` 返回保留元数据，`clean()` 只清理允许的非当前准确代际。

`FactorRegistry::recovery(...)` 提供失去旧因子后的独立强审批替换。`retire()` 只用于已停用或缺失账号，保留永久拒绝标记。活跃账号的独立特权撤销见下节。退役／撤销后的独立恢复使用下述新因子恢复服务，不能用普通禁用、重新初始化目录或直接修改存储替代。

## 活跃账号丢失因子后的特权撤销

`FactorRegistry::privilegedRevocation()` 已接入本地工作树，仍是可选候选接口。它保留 `mfaRequired=true`，推进凭据版本并写永久撤销标记，使旧会话和新的密码登录都不能通过；不会降为仅密码登录，也不会颁发新因子或恢复码。撤销标记持续阻断认证，只有下述独立新因子恢复完成且显式交接权威后才可继续认证。

```php
$revocation = $directory->privilegedRevocation(
    $fence, $currentRevocationAuthority, $requestBudgets,
    $independentApproval, $samePdoAudit, $samePdoEvents
);
$review = $revocation->review($subject, $source);
// 显示 block_mfa_login、MFA要求保持、必须独立恢复及整个旧权威关闭的效果。
$result = $revocation->execute($review['context'], $source, $approvalProof);
```

仓储必须提供准确凭据材料的同PDO CAS能力 `FactorMigrationRepository`；物理因子服务必须使用同PDO的强类型登记权威。预览绑定账号／目录／注册工作进程根的准确状态、目标、用途、明确效果、权威和至多300秒期限。操作员审批必须来自当前独立强认证，并将整个context绑定到一次性授权；普通管理、迁移或恢复审批不能替代。`factor_privileged_revoke` 与 `factor_privileged_cleanup` 为不同审批用途；示例权限资源类型为 `factor_revocation`，ID为subject、版本为state，字段绑定整个context。verify阶段在SQL之外消费授权，其余阶段执行当前本地权限核验；不能在SQL回调中发送通知。

执行先排空并永久关闭旧工作进程权威，再同事务推进账号版本、写严格格式6的revoked目录、同PDO审计及通知意图，提交后才清理准确旧物理代际。密码、地址、角色、验证状态及账号启用状态保持。`FactorInspection::retired()` 对这种撤销目录也返回true，即使账号本身仍为active。新格式需同步升级全部管理／认证读取器；真实旧读取代码安全拒绝格式6，不进行自动兼容降级。没有表结构变化。

`account.completion_unknown` 表示关闭持久化、SQL提交回执或后续清理不能确认；不得自动重放。宿主持有准确已关闭EX上下文后，先用 `inspectClosed($subject,$source)` 检查保留决定。尚未提交撤销时，用 `reviewClosed()` 加新审批调用 `executeClosed()`；已有revoked标记时，用 `reviewClosed($subject,$source,true)` 获取专门的清理预览和新审批，再执行 `executeClosed()`，不重复账号版本推进、审计或通知。清理只针对已保留的准确代际，冲突不能删新因子。继续处理其他账号须另行审批工作进程权威交接；不能重新打开旧权威文件。

本地九版候选、旧读取器、两版关联流程及接入后19次检查、静态、两版消费者和386文件归档已通过；两版双物理后端私有MySQL20组880项全部通过，实例已清理。MFA事件对应的无秘密通知类型、期限和固定邮件主题已进入账号通知基础；可复用的`FactorNotices`现在能在可信MFA回调里同PDO保存加密通知并入队，工作端重新检查当前账号地址、独立读取权限、Outbox租约及发送预算。普通管理、首次绑定、特权撤销、因子替换、旧因子迁移、独立恢复与终态清理回调已在PHP7.2／8.5本地SQLite／禁TCP MySQL通过；因子替换的`factor_replaced`及五种迁移事件的固定类型缺口已修复。撤销与恢复决定发生通知拒绝时数据库记录回滚，因子替换已消费的证明尝试数保留，终态清理仍须把物理删除后的未知结果按关闭态复核处理。本机TLS SMTP四情形也已由真实因子事件与两版安装包验证；外部SMTP、停用账号邮件和目标宿主仍须单独验收，不能将旧事件Outbox视作正式邮件。原生POST／CSRF／缓存／Chromium已有[独立本地样例](managed-authentication-native.md)和两端专项，目标宿主仍须单独验收。

## 撤销／退役后的独立新因子恢复

`FactorRegistry::restoration()` 已接入本地工作树，仍为候选接口。只恢复当前启用、已验证的账号，且目录必须保留 retired／revoked 标记；账号启用及邮箱验证仍由宿主先完成。恢复生成不同的新槽位，不重新启用旧秘密，不改变密码、地址、角色或账号状态，最终仍要求MFA。

```php
$restoration = $directory->restoration(
    $fence, $currentRestorationAuthority, $requestBudgets,
    $independentApproval, $samePdoAudit, $samePdoEvents
);
$review = $restoration->review($subject, $source);
// 显示 require_mfa_with_new_factor，取得绑定整个review的一次性独立审批。
$enrollment = $restoration->begin($review, $source, $beginApprovalProof);
$operationId = $enrollment->selector();
// 绑定资料和新恢复码只交付一次，须由受保护页面处理，不记录日志。
$newCodes = $restoration->prove($operationId, $newTotpCode, $source);
if ($newCodes === null) { throw new \RuntimeException('新因子证明未通过'); }
// 数组中的新恢复码须安全交付；空数组表示已启用因子的再次证明。
$activation = $restoration->operationReview($operationId, $source);
$result = $restoration->activate($activation, $source, $activationApprovalProof);
```

准备审批用途为 `factor_restoration_begin`，启用为 `factor_restoration_activate`，不能互换。整个签名context绑定账号／目录／工作进程根、操作、准确新槽位、效果、当前状态和至多300秒期限；verify阶段在SQL之外消费独立强审批，其他阶段重新核对当前权限和预算。仓储与物理服务须保留准确同PDO登记链和 `FactorMigrationRepository` 的实际凭据材料CAS检查。审计回调签名为 `(phase, context, before, after)`，通知回调为 `(type, context, before, after)`，均只写同PDO事务，不发送邮件。

`begin()`先提交意图、单一流程游标和开始审计／通知，再准备新因子；同账号不能并行创建另一个未决流程。证明尝试先提交计数，第五次允许、第六次拒绝（默认策略），重新证明已启用的新因子只返回空数组，不重发恢复码。流程期限与原始准备资料期限分别校验，过期准备资料不能首次证明。

`activate()`永久关闭整个旧工作进程权威，精确检查已证明的新因子，同事务推进凭据版本、保持MFA要求并写格式7目录、审计和通知意图。旧会话、旧因子和旧恢复码不能继续认证。宿主必须显式完成强审批权威交接；不能重新打开旧文件。所有读取器应同步升级，实际上一版读取代码安全拒绝格式7。没有表结构变化。

`operationReview($id,$source,'cancel')`取得取消专用context，新审批后调用 `cancel()`，保留目录阻断状态；取消不直接删除因子。随后以 `clean` 用途取得新审批并调用 `clean()`，仅清理准确非当前的新槽位。已激活流程以 `clean_previous` 用途清理准确旧槽位。清理要排空权威，不能借机删除当前认证槽位，已完成清理不重复审计。

`account.completion_unknown`不能自动重试。权威有效但已关闭时，宿主持有准确EX排空上下文，先调用 `inspectClosed()`，再使用 `operationReviewClosed()`及新审批明确选择 `activateClosed()`、`cancelClosed()`或 `cleanClosed()`。检查只返回保留元数据，不重发绑定资料或恢复码；权威文件损坏时不能自动补建。

`maintenance(...)`提供恢复专用历史维护：只回收已清理的取消流程，或已激活且旧槽位已清理的流程；同时满足原保留期限和本次决定的新保留期限。关联单一游标与流程一起验证及回收，分页每次直接扫描1—50条，最多另取50条关联游标。重封存包括关联游标，不延长原时间、不改变其他用途，也不改物理因子。

## 历史、密钥与未知结果

迁移、普通操作／绑定及独立新因子恢复共享工作流账本，但维护按用途隔离。`FactorMigration::maintenance(...)` 与 `FactorOperations::maintenance(...)` 分别返回维护服务；审批绑定准确页快照、用途、模式及目标密钥，跨用途预览在 SQL 与权限回调前拒绝。

- `review('rekey', ...)` 加 `maintain(...)` 只重封存本用途记录和账本根，不延长业务时间，保留其他用途原样；其他用途仍使用旧封存键时，不能提前退役旧键。
- 到保留期后，`review('purge', ...)` 加 `drainAndMaintain(...)` 显式排空并永久关闭当前工作进程权威，然后准确删除允许回收的终态历史。继续业务必须另行完成强审批权威轮换；不能重新打开原权威文件。
- 未明确处置的普通 `prepared`、待确认绑定、未完成清理的禁用及仍有物理准备回执的迁移继续保护。过期不代表副作用不存在，不能静默删除来释放容量。
- 关闭后的检查／续办只能在同一已持久关闭、当前持有的排空上下文中调用 `reviewClosed()`／`maintainClosed()`，并重新获取准确审批。审计与通知失败回滚 SQL；实际提交回执丢失、授权关闭后的持久化失败或提交后外层权威检查失败报告 `account.completion_unknown`，显式检查后不能重复发通知。

普通 prepared 意图的独立处置见下一节；当前仍需完成所有用途的容量／密钥协同、独立备份新鲜度与安全代际、正式 MFA 通知预算及目标宿主的原生请求接入。数据库 HMAC 不证明一个完整有效旧备份足够新。

完整旧备份已在本地复现旧会话重新生效，独立状态见证仍是未接入的隔离原型。准确风险、已执行证据及剩余接入／恢复契约见[新鲜度与安全代际](account-factor-freshness.md)，不能以新因子恢复已实现代替这个要求。

## 明确放弃普通未决意图

`FactorRegistry::operationResolution()` 专门处理 disable／regenerate／reencrypt 的 prepared 未决状态；不能使用普通操作审批、绑定审批或迁移维护审批代替。仓储还必须实现 `FactorMigrationRepository`，以核对实际凭据材料的保持；物理服务必须保留使用完全相同PDO的强类型注册权威，包装成普通 callable 或使用另一PDO会拒绝。

```php
$resolver = $directory->operationResolution(
    $fence, $currentResolutionAuthority, $requestBudgets,
    $independentApproval, $samePdoAudit, $samePdoEvents
);
$review = $resolver->review($operationId, $source);
// 管理界面须显示整个该工作进程权威会关闭，以及有效账号凭据会失效。
$result = $resolver->abandon($review['context'], $source, $approvalProof);
```

预览绑定准确根、行、当前账号与目录、用途及权威；独立审批示例资源类型为 `factor_operation_resolution`，资源ID为context.operation，版本为context.state，字段必须绑定整个context。权限／审批回调检查当前强认证操作员、对象范围和一次性授权；verify阶段在SQL之外，其他阶段必须使用当前本地权限核验，不执行网络或通知投递。预算在历史和操作者查询之前检查，最终预算和当前审批／权限会再次复核。

该动作关闭整个配置的工作进程权威；这不是一次只影响单个请求的轻量操作。review还返回 `closes_worker_authority`、`revokes_active_credentials` 和 `decision_retention_seconds`。管理员应在维护与权威交接安排明确后审批。有效账号会推进凭据版本，密码、邮箱、角色、MFA要求、目录绑定与物理因子保持；停用／缺失身份保持原样。结果始终说明原操作结果未知，不重新执行旧操作或交付旧恢复码。继续业务须显式强审批轮换到新的权威，不能重新打开旧文件。

处置在原行记录严格格式2的abandoned状态及独立resolution元数据，原创建／到期字段保持。维护同时检查原保留期和从本次处置开始的新保留期，极旧意图不能立即被删除。新标记需要同步升级所有管理读取器；旧读取器安全拒绝。新旧权威的预览不能互用。

提交回执丢失、授权排空后的持久化失败或SQL提交后的权威检查异常，均报告 `account.completion_unknown`。审计／通知或宿主CAS不符合契约时回滚SQL，权威保持关闭。权威文件仍有效时，由宿主持有准确关闭EX上下文，调用 `inspectClosed()` 核对；未完成的prepared可用 `reviewClosed()` 和新的独立审批执行 `abandonClosed()`，不重复已完成的处置。文件本身损坏时不能自动补建或重写为open，需独立运维恢复；完整独立备份／退役恢复能力仍在规划中。

## 本地验证

选择已安装 ext-sodium、pdo_sqlite 的 PHP 运行时：

```sh
python3 tests/account_factor.py php
python3 tests/mysql_check.py --account-factors php
python3 tests/account_factor_consumer.py php
```

第一条只使用自动创建的临时 SQLite 与私有因子目录。第二条创建禁用 TCP 的独立 MySQL，通过专属 Unix socket 顺序执行两种物理后端；测试拒绝不属于控制器的 MySQL 路径，禁止指向业务数据库。第三条通过全新Composer消费者安装独立包副本，确认`Security`和恢复类来自安装包，再运行工厂真实密码／TOTP登录、缺配置／权限拒绝，以及恢复、取消／保留期、认证及三用途维护故障检查；测试代码位于临时消费者，示例与SQL资源均使用安装包中的文件，不加载SDK工作树的自动加载器。该消费者检查已加入CI。PHP7.2／8.5两端各五组本地通过，当前454文件ZIP归档含本指南、原生登录样例与因子源码。常规 `bin/check.sh` 已纳入可移植测试，缺少可选加密扩展时明确未执行；要求完整加密验收时应设置 `SOSECURITY_REQUIRE_CRYPTO=1`。

仅本地测试通过不代表生产持久化、宿主权限、真实浏览器、远端 CI、发布或独立安全审查通过。完整范围继续以[规划](security-refinement.md)为准。

本地工作／关闭清理的借用现已核对进程、原生Fiber和有效句柄，并避免子进程替父进程释放锁；同上下文嵌套保持。详见[执行上下文与锁清理](account-fence-context.md)。正式部署仍须排空并重载旧工作进程，不能把本地源码修复当作生产更新。
