# 独立见证与认证状态边界

受保护宿主现已补齐两端本地 MySQL HTTP／TLS，并使用持续 `SystemClock`，八次观察均确认凭证在回调开始时有效、结束时到期，且认证来源和见证未写入。SQL／认证文件／PHP 会话联合回放仍被拒绝；不是业务 PDO 事务组合或完整恢复提交。见[当前后端与时钟记录](state-http-mysql-integration-2026-10-21.md)。

现有受管认证示例支持明确的私有 `Security`／`state_policy` 组合，并在 CSRF 前避免原生会话更新，分离 Cookie 管理与无 Cookie 的 Bearer 路由。两端本地 SQLite HTTP／TLS 及真实 Chromium 已核对，联合恢复旧 SQL／认证文件／PHP 会话仍拒绝旧权限；不是全部宿主或安全恢复提交。接线、HTML 回引策略和证书限定见[宿主记录](state-http-integration-2026-10-21.md)。

原生账号 API 的 pending／current 现在记录同一准确意图：操作者、目标、已验证凭证摘要、标准化参数、实际身份／范围、完整来源和准确策略。`StateOperation::credential()` 只是不可变描述，不是认证或批准；RolePolicy 指纹覆盖完整规则。格式 2／3 保留原结构，未知效果不重放。两点真实强杀及范围见[意图记录](state-api-intent-integration-2026-10-21.md)。

账号凭证公开工厂现在通过 `Security::apiCredentials($stateAccountPolicy)` 接入原生写入前准入。八个入口在完整来源下只读核对账号／因子／会话／API 账本，普通拒绝不产生 pending；原构造和普通模式保留，新的原生模式禁止外套 `run()`。委托只支持同一提供方的纯 `RolePolicy`；自定义／带审计委托、其他 API 工厂及最终恢复仍未完成。见[公开接线记录](state-api-entry-integration-2026-10-21.md)。此前固定代际退役和手工活跃边界的历史验收见[退役记录](state-managed-api-integration-2026-10-21.md)。

旧版 `ApiKeys` 的主体代际已提供原生处置：`StateApiKeyRetirement`、`apiKeyRetirementReview()`／`retireApiKeys()` 和新批准续办，固定写入同一实际 namespace 的永久标记。格式 1 密钥在标记存在时拒绝，格式 2 须匹配当前代际；标记本身不证明新鲜性，仍须完整来源见证。账号字段不变、隔离不解除；受保护 API 工厂仍拒绝未接线能力，禁止旧 API 代码混合部署。见[本组记录](state-api-retirement-integration-2026-10-21.md)。

安装的 `prepare()`／`resume()` 可在末尾显式传入同一 `SessionRegistry` 和其实际 `FileStore`，将会话／记住登录清空及固定新 epoch 纳入同一批准清单，待完成的旧登录不能继续。清单格式 3 必须恢复准确服务图；格式 2 保留原安装语义，不代表清空会话。账号继续隔离，旧版 `ApiKeys` 等其他授权尚未完成处置。见[本组记录](state-session-retirement-integration-2026-10-21.md)。

文件来源指纹现为 `FileSnapshot.Profile.3`：严格校验但不采用最多 64 个、每个 64 KiB 的 `stage-0` 至 `stage-63` 私有暂存槽；正式认证字节仍完整纳入来源。受保护 FileStore 和原生恢复写入复用固定槽，进程终止不再留下随机暂存节点。新旧来源不可混用，不能删除或初始化旧见证绕过迁移。三个安装持久化点的真实 SIGKILL 与独立进程续办见[当前中断记录](state-crash-integration-2026-10-21.md)。

`StateCredentialInstallation` 通过 `credentialInstallationReview()`／`installCredentials()` 固定写入新因子及账号／目录三行 SQL，并消费原候选。未知效果只能凭持久原清单、`credentialResolutionReview()` 与新的独立强批准续办；完成仍保持账号停用和隔离。安装清单格式 2、审计记录格式 2（兼容读取 1）不支持混合旧读取器部署。详见[当前安装记录](state-installation-integration-2026-10-21.md)。

`StateRecoveryCredentials` 可在独立受保护 FileStore 中持久准备随机新密码和加密的新 TOTP。候选绑定已审计完成禁用的准确行、来源及隔离根，最多四份／300 秒／五次确认；服务重建保留状态，旧文件回放由独立见证拒绝。`confirm()` 要求新密码和真实 TOTP，`describe()` 仅提供非秘密候选摘要；二者均不安装凭据或开放账号。必须继续独立批准的固定写入和最终恢复。见[凭据准备记录](state-credentials-integration-2026-10-21.md)。

恢复审计现在可通过 `StateRecoveryAudit` 显式注入见证构造函数的末尾可选参数。关闭及隔离处置先稳定追加签名记录，再发布根引用；记录缺失、篡改或回退时拒绝。`recoveryHistory()` 每页最多四条，重启可追溯原审批和各次续办；容量固定 256 条，孤立记录也计入，不自动采用或清理。历史不完整明确标记，审计存在不等于最终恢复已完成。格式 2／3 根字段扩展，旧读者不能混用。见[耐久审计记录](state-recovery-audit-integration-2026-10-21.md)。

账号禁用的未知结果现在可通过 `accountResolutionReview()`／`resolveAccounts()` 续办，要求新的 `state.accounts.resolve` 批准。只有原操作写入前封存的行摘要清单有效；旧批准、缺少清单的历史根和未登记字节均拒绝。续办沿用原禁用版本，不启用账号、不更换可信摘要，仍处于隔离。格式 3 字段语义扩展，不允许混用旧读者。见[账号续办记录](state-account-resolution-integration-2026-10-21.md)。

陈旧 current 与 pending 使用不同的关闭审批：`staleReview()`／`retireStale()` 要求 `state.retire_stale`，原 `retirementReview()`／`retirePending()` 使用 `state.retire_unknown`。须显式配置准确资源字段和恢复管理员角色。新入口保留原可信摘要，只进入 closed 和后续 quarantined；不会采用旧备份摘要或重新开放账号。格式 2／3 的合法状态语义已扩展，旧读者可能拒绝新回执，不能混用部署。详见[专项记录](state-stale-integration-2026-10-21.md)。

这是未发布候选的显式接入接口。当前主 SDK 已接入见证、认证边界及分阶段隔离恢复；完整工厂／全入口覆盖和最终安全恢复仍未完成，不能据此关闭 F01 或判断可发行。准确实现、快照及验收范围见[接入记录](state-boundary-integration-2026-10-21.md)。[English](state-boundary.en.md)。

## 独立状态与声明范围

HMAC 证明完整性，不能证明状态足够新。联合恢复旧账号 SQL、会话和因子文件，可能同时恢复旧权限与有效签名。`LocalStateWitness` 在这些备份之外保存签名检查点；入口先比较完整来源，再持久化 pending，最后才允许业务效果。来源与检查点不一致时，在身份提供器及业务调用之前拒绝。

宿主必须声明实际启用的账号字段、目录／意图／审计、会话、因子、持久登录及其他授权效果，登记全部写入者。没有声明的服务不因存在一个见证而自动受保护。当前受保护物理存储仅接受准确覆盖的 `FileStore`，包括其 namespace 包装；这不表示普通 SDK 已停止支持其他后端。其他受保护后端的适配仍未完成，不能改用任意摘要回调来绕过拒绝。

见证、SQL／认证文件及采集临时目录需要独立的物理域。SDK 检查明显重叠、准确 PDO、固定来源和文件身份；部署还必须让见证不随业务备份一起恢复。需要使用具体 `SqlStateSnapshot`／`FileStateSnapshot`／`CompositeStateSnapshot`，格式 2 或后续隔离恢复格式 3；格式 1 不能用于受保护认证。

初始化是独立审批的首次采用，不是应用启动动作。由宿主停写、审阅完整状态并取得预期摘要后，显式调用 `initialize($expectedDigest)`；禁止在异常后自动取当前摘要重新初始化。

## 显式构造认证服务图

以下仅展示已有依赖准备后的构造顺序，不包含来源声明、初始化或完整部署。`$witness` 必须对应已审批的准确服务图，`$store` 必须是被覆盖的原始 FileStore，`$provider`、`$managedFactor`、时钟和密钥必须复用同一组准确依赖；受管理因子工作进程还须使用绑定同一边界的栅栏。后文的显式认证配置现在可以复用工厂；普通配置仍不自动启用保护。

```php
$boundary = new SoSecurity\Account\StateBoundary($witness, $operationBudgets);
$requests = new SoSecurity\Account\StateRequests($publicRequestCheck, $currentAdmission);

$sessions = new SoSecurity\Auth\SessionRegistry(
    $store, $provider, $managedFactor, $clock, 1800, 28800, 16, $boundary
);
$authentication = new SoSecurity\Auth\AuthenticationFlow(
    $store, $provider, $sessions, $requests, $managedFactor, $clock,
    300, 10, 5, $boundary
);
$remember = new SoSecurity\Auth\RememberedLogin(
    $store, $provider, $sessions, $rememberKeys, $requests, $managedFactor, $clock,
    2592000, 8, 300, 5, $riskGuard, $boundary
);
```

`$operationBudgets($phase, $action)` 对 `public`／`final` 阶段返回严格的 `true`。公开请求检查在锁前确认来源、CSRF 和请求预算；`$currentAdmission($action, $scope)` 在锁内、pending 前只读确认准入。它不能修改受保护数据、消费因子或签发授权，也不代替账号权限策略。独立预算不得写入同一被采集物理目录。未绑定的旧服务不能继续访问已登记目录。

同一操作内的会话与因子调用复用外层检查点；不能给每个内部 SQL 事务单独完成见证。长驻进程要复用准确边界，不能反复构造对象来替换已绑定目录的权威。每进程最多绑定 128 个物理目录；新代际切换须停止旧写入者并重新引导进程，当前不提供热解绑。

保护模式的单次授权服务也需要追加同一个边界：

```php
$grants = new SoSecurity\Operation\Grants(
    $store, $sessions, $authorizer, $grantRequestGuard, $grantPolicy, $clock, $boundary
);
```

`$grantRequestGuard` 是授权组件原有的无参数请求检查，不直接传入需要 action／scope 两个参数的 `StateRequests`。宿主须在进入外层边界前完成公开 CSRF／来源和预算检查；活动上下文内的防御检查不代替该阶段。`SessionRegistry::requiresStateBoundary()` 只查询保护模式，不证明当前请求有权限。保护会话不能与未保护的挑战／授权存储混用。详见[入口修复](state-entry-fix-2026-10-21.md)。

## 显式认证工厂

已有受管理因子配置和准确服务依赖时，可以追加以下配置。`$store` 是完整来源声明中的准确原始 FileStore；身份服务必须为 `PasswordIdentityProvider`，请求守卫实现 `StateRequestGuard`，因子栅栏已绑定同一边界和上下文。当前纯权限视图要求会话与因子使用同一完整文件域，工厂时钟与原始因子时钟一致。以下片段不创建数据库、见证或栅栏，也不是完整部署：

```php
$config['authentication']['managed_factors'] = true;
$config['authentication']['state_boundary'] = [
    'authority' => 'state_authority',
    'store' => 'authentication_files',
    'scope' => $scope,
    'epoch' => $trustedEpoch,
];
$services['state_authority'] = $boundary;
$services['authentication_files'] = $store;
$sdk = SoSecurity\Security::fromArray($config, $services, $clock);
$policy = $sdk->stateAccountPolicy(
    $witness, $source, $sqlSource, $fileSource,
    $sqlName, $fileName, $accountTable, $columns
);
```

`$columns` 是固定账号表的八项字段映射，来源对象和名称必须与准确见证一致。工厂复用会话、认证、持久登录、目录、因子及授权对象，纯策略也从这份实际图构造；不需要重建或猜测内部因子对象。普通未保护工厂的构造行为保留。

`operations.request_guard` 须另配无参数检查；独立公共预算放在认证文件域之外。诊断仅将准确依赖标为 `manual`，不读取当前见证、不自动初始化、不证明已部署验收。生命周期服务现可通过 `StateAccountConnection` 显式声明完整 SQL 来源，再在准确外层边界中调用；未声明时拒绝。见[生命周期接入记录](state-lifecycle-integration-2026-10-21.md)。原生请求前置检查及完整流程验收仍待完成。旧重设证明及其他尚未接入的授权／重放状态入口在保护配置下继续明确拒绝；这些仍属于完整计划待完成项。具体能力、失败及范围见[工厂接入记录](state-factory-integration-2026-10-21.md)。

## 生命周期公开方法的前置准入

注册、密码找回、邮箱丢失恢复可另配 `accounts.state_request_guard`，依赖必须实现 `StateRequestGuard`，并先创建准确 `StateAccountConnection`。三个服务的 `request`／`confirm`／`cancel` 随后自行处理外层操作；不要再先调用 `run()` 包装这些方法。格式检查及公共预算在 pending 前完成，同一预算编号复用于后续阶段，锁内重新检查请求守卫。原有业务权限、受管理恢复码和独立审批继续保留。

地址变更、私有审批预览、初始化、通知和维护不通过该公开入口暴露。已确认完整回滚、执行上下文更新且完整来源未变的预算拒绝可结束 pending，见[预算拒绝记录](state-budget-integration-2026-10-21.md)。已有提交进展、见证最终预算拒绝和真实 HTTP／CSRF 联合验收仍待完成；不能用请求守卫替代账号／一次性操作授权。准确顺序、MySQL 修复及剩余工作见[公开请求接入记录](state-request-integration-2026-10-21.md)。

## 当前账号权限

高风险操作使用准确服务图构造的 `StateAccountPolicy`、服务端生成的 `StatePermission`，再调用 `StateBoundary::authorized($action, $scope, $target, $policy, $permission, $operation)`。动作、scope 和目标必须完全一致；角色、强度、认证新鲜度和允许方法由服务端要求决定，不能照抄请求参数。

策略从与见证一致的同次采集中纯读取账号、会话、账本及物理因子，不调用另一份身份提供器或消费证明。普通权限拒绝发生在 pending 前，后续合法请求仍可继续。`StatePermission` 本身不是批准；`run()` 也不是请求身份或对象权限的替代品，不能把任意客户端动作映射成可调用闭包。

## 持久化与故障处理

`LocalStatePersistence($canonicalDirectory, $milliseconds, $python)` 是可选 Linux／Python 3 适配；要求准确的私有 0700 目录、同所有者的 0600 单链接文件，以及进程控制功能。构造不创建状态或启动进程。调用时对准确继承的文件与目录描述符校验并执行 `fsync`，包括文件原子重命名后的场景；不能用 `fflush()` 或恒真回调代替。基础密码／CSRF 组件不依赖此适配。

| 结果 | 宿主应采取的动作 |
| --- | --- |
| 正常准入／权限拒绝 | 返回统一拒绝；不清空见证、不重建状态 |
| `account.witness_stale` | 停止受影响服务图的业务效果，核对恢复及越界写入，进入独立恢复流程 |
| `account.witness_pending` | 保留未决状态；不能重放原业务操作或自动采用数据库 |
| `account.completion_unknown` | 业务或持久化完成情况不确定；保留原根、错误及实际 SQL／物理效果，独立审阅和对账 |
| `storage.clock`／预算超时 | 保留拒绝；若已进入 pending，按未知结果处理，不延长期限掩盖问题 |

SQL 回滚不证明邮件、外部审批或文件效果已回滚。AtomicStore 的事务回调仍必须保持纯函数、可重试，不能把这些 I/O、随机值或见证操作放进去。操作成功才返回结果；未知结果不能简单自动重试。

现有 `StateRetirementControl` 及各审阅／固定处置类型支持独立当前管理员、近期强认证、一次性批准、关闭旧根和隔离新代际，以及准确账号／因子处置与续办。**当前这些步骤仍保持 quarantined，没有最终恢复业务可用的提交接口。** 不能把禁用账号或清除因子当作完整恢复成功。

当前本地检查包含真实联合备份和省略保护后的危险对照；它们覆盖声明的固定测试服务图，不证明全部启用能力或真实掉电耐久性。PHP7.2 私有单调时钟、Fiber 差异、MySQL 元数据权限及未执行项见[验证记录](verification.md)。完整验收继续按[有限周期计划](full-plan-2026-10-21.md)执行。

## Bearer 与业务 PDO 事务组合

原生保护工厂返回的 `CredentialRegistry` 提供 `withAuthorization($scope, $authorizationHeader, $requiredScope, $pdo, $tables, $businessPolicy, $prepare, $work)`。直接调用，不套外层 `run()`，不先开启宿主事务。`$pdo` 必须是当前完整 SQL 来源使用的同一实例；一至四张业务表须按完整 `columns`／`primary`／可选 `where` 声明并已纳入该来源。不能把未声明表、独立连接或任意外部效果纳入其原子性声明。

独立见证锁覆盖完整流程：原生只读凭证准入、`$prepare(PDO, VerifiedCredential)` 读取服务端对象并返回已验证参数的 `Operation\Intent`、纯 `RolePolicy` 对对象及请求字段授权，然后 durable pending、真实凭证复查与使用记录、SDK 自有 SQL 事务、最终来源确认和 current。准入阶段的凭证、对象或字段拒绝在 pending 前结束；业务回调 `$work(PDO, VerifiedCredential, Intent)` 只调用一次，返回值仅在整个入口成功返回后可作为成功结果。

`$prepare` 是受信任宿主的只读代码，不能更新状态、发送消息、修改事务或使用客户端自报对象属性。`$work` 仅通过提供的 PDO 修改已声明业务表，应使用绑定的 Intent 和版本比较更新；不得执行 DDL、COMMIT／ROLLBACK、切换连接或发送外部请求。全部相关写入者须共用见证与围栏。SDK 不解析或沙箱化任意 PHP／SQL 回调；绕开这些约定的写入者仍是未验收缺口。

凭证在提交前／后复查到期和时间倒退。SQL 回滚不等于认证文件的使用记录也已回滚；一旦进入效果阶段的异常、事务所有权丢失或最终确认失败，保留 `account.completion_unknown`／pending，不重放业务。准确回执绑定服务端 Intent、业务策略、表名、凭证摘要及完整来源，不存业务明文。示例 [StateDocuments.php](../examples/StateDocuments.php) 展示服务端读取、所有者／editor／title 权限及版本比较更新；不自动创建业务表。

## 原生业务 HTTP 接入

受管认证示例的私有引导包可按顺序返回 `security`、`state_policy`、`business_connection` 三个字段；前两字段与原保护模式一致，第三字段是准确 SQL 来源的同一 PDO。原二字段包和普通 Security 对象继续保留。业务表必须在首次可信初始化前经独立迁移创建并完整声明；不要在请求中自动建表或更新见证来源。

`POST /managed-authentication.php?api=document` 仅接受 `application/x-www-form-urlencoded`，字段为 `action=rename&id=...&version=...&title=...`，要求 `Accept: application/json` 和 `Authorization: Bearer ...` 的 `records:write` 能力。Cookie、`_csrf`、自报 owner 均不能替代实际权限。客户端提交 Origin 时必须与配置来源完全一致。成功返回 `document.id` 与新 `document.version`，不创建 PHP 会话，不返回 Cookie 或 CSRF。文档由服务器加载，editor／实际所有者／title 字段由纯 RolePolicy 核对。

格式 3 实际宿主、浏览器、联合备份回放、三个真实 SIGKILL 点及并发等待后拒绝的有限证据见[宿主接入记录](state-business-host-integration-2026-10-21.md)。未知结果继续按 pending 处置，不通过 HTTP 暴露恢复、初始化或维护操作。

## 原生一次性操作

`operations($stateAccountPolicy)` 显式选择五个公开方法的原生只读准入；请求守卫、真实当前会话和纯 RolePolicy 在 pending 前检查。默认 operations() 保留原有手工外层授权组合，原生实例不作为嵌套的恢复审批依赖。原生业务使用 execute 将受信任只读 Intent 加载、证明消费、自有 SQL 和最终 current 纳入同一次见证；正常参数篡改销毁、SQL 回滚不退还证明、未知结果不重放。准确调用、消费者及未验收边界见[原生操作记录](state-grants-integration-2026-10-22.md)与[操作指南](operations.md)。
