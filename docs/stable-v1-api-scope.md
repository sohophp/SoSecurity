# 1.0.0公开API与实验范围（管理已签收，仅S稳定）

2026-10-25。本文件登记管理在6de2a35已签收的首版S方法及部署限制；固定基础门禁及先前本地包管理复核均已完成；本次中文文档交付包的准确提交、摘要与最小安装验证以包外交付清单为准，S/E名单与调用限制不变，未公开发布，不新增/删除接口，不修改候选契约。依据 [管理范围](stable-v1-management-2026-10-25.md) 与 [管理审查](stable-v1-review-2026-10-25.md)；运行时基线为 `fedc471fae6cb7d623904f1d50bc041357a178a1`，管理文档基线为 `66f2722`。配套执行清单见 [固定验收](stable-v1-acceptance.md)。历史完整愿景保留后续，不自动进入本版任务队列。

## 分类规则

- **S（1.0.0稳定承诺，限已签收调用方式）**：仅承诺下列普通调用方式、依赖与后端。每个公开类型逐项列于末尾；方法名对应原候选完整签名，不创建新签名或修改默认值。
- **E（实验/首版不作稳定承诺）**：已有API仍保留，不代表无缺陷或可以安全投产。类型/方法仍受既有权限、审批、状态连接与隔离限制约束。本版不调用暂缓流程验证它们。
- 同一类型可有S和E方法；表中的S不得覆盖下文明确排除的方法、参数组合或配置。构造函数可接收E类型，不意味着该组合取得稳定承诺。错误、值对象和接口的契约保留不等于所有使用它的流程稳定。
- 本表覆盖主包实际清单278个类/接口；独立 `integrations/*` Composer包不进入首版稳定范围，已有源文件与API保持。命名空间内部类型仍按 `resources/api/internal.json` 管理，不因本表变为公开API。

## 基础接入范围

| 编号 | 稳定承诺用途 | 运行时和依赖边界 | 固定验收 | 接入说明（docs/） |
| --- | --- | --- | --- | --- |
| S01 | CSRF | PHP7.2—8.5；ext-session或独立AtomicStore；SignedTokens显式HmacKeys | F01、F02、H01、H04 | configuration.md / signed-csrf.md |
| S02 | 本地验证码 | PHP7.2—8.5；算术无GD；图片/交互验证码需ext-gd；状态需AtomicStore | F02、H01 | captcha.md |
| S03 | 限流和封禁/请求预算 | PHP7.2—8.5；跨请求使用FileStore、RedisStore或MySqlStore；MemoryStore不作生产共享承诺 | F03、B01—B04、H01 | configuration.md；examples/configuration-presets.php |
| S04 | 密码安全 | PHP7.2—8.5；bcrypt；Argon2id仅编译支持时可选，不回退减弱算法 | F04 | passwords.md |
| S05 | 普通宿主认证和会话登记 | PHP7.2—8.5；宿主IdentityProvider/请求保护；state boundary为null；本版稳定承诺限普通密码会话 | F05、B04、H01 | authentication.md |
| S06 | 原生PHP会话安全 | PHP7.2—8.5；ext-session；宿主负责Session启动时机、HTTPS和请求生命周期 | F05、H01、H04 | authentication.md |
| S07 | 输入验证和输出编码 | PHP7.2—8.5；Escaper按HTML/属性/URL/JS上下文使用；不包含HTML净化 | F06 | validation.md |
| S08 | HTTP边界策略 | PHP7.2—8.5；可信代理明确配置；CORS不替代认证/CSRF；PHP7.2—8.5 | F06、H01、H04 | http-policy.md |
| S09 | 受限上传 | PHP7.2—8.5；ext-fileinfo；图片检查需GD；私有目录与显式Scanner；不包含隔离队列/ClamAV服务 | F07、H03 | upload.md |
| S10 | 受限出站请求 | PHP7.2—8.5；显式主机/地址策略；原生传输需ext-curl及TLS/CA；本地命名空间验证 | F08、H06 | outbound.md |
| S11 | 普通API密钥和HMAC鉴权 | PHP7.2—8.5；共享AtomicStore；state参数为null；普通Bearer使用ApiKeys | F09、B02、B03、H02 | api.md |
| S12 | Webhook验签 | PHP7.2—8.5；四个已有协议；Ed25519需ext-sodium；显式当前密钥/请求保护；不承诺收件处理编排 | F10、H05、Q01 | webhooks.md |
| S13 | 工厂/存储/错误/时钟基础 | PHP7.2—8.5；配置按需惰性启用；具体方法及共享底层限制见下文；后端不能互相冒充 | G01、F11、B01—B04、C01 | configuration.md / mysql.md |
| S14 | 普通授权和审计依赖 | PHP7.2—8.5；当前宿主权限提供者；不配置SnapshotPolicy/StateBoundary/SQL审计委托 | F12 | authorization.md / audit-budget.md |

宿主仍拥有路由、账号数据、权限事实、数据库连接及业务事务。验证码答案/CSRF绑定必须来自可信会话上下文；安全上传仅信任真实上传来源或明确的服务器文件入口；API验签针对原始请求字节。共享限流/防重放不得用MemoryStore或单会话SessionStore替代。自定义AtomicStore/Resolver/Transport/身份提供者必须承担文档规定的原子性、时限和当前权限契约；本地桩实现通过不构成任意第三方适配器承诺。

## 混合类型的方法与启用条件

| 现有入口 | S调用方式 | E入口/组合及现有限制 |
| --- | --- | --- |
| `Security` | `fromArray`、`config`、`csrf`、`csrfPolicy`、`signedCsrf`、`captcha`、`rateLimiter`、`budgetLimiter`、`budgetGroup`、`budgetComposite`、`sessions`、`authentication`、`authorization`、`passwordHasher`、`passwordPolicy`、`outbound`、`apiKeys`、`hmacSigner`、`hmacVerifier`、`uploader`、`session`、`configureSession`、`sessionCookieHeader`、`diagnose(null,false)`、`initializeStorage(false)`；下列参数限制同时适用 | 其余工厂方法，包括 `apiCredentials`、`webhookInbox`、`webhookProcessor`、`stateAccountPolicy`、`stateAccountConnection`、账号/恢复/因子、租约/操作授权/签名链接/下载、隔离上传、HTML净化、幂等/发件箱、持久登录；`diagnose`主动探测及`initializeStorage(true)`不作首版稳定承诺。`webhook(name)`仅普通无状态连接验签列入S |
| `Configuration\Config` | 读取S模块配置；未配置的模块保持未启用；普通`authentication.state_boundary=null` | 配置受保护状态边界、managed factors、原生委托等仍要求完整精确服务图；不能省略连接退回普通模式。E模块的getter只保证旧契约保留，不获得功能稳定承诺 |
| `Csrf\CsrfTokens`、`Captcha\Captcha`、`Api\ApiKeys` | `state=null`，独立普通存储；`ApiKeys::stateEpoch`不列入S | `StateProofConnection`/`StateApiKeyConnection`等受保护连接均为E；不允许把已受保护FileStore换成无状态连接绕过保护 |
| `Api\HmacVerifier` | 普通构造与`verify`，精确KeyProvider和NonceStore；原始请求/作用域校验 | `verifyFor`、`withVerification`及StateAccountPolicy/密钥快照/原生业务事务组合为E |
| `Webhook\Verifier` | 普通构造、`endpoint`和`verify`；`Security::webhook`未配置state_connection | `stateContext`及受保护`StateWebhookConnection`、历史收件/查询/处理等为E；Q01/H05仍用于评估共享底层和已知失败，不因此承诺稳定 |
| `Auth\SessionRegistry` | 无StateBoundary的普通登记、验证、替换、列举、撤销、全部撤销；每次读取当前宿主身份 | `boundTo`、`credentialInstallationContext`、`credentialRegistryContext`、`operationRolePolicy`、`operationSnapshotPolicy`、`statePolicy`、`requiresStateBoundary`以及与原生边界/管理流程衔接的组合为E；诊断返回不作为授权依据 |
| `Auth\AuthenticationFlow` | 无StateBoundary的密码流程、取消；已声明MFA的账号必须按既有行为拒绝/进入挑战，不能为本版关闭MFA | `secondFactor`及实际因子集成流程首版不作稳定承诺。测试中的普通TOTP/恢复码属于附加耦合检查，不是最终账号恢复启用或跨代际恢复 |
| `Authorization\Authorizer` | 普通PolicyProvider/CallbackPolicy/RolePolicy的决定、批量、断言与投影 | `stateAuditedPolicy`、`stateRolePolicy`、`stateSnapshotPolicy`及SnapshotPolicy组合为E；不得缓存权限事实来规避复核 |
| `Storage\FileStore` | 普通未绑定目录下的构造、`transact`、`prune`、`pruneBatch`；`usesClock`只作上下文匹配 | `bindStateBoundary`、`containState`、`resolveState`、`installCredentialState`、`retireApiKeyState`、`retireProofState`、`snapshotBinding`、`snapshotFile`、`snapshotReference`为E；目录已被绑定时不能转成普通目录或移除保护标记 |
| `Storage\MySqlStore` | 普通专用连接的安装、构造、原子变更及清理；`schema`为当前结构描述 | 安装/变更不加入调用者已有事务；不接管宿主回滚。高级组件通过相同PDO或共享事务工具使用它时，仍需独立耦合证明 |
| `Diagnostics\Inspector` / `Audit\AuditLogger` | 普通只读诊断和本地脱敏事件；诊断不构成安全认证 | 恢复/修复型操作、SQL审计委托与复杂审计发件箱为E；宿主自行注入的远程投递不在本地验收范围 |

## 首版最终源码路径核对（2026-10-25，fedc471；6de2a35已签收限制方案）

本表核对上文S用途和混合方法的普通分支，不改变完整类型登记、方法契约或S/E名单。源码与当前`fc395be`候选的src/resources/tests/examples一致；G/B/F/H/C及本轮Q01/Q02分别提供执行证据。这里的隔离结论限于不配置/调用E入口、不混用受保护目录或连接的部署；不能证明任意自定义服务、同进程E调用或所有未来缺陷都被隔离。

| 已审S方法/用途 | 实际普通调用路径与默认分支 | 实验路径的边界及现有证据 |
| --- | --- | --- |
| S01/S02：`Security::csrf/captcha/csrfPolicy/signedCsrf` | `proofStore(null)`→`authBoundary()`缺省null→`store('tokens')`；Config缺省token_storage为SessionStore。CsrfTokens/Captcha的state为null时直接调用普通AtomicStore；signedCsrf只取显式HmacKeys和Clock | 配置保护边界却未传完整proof连接时抛configuration.state_proof，不退回普通模式；不调用账号注册/恢复。F01/F02/F11、H01/H04、C01覆盖普通分支 |
| S03：`rateLimiter/budgetLimiter/budgetGroup/budgetComposite` | rateLimiter→`store('shared')`→普通RateLimiter；预算方法→`apiStore(true)`→相同共享存储。拒绝MemoryStore/SessionStore承担跨会话预算 | `store`末尾检查与捕获认证目录重叠并拒绝；不调用管理凭据。F03/B04/H01/C01覆盖；自定义AtomicStore的原子性/预算仍属宿主契约 |
| S04：`passwordHasher/passwordPolicy` | 根据password配置构造本地哈希/策略，默认不接外部breach_checker；不读取账号或启动管理状态 | Argon2id依实际构建能力；可选外部检查服务不由本地验收替代。F04、H01/C01覆盖bcrypt及算法拒绝 |
| S05：`sessions/authentication`及普通SessionRegistry/AuthenticationFlow方法 | `authBoundary`缺省null；`authFactor`在managed_factors=false、second_factor=null且mfa未配置时返回null；通过宿主IdentityProvider及request_guard走普通会话/密码路径 | 缺认证配置/守卫即拒绝；只有显式配置才调用managedSecondFactor或StateBoundary。已启用MFA的账号不会因此降级。F05/F11、H01、C01提供基础与当前身份变化证据 |
| S06/S08：`session/configureSession/sessionCookieHeader`及HTTP策略 | SessionSecurity的时间/轮换及显式原生配置、Cookie构造；ClientIp/TrustedProxies/CORS/Headers按独立策略处理 | fromArray不自动启动Session/发头；代理/会话生命周期由宿主负责。F05/F06、H01/H04、C01覆盖 |
| S07：验证/输出编码 | Validator/Rule及上下文Escaper直接执行有界输入和编码；不通过账号管理或SqlInbox | HTML净化/高级可选适配不自动随基础编码启用。F06覆盖，S不包含未验收的E组合 |
| S09：`uploader`及普通上传方法 | `Security::uploader`→Upload\Saver/Policy；与`quarantine()`分开，不构造扫描任务/租约/SqlProcessor | 原始上传来源、MIME/大小/资源检查仍执行；自定义Scanner/Storage须满足契约。F07/B01/H03/C01覆盖真实故障及multipart |
| S10：`outbound`及普通出站方法 | `Security::outbound`→Http\Outbound\Client，显式Resolver/Transport；普通真实cURL路径不调Outbox/工作进程 | SSRF、固定地址/TLS和Deadline仍共享；F08/H06已分别覆盖适配故障及真实隔离网络，非真实外部服务通过 |
| S11：`apiKeys(null)`及普通ApiKeys方法 | `apiStore()`在authBoundary非null时拒绝普通入口；否则构造`new ApiKeys(store,clock)`，state缺省null，issue/authenticate/revoke走普通存储/epoch，不构造CredentialRegistry | CredentialRegistry只由`apiCredentials`显式调用，旧account.completion_unknown不进入此图；普通ApiKeys自身仍可能api.issuance_unknown，不允许自动重试。F09/B02/B03/H02/C01覆盖 |
| S11：`hmacSigner/hmacVerifier()`及`HmacVerifier::verify` | 普通SignaturePolicy/KeyProvider/NonceStore；构造器state/boundary均null。verify检查候选、consume nonce、最终时效，不调用native/withVerification | 额外状态图参数不完整即拒绝；受保护图只能用E方法，不能混用普通verify。F09/H02/C01验证原始字节/重放/权限/故障 |
| S12：`webhook(name)`与`Verifier::endpoint/verify` | `webhookState`缺省返回null；工厂只构造Endpoint/Verifier。verify→当前请求守卫、Wire、两次密钥复核、时效；无PDO、SqlInbox、关联表或业务处理调用 | SqlInbox仅由webhookInbox显式构造，SqlProcessor同理；普通验签不提供耐久收件/去重保证。F10/H05及Q01当前收件专项分别记录，不能互相替代 |
| S13：`fromArray/config/diagnose(null,false)/initializeStorage(false)` | fromArray仅Config与SystemClock；高级配置块仅在显式提供时校验，未提供保持null/空。Inspector默认probe=false；显式initializeStorage(false)仅遍历shared/tokens普通后端 | initializeStorage不是请求故障自动修复入口；true恢复参数仍E。F11及最小工厂/C01证明无高级服务依赖；诊断不构成授权或稳定认证 |
| S14：`authorization`、普通Authorizer方法和本地AuditLogger | 普通IdentityProvider/PolicyProvider/本地审计；未配置Policy默认拒绝，受审计允许决定返回前重新读取当前身份 | stateAudited/Role/Snapshot及SQL审计委托仍E；任意注入sink/策略不由工厂自动隔离。F12与已有当前权限回归覆盖普通拒绝/复核 |
| 共享FileStore | 普通transact/prune仍经FileStateBoundary::assertActive；未绑定物理目录不调用保护闭包，绑定后不能绕过；锁、读取、原子写入和Deadline共同执行 | 保护域是进程内物理目录身份，不是仅namespace。限制方案要求S与E目录不混用、S部署不注册E操作；B01/C01验证普通路径，不能把删除标记/换目录当迁移 |
| 共享SQL | MySqlStore的owned/install用SqlTransactionGuard::assertIdle及SqlSchema检查；自己begin/commit/清理并恢复会话策略。它不调SqlInbox、SqlProcessor或高级SqlTransaction编排 | Guard/SqlSchema/Deadline仍共享；专用PDO，不加入宿主已有事务；B03全部事务/索引/错误模式与C01实测支撑普通路径。未知提交/清理失败仍拒绝且不重试 |

对应源码：[工厂](../src/Security.php)、[Config](../src/Configuration/Config.php)、[ApiKeys](../src/Api/ApiKeys.php)、[HMAC](../src/Api/HmacVerifier.php)、[Webhook](../src/Webhook/Verifier.php)、[文件保护域](../src/Storage/FileStateBoundary.php)、[MySQL](../src/Storage/MySqlStore.php)、[Deadline](../src/Support/Deadline.php)。这不是根据类型名称推断，也没有用新测试框架替代源码核对。

**6de2a35已签收的结论**：在上述普通调用图、独立存储/连接、E模块不配置也不暴露入口的限制下，旧管理3000ms/未知结果及SqlInbox收件操作不在S执行路径上；当前没有证据显示必须修改SDK的S缺陷。保留E原失败，不将新Q01通过称为根因修复。共享Deadline不能隔离：PHP7.2用microtime，回拨会拒绝合法请求，因此稳定支持须明示可用性条件及故障503，不承诺不间断服务；不能把它标成仅E问题。具体依赖、宿主责任、未知结果处置和迁移/回滚见[最小接入指南](stable-v1-integration.md)。管理已签收这些限制下的S范围；最终包身份及最小烟测登记在外部交付清单，E未获得稳定承诺，公开发布仍未授权。

## 实验入口分组（保留源码和旧契约）

| 分组 | 具体入口及启用条件 | 本版边界 |
| --- | --- | --- |
| E1 账号与受保护图 | 全部`Account\*`；`Security::registration/addressChange/recovery/mailboxRecovery/accountFactors/managedSecondFactor/stateAccount*`；显式StateBoundary、LocalStateWitness、精确快照/文件目录/权限上下文 | 3000ms超时和completion_unknown保持阻塞分析；不运行恢复启用、跨代工作进程交接、未知回执续办或完整F01 |
| E2 管理凭据与状态授权 | `Api\CredentialRegistry/CredentialPolicy/CredentialInfo/IssuedCredential/VerifiedCredential`；Authorization的SnapshotPolicy/SnapshotEvaluator；显式管理/状态策略 | 普通ApiKeys不等于该流程已通过；无法证明与S隔离时阻止发布 |
| E3 耐久编排 | 全部`Idempotency\*`、`Outbox\*`；Webhook的Message/Receipt/SqlInbox/SqlProcessor/Processing*；显式PDO、完整结构和当前业务权限 | 不运行处理器/发件箱总入口、未知结果处置或历史待办续办；只允许清单列明的全新隔离收件防御检查 |
| E4 扩展认证/授权 | Mfa、RememberedLogin/Remember*、DeviceRisk*、TotpSecondFactor、SecondFactor、Concurrency、Operation、Link、Download；显式相应配置/服务 | 不扩大首版承诺；保留已有测试与失败；不得关闭已启用保护使普通路径通过 |
| E5 外部/可选高级能力 | 外部验证码提供商、PwnedPasswords、Crypto、HTML净化、ArchiveInspector/ClamAvScanner/Quarantine*、高级Audit类型以及独立集成包 | 外部IdP/设备/扫描器/投递/生产代理/WAF验收均未执行；本地模拟及归档存在不等于服务验收 |

## 共享底层耦合与已知失败的影响

| 共享点 | 对基础路径的实际关联 | 证据要求与仍开放的结论 |
| --- | --- | --- |
| `Support\Deadline`（内部类型） | FileStore、RedisStore、Webhook验签、出站传输和SqlTransaction使用真实耗时预算；不由注入的业务Clock替代 | PHP7.2无hrtime时用microtime，倒退即到期拒绝。能防止延长权限窗口，但基础组件可能拒绝合法请求；不是仅高级功能限制。Q02、真实后端和HTTP必须记录默认时钟路径，不能平滑、伪造时钟或修改系统时间 |
| `Support\SqlTransaction`、`SqlTransactionGuard`、`SqlSchema`（内部） | 普通SQL组件使用事务工具；MySqlStore有自己的普通事务实现，并共享Guard/结构验证，不应笼统认定所有路径相同 | B03、Q01验证真实后端、调用者事务保留和失败清理；不运行恢复/未知结果编排。高级失败不能直接推出普通存储失败，也不能据普通存储通过判定高级路径稳定 |
| `Storage\FileStore` / `FileStateBoundary`（内部） | 普通存储和受保护目录入口在同类实现中；构造、锁、序列化、目录保护可能共同受影响 | 验收仅用自建普通目录，验证权限/损坏/锁故障拒绝；已绑定目录不能作为普通路径降级。需要代码审查加实际消费者来源和后端证据 |
| `Security`、`Configuration\Config` | 工厂按需构造，但共享配置解析、`authBoundary`和存储路由；Boundary缺省null不是完整隔离证明 | F11/B04/H01/C01验证最小配置、不注入高级依赖即可接入；配置E后遇不支持组合应拒绝，不能静默转换 |
| 普通API/验签与管理流程 | 普通`ApiKeys`和无状态连接HmacVerifier不运行LocalStateWitness管理流程；共享存储/时钟仍有耦合 | 九版旧默认管理记录仅8.4/8.5当轮完整通过；更近8.5第二次签发审计超时出现completion_unknown。后续未执行，不重试。管理已结合源码路径及B/H/C签收普通S调用的隔离部署条件；共享时钟及普通API未知结果仍按接入指南拒绝，不宣布所有高级路径无影响 |
| Webhook接收历史失败 | PHP7.2/MySQL `event_type/receive`原断言没有保存最初SDK错误码；位于SqlInbox收件分支 | 不能归为时钟问题；独立消费者后续通过不覆盖原失败。Q01固定检查当前候选并保留旧失败；最终关闭须说明根因/最小修复或可验证隔离依据，不只改实验标签 |

首版的五项发布阻塞采用 [验收文档](stable-v1-acceptance.md#发布阻塞与停止条件) 的同一编号，不另外新增阻塞队列。历史默认预算、时钟及未解释失败的原始证据路径在该文列明。

## 完整公开类型登记

以下清单由当前`classes.json`与`candidate.json`逐项比对，均为既有类型。S行列出原契约的公开方法名（含构造/魔术方法）；签名、参数类型、可空性和默认值以原候选为准，且必须服从上面的混合方法排除表。E行只登记入口，完整方法仍在原契约；不作首版稳定承诺。S/E是待审查发布范围，不修改API契约文件。

清单SHA-256：`240d3ab29336577d8b1b7d0aad7352e2076e03d22c68debe71ceb6a270a39aa1`；契约SHA-256：`0087d40d2d9be7d5ab6409973e3a0e6d97a618e99454a617954f4288d7d602e4`。

共278项：含S承诺的类型101项，E类型177项；这些类型内另有明确排除的方法/组合，不能按类型数推导已完成场景数。

| 既有公开类型 | 分类/验收组 | 既有契约方法登记，非稳定方法白名单 |
| --- | --- | --- |
| `Account\AccountRecord` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\Address` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\AddressChange` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\ChangeDelivery` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\CompositeStateCapture` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\CompositeStateSnapshot` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\Delivery` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\DispatchNotice` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\Dispatcher` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorEnrollment` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorInspection` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorIntentMaintenance` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorManagementRepository` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorMigration` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorMigrationMaintenance` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorMigrationRepository` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorNotices` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorOperationResolution` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorOperations` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorRecovery` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorRecoveryEnrollment` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorRegistry` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorReplacementApproval` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorRepository` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorRestoration` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorRevocation` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorSlot` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FactorWorkerAuthority` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FenceStateSnapshot` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FileStateCapture` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\FileStateSnapshot` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\IdentityRepository` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\KeyRingStateSnapshot` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\LocalEpochFence` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\LocalStatePersistence` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\LocalStateWitness` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\MailMessage` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\MailResult` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\MailTemplates` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\MailTransport` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\MailboxRecovery` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\MailboxRecoveryDelivery` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\ManagedSecondFactor` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\Notice` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\Notifications` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\Policy` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\QuarantineStateSnapshot` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\Recovery` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\RecoveryApproval` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\RecoveryDelivery` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\Registration` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\Repository` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\RequestBudgets` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\SendBudgets` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\SmtpTransport` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\SqlStateCapture` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\SqlStateSnapshot` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateAccountConnection` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateAccountContainment` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateAccountPolicy` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateAccountResolution` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateAccountResolutionReview` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateApiKeyConnection` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateApiKeyRetirement` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateApiKeyReview` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateBoundary` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateContainmentReview` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateCredentialEnrollment` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateCredentialInstallReview` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateCredentialInstallation` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateFactorContainment` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateFactorContainmentReview` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateFactorInventory` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateFactorResolution` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateFactorResolutionReview` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateLeaseConnection` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateOperation` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StatePermission` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateProofConnection` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateProofRetirement` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateProofReview` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateQuarantineConnection` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateRecoveryAudit` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateRecoveryCredentials` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateRequestGuard` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateRequests` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateRetirementControl` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateRetirementReview` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateSnapshot` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateStoreSource` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateSuccessorReview` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateWebhookConnection` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateWorkerHandoff` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\StateWorkerReview` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\WebhookStateSnapshot` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Account\WitnessedStore` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Api\ApiKeys` | S11 | `__construct`、`authenticate`、`fromAuthorization`、`issue`、`revoke`、`rotate`、`stateEpoch` |
| `Api\Credential` | S11 | `__construct`、`__debugInfo`、`__sleep`、`__wakeup`、`expiresAt`、`identity`、`token` |
| `Api\CredentialInfo` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Api\CredentialPolicy` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Api\CredentialRegistry` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Api\Hmac` | S11 | `sign` |
| `Api\HmacSigner` | S11 | `__construct`、`sign` |
| `Api\HmacVerifier` | S11 | `__construct`、`__debugInfo`、`__sleep`、`__wakeup`、`verify`、`verifyFor`、`withVerification` |
| `Api\Identity` | S11 | `__construct`、`__set`、`allows`、`id`、`scopes`、`subject`、`validateScopes` |
| `Api\IssuedCredential` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Api\KeyProvider` | S11 | `find` |
| `Api\KeyRing` | S11 | `__construct`、`find`、`stateDigest` |
| `Api\NonceStore` | S11 | `__construct`、`assertActive`、`consume`、`maximumTtl`、`stateAvailable`、`stateContext`、`stateKey` |
| `Api\SignaturePolicy` | S11 | `__construct`、`clockSkew`、`maximumBody`、`maximumLifetime`、`options`、`target` |
| `Api\SigningKey` | S11 | `__construct`、`__debugInfo`、`__set`、`__sleep`、`__wakeup`、`generate`、`identity`、`secret` |
| `Api\VerifiedCredential` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Audit\AlertOutboxPublisher` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Audit\AlertOutboxWorker` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Audit\AuditLogger` | S14 | `__construct`、`__debugInfo`、`__sleep`、`prepareState`、`record`、`stateContext` |
| `Audit\BudgetedSink` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Audit\Diagnostics` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Audit\MetricsSink` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Audit\RecentEvents` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Audit\SqlSink` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Audit\WindowArchive` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Auth\Account` | S05 | `__construct`、`__set`、`__sleep`、`enabled`、`fingerprint`、`mfaRequired`、`roles`、`scope`、`subject`、`version` |
| `Auth\AuthenticationFlow` | S05 | `__construct`、`__debugInfo`、`__sleep`、`cancel`、`password`、`secondFactor` |
| `Auth\CallbackIdentityProvider` | S05 | `__construct`、`__debugInfo`、`__sleep`、`authenticate`、`find` |
| `Auth\DeviceRiskDecision` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Auth\DeviceRiskPolicy` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Auth\IdentityProvider` | S05 | `authenticate`、`find` |
| `Auth\LoginResult` | S05 | `__construct`、`__debugInfo`、`__set`、`__sleep`、`__wakeup`、`account`、`challenge`、`credential`、`expiresAt`、`status` |
| `Auth\PasswordIdentityProvider` | S05 | `__construct`、`__debugInfo`、`__sleep`、`authenticate`、`find` |
| `Auth\PasswordRecord` | S05 | `__construct`、`__debugInfo`、`__set`、`__sleep`、`__wakeup`、`account`、`hash`、`identity`、`validateHash` |
| `Auth\RememberCredential` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Auth\RememberResult` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Auth\RememberedLogin` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Auth\SecondFactor` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Auth\SessionCredential` | S05 | `__construct`、`__debugInfo`、`__set`、`__sleep`、`__wakeup`、`expiresAt`、`id`、`token` |
| `Auth\SessionRegistry` | S05 | `__construct`、`all`、`boundTo`、`credentialInstallationContext`、`credentialRegistryContext`、`epoch`、`operationRolePolicy`、`operationSnapshotPolicy`、`policy`、`reference`、`register`、`replace`、`requiresStateBoundary`、`revoke`、`revokeAll`、`statePolicy`、`strength`、`verify` |
| `Auth\TotpSecondFactor` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Auth\VerifiedSession` | S05 | `__construct`、`__set`、`__sleep`、`account`、`authenticatedAt`、`createdAt`、`expiresAt`、`id`、`method`、`recent`、`resumed`、`strength` |
| `Authorization\Authorizer` | S14 | `__construct`、`__debugInfo`、`__sleep`、`assertAllowed`、`assertBatch`、`decide`、`decideBatch`、`project`、`stateAuditedPolicy`、`stateRolePolicy`、`stateSnapshotPolicy` |
| `Authorization\CallbackPolicy` | S14 | `__construct`、`__debugInfo`、`__sleep`、`decide` |
| `Authorization\Decision` | S14 | `__construct`、`__debugInfo`、`__set`、`__sleep`、`allow`、`allowed`、`deny`、`fields`、`reason` |
| `Authorization\PolicyProvider` | S14 | `decide` |
| `Authorization\PolicySet` | S14 | `__construct`、`__debugInfo`、`__sleep`、`decide` |
| `Authorization\Resource` | S14 | `__construct`、`__debugInfo`、`__set`、`__sleep`、`attributes`、`fingerprint`、`id`、`scope`、`type`、`version` |
| `Authorization\RolePolicy` | S14 | `__construct`、`__debugInfo`、`__sleep`、`decide`、`fingerprint` |
| `Authorization\SnapshotEvaluator` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Authorization\SnapshotPolicy` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Captcha\Captcha` | S02 | `__construct`、`arithmetic`、`click`、`image`、`imageArithmetic`、`imageDigits`、`imageLetters`、`revoke`、`slider`、`verify` |
| `Captcha\Challenge` | S02 | `__construct` |
| `Captcha\HCaptcha` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Captcha\ImageRenderer` | S02 | `__construct`、`render`、`renderQuestion` |
| `Captcha\Recaptcha` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Captcha\Turnstile` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Concurrency\Lease` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Concurrency\LeaseManager` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Concurrency\LeasePolicy` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Concurrency\LeaseStatus` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Configuration\Config` | S13 | `__construct`、`__set`、`accountFactors`、`accounts`、`api`、`apiCredentials`、`authentication`、`authorization`、`budgetPolicies`、`budgetPolicy`、`captcha`、`csrf`、`downloads`、`html`、`idempotency`、`leasePolicy`、`mfa`、`operations`、`outbound`、`outbox`、`password`、`policy`、`remember`、`session`、`signedLinks`、`site`、`statelessCsrf`、`storage`、`tokenStorage`、`upload`、`uploadQuarantine`、`webhooks` |
| `Crypto\Cipher` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Csrf\CsrfTokens` | S01 | `__construct`、`issue`、`revoke`、`verify` |
| `Csrf\RequestPolicy` | S01 | `__construct`、`requiresToken` |
| `Csrf\SignedTokens` | S01 | `__construct`、`issue`、`reuseOrIssue`、`verify`、`verifyDoubleSubmit` |
| `Diagnostics\Inspector` | S13 | `inspect` |
| `Download\Access` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Download\Downloads` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Download\File` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Download\Grant` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Download\LinkAccess` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Download\Policy` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Download\RangeException` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Download\Request` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Download\SessionAccess` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Download\Transfer` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Exception\ConfigurationException` | S13 | `__construct`、`reason` |
| `Exception\DependencyException` | S13 | `__construct`、`reason` |
| `Exception\SecurityException` | S13 | `__construct`、`reason` |
| `Exception\ValidationException` | S13 | `__construct`、`reason` |
| `Http\ClientIp` | S08 | `__construct`、`resolve` |
| `Http\Cookie` | S08 | `header` |
| `Http\Cors` | S08 | `__construct`、`evaluate` |
| `Http\CorsDecision` | S08 | `__construct`、`allowed`、`headers`、`reason`、`status` |
| `Http\IpRules` | S08 | `__construct`、`contains` |
| `Http\Outbound\Client` | S10 | `__construct`、`request` |
| `Http\Outbound\CurlTransport` | S10 | `__construct`、`send` |
| `Http\Outbound\DohResolver` | S10 | `__construct`、`resolve` |
| `Http\Outbound\Policy` | S10 | `__construct`、`__set`、`budgetMs`、`check`、`headerBytes`、`options`、`redirects`、`requestBytes`、`responseBytes` |
| `Http\Outbound\Resolver` | S10 | `resolve` |
| `Http\Outbound\Response` | S10 | `__construct`、`__debugInfo`、`__sleep`、`__wakeup`、`body`、`headerBytes`、`headers`、`peer`、`status`、`values` |
| `Http\Outbound\Transport` | S10 | `send` |
| `Http\PermissionsPolicy` | S08 | `build` |
| `Http\Redirects` | S08 | `__construct`、`allows`、`target` |
| `Http\RequestException` | S08 | `__construct`、`reason` |
| `Http\SecurityHeaders` | S08 | `build` |
| `Http\Uri` | S08 | `__debugInfo`、`__sleep`、`__wakeup`、`host`、`hostName`、`origin`、`originValue`、`parse`、`path`、`port`、`resolve`、`scheme`、`target`、`url`、`withoutFragment` |
| `Idempotency\Outcome` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Idempotency\Policy` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Idempotency\Request` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Idempotency\Response` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Idempotency\SqlExecutor` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Link\IssuedLink` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Link\Links` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Link\Policy` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Link\Target` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Link\VerifiedLink` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Mfa\Enrollment` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Mfa\Totp` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Mfa\TotpFactors` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Operation\Confirmation` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Operation\Grant` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Operation\Grants` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Operation\Intent` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Operation\Permit` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Operation\Policy` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Outbox\Claim` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Outbox\Message` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Outbox\Policy` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Outbox\SqlOutbox` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Outbox\Status` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Output\Escaper` | S07 | `html`、`json`、`urlComponent` |
| `Output\HtmlCleaner` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Output\HtmlPolicy` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Output\HtmlPurifierSanitizer` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Output\HtmlSanitizer` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Password\PasswordBlocklist` | S04 | `__construct`、`__debugInfo`、`__set`、`__sleep`、`baseline`、`contains`、`count`、`fromFile`、`fromPasswords` |
| `Password\PasswordHasher` | S04 | `__construct`、`hash`、`maximumBytes`、`needsRehash`、`parameters`、`profile`、`verify`、`verifyAndUpgrade` |
| `Password\PasswordPolicy` | S04 | `__construct`、`__debugInfo`、`__set`、`__sleep`、`errors`、`forHasher` |
| `Password\PwnedPasswords` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Password\ResetTokens` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Password\Verification` | S04 | `__construct` |
| `RateLimit\BudgetDecision` | S03 | `__construct`、`__set`、`__sleep`、`allowed`、`reason`、`remaining`、`reservedUntil`、`retryAfter` |
| `RateLimit\BudgetGroup` | S03 | `__construct`、`__debugInfo`、`consume`、`inspect`、`reset` |
| `RateLimit\BudgetLimiter` | S03 | `__construct`、`__debugInfo`、`consume`、`inspect`、`policy`、`reset` |
| `RateLimit\BudgetPolicy` | S03 | `__construct`、`__set`、`algorithm`、`capacity`、`fingerprint`、`limit`、`maximumEntries`、`window` |
| `RateLimit\BudgetResult` | S03 | `__construct`、`__set`、`__sleep`、`allowed`、`blocked`、`charged`、`decisions`、`mode`、`reservedUntil`、`retryAfter` |
| `RateLimit\CompositeLimiter` | S03 | `__construct`、`__debugInfo`、`consume`、`inspect`、`scopeFor` |
| `RateLimit\Decision` | S03 | `__construct` |
| `RateLimit\Policy` | S03 | `__construct`、`__set`、`banDurations`、`historyTtl`、`limit`、`window` |
| `RateLimit\RateLimiter` | S03 | `__construct`、`ban`、`consume`、`inspect`、`reset` |
| `Security` | S13 | `__debugInfo`、`accountFactors`、`addressChange`、`apiCredentials`、`apiKeys`、`authentication`、`authorization`、`budgetComposite`、`budgetGroup`、`budgetLimiter`、`captcha`、`clearRememberCookieHeader`、`config`、`configureSession`、`csrf`、`csrfPolicy`、`diagnose`、`downloads`、`fromArray`、`hmacSigner`、`hmacVerifier`、`htmlCleaner`、`idempotency`、`initializeStorage`、`leases`、`mailboxRecovery`、`managedSecondFactor`、`mfa`、`operations`、`outbound`、`outbox`、`passwordHasher`、`passwordPolicy`、`quarantine`、`rateLimiter`、`recovery`、`registration`、`rememberCookieHeader`、`rememberedLogin`、`resetTokens`、`session`、`sessionCookieHeader`、`sessions`、`signedCsrf`、`signedLinks`、`stateAccountConnection`、`stateAccountPolicy`、`uploader`、`webhook`、`webhookInbox`、`webhookProcessor` |
| `Session\SessionSecurity` | S06 | `__construct`、`configure`、`cookieHeader`、`invalidate`、`rotate`、`touch` |
| `Storage\AtomicStore` | S13 | `transact` |
| `Storage\Change` | S13 | `__construct`、`__debugInfo`、`__set`、`__sleep`、`__wakeup`、`expiresAt`、`result`、`value` |
| `Storage\FileStore` | S13 | `__construct`、`bindStateBoundary`、`containState`、`installCredentialState`、`prune`、`pruneBatch`、`resolveState`、`retireApiKeyState`、`retireProofState`、`snapshotBinding`、`snapshotFile`、`snapshotReference`、`transact`、`usesClock` |
| `Storage\MemoryStore` | S13 | `__construct`、`transact` |
| `Storage\MySqlStore` | S13 | `__construct`、`install`、`prune`、`schema`、`transact` |
| `Storage\NamespacedStore` | S13 | `__construct`、`transact`、`underlying` |
| `Storage\PruneResult` | S13 | `__construct`、`complete`、`removed`、`scanned` |
| `Storage\RedisStore` | S13 | `__construct`、`initialize`、`transact` |
| `Storage\SessionStore` | S13 | `__construct`、`transact` |
| `Storage\StorageException` | S13 | `__construct`、`reason` |
| `Support\Clock` | S13 | `now` |
| `Support\HmacKeys` | S13 | `__construct`、`__debugInfo`、`__set`、`__sleep`、`currentId`、`sign`、`stateDigest`、`verify` |
| `Support\SystemClock` | S13 | `now` |
| `Upload\ArchiveInspector` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Upload\Candidate` | S09 | `__construct`、`__debugInfo`、`__set`、`__sleep`、`__wakeup`、`bytes`、`contents`、`digest`、`extension`、`height`、`mime`、`sourceBytes`、`width` |
| `Upload\ClamAvScanner` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Upload\Policy` | S09 | `__construct`、`__set`、`jpegQuality`、`maximumBytes`、`maximumHeight`、`maximumPixels`、`maximumWidth`、`mime`、`options`、`requiresScan`、`workingBytes` |
| `Upload\Quarantine` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Upload\QuarantineStatus` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Upload\Saver` | S09 | `__construct`、`saveFile`、`saveUpload` |
| `Upload\Scanner` | S09 | `scan` |
| `Upload\StoredFile` | S09 | `__construct`、`__debugInfo`、`__sleep`、`__wakeup`、`metadata`、`path` |
| `Upload\Validator` | S09 | `__construct`、`inspectFile`、`inspectUpload`、`policy`、`withTemporaryDirectory` |
| `Validation\Result` | S07 | `__construct`、`__debugInfo`、`__sleep`、`__wakeup`、`data`、`errors`、`valid` |
| `Validation\Rule` | S07 | `code`、`passes` |
| `Validation\Validator` | S07 | `__construct`、`validate` |
| `Webhook\Endpoint` | S12 | `__construct`、`__set`、`account`、`fingerprint`、`futureSkew`、`id`、`ioMilliseconds`、`maximumBody`、`options`、`protocol`、`scope`、`tolerance`、`url` |
| `Webhook\KeySet` | S12 | `__construct`、`__debugInfo`、`__set`、`__sleep`、`__wakeup`、`fromEncoded`、`matches`、`stateDigest`、`verify` |
| `Webhook\Message` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Webhook\ProcessingClaim` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Webhook\ProcessingPolicy` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Webhook\ProcessingStatus` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Webhook\Receipt` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Webhook\Request` | S12 | `__construct`、`__debugInfo`、`__set`、`__sleep`、`__wakeup`、`body`、`header`、`method`、`url` |
| `Webhook\SqlInbox` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Webhook\SqlProcessor` | E | E1—E5按上述命名空间/用途分类；原契约完整保留 |
| `Webhook\VerifiedWebhook` | S12 | `__construct`、`__debugInfo`、`__set`、`__sleep`、`body`、`bodyDigest`、`endpoint`、`expiresAt`、`keyId`、`messageId`、`timestamp`、`verifiedAt` |
| `Webhook\Verifier` | S12 | `__construct`、`__debugInfo`、`__sleep`、`endpoint`、`stateContext`、`verify` |
