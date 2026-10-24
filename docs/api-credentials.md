# 账号级API凭据生命周期

历史阶段记录：下述为当时的R4.1本地验收，不能作为当前源码的完整验收。九版完整检查／磁盘耗尽／新消费者、各3753核心断言／720独立格式检查／592原生HTTP／600真实TLS及文件／Redis／MySQL各24进程通过；PHP7.2／8.5真实密码／TOTP TLS移动Chromium、144类API／246文件归档与静态检查通过。最新策略引用与下载预算回归另以九版专项复验。现有[低层ApiKeys与HTTP签名](api.md)保持兼容；生产、常驻Apache、下游、远端CI和独立审查未执行。

## 使用方式与信任边界

`Api\CredentialRegistry`显式组合共享AtomicStore、真实SessionRegistry、匹配的IdentityProvider／SecondFactor、独立HmacKeys、站点标识、请求保护与服务器权限范围提供器。构造和导入没有Session、HTTP头、网络或业务表副作用。

```php
$policy = new SoSecurity\Api\CredentialPolicy([
    'allowed_scopes' => ['documents:read', 'documents:write'],
]);
$credentials = new SoSecurity\Api\CredentialRegistry(
    $sharedStore, $sessions, $identityProvider, $privateApiKeys, 'my-api',
    $requestGuard, $scopeProvider, $policy, null, $sameSecondFactor
);
// subject和sessionToken来自宿主当前Session，不能来自管理表单。
$issued = $credentials->issue($tenant, $subject, $sessionToken,
    '部署工具', ['documents:read'], 86400);
$plaintextForOneTimeDisplay = $issued->token();
$managementMetadata = $issued->metadata()->toArray();

// 独立Bearer路由，仅传入实际收到的Authorization；范围由服务器路由固定。
$proof = $credentials->fromAuthorization($tenant, $actualAuthorization, 'documents:read');
if ($proof === null) { /* 宿主返回统一认证失败，停止业务 */ }
// 只有非null时才继续，并按proof.account()检查对象／租户／字段权限。
```

`requestGuard(operation, Account|null, metadata): bool`由宿主提供，只接受严格true。管理动作在验证真实Session后调用，Account为实际操作者，metadata.owner为凭据所属账号；验证CSRF、来源、请求预算和必要的管理权限。`authenticate`动作在解析令牌前调用，account为null，metadata仅含服务器指定的required_scope，需校验实际Bearer路由和入口预算。不能把null当作已登录账号，也不能把该回调中的管理元数据当作业务对象授权。

原生`authenticate`／`fromAuthorization`还会在见证完成后只读复核当前凭据、账号、范围和请求权限。返回的有效范围取前后观察的交集；应使用`VerifiedCredential::scopes()`／`allows()`，而不是签发元数据中的范围来授权。边界预算守卫需支持`api.credentials.authenticate_check`；认证请求守卫可重复调用，入口层先完成一次性预算／证明消费，回调只复核请求上下文和当前权限。完成后拒绝不重放、不删除已完成状态。详见[最终返回修复及证据](native-bearer-return-2026-10-23.md)。

`scopeProvider(Account): array`从当前服务器权限返回规范范围列表，与策略全局允许列表取交集。未知／重复／非列表等无效返回值视为依赖故障，不静默当作放行。签发／替换必须完整满足请求的每项范围；认证有效范围是已签发范围与当前可用权限的交集，权限范围本身不能替代对象授权。普通管理操作会在身份和对象授权读取后再次查询范围，并取两次观察的交集；随后复核会话、身份及对象授权。返回前还会以最终观察时间核对会话到期及敏感动作的近期认证期限。提供器必须只读、可重复调用；同一操作不能依赖固定调用次数，也不能在其中消耗一次性请求预算。回调故障默认拒绝，不能把顺序复核当成宿主权限数据的原子事务。

手工构造时身份／因子适配器必须与SessionRegistry使用同一可信来源。API持有令牌不代表本次完成密码或MFA；管理操作始终要求实际Session。默认签发／轮换／替换需300秒内、强度至少1的password／totp／webauthn，恢复码须显式选择，记住登录恢复不能冒充近期认证。查询／撤销只需当前有效会话，允许及时止损；宿主可通过请求保护增加敏感操作限制。

## 服务账号与显式委派

默认只允许账号管理自己的凭据。服务账号不需要伪造交互登录；可同时注入构造末尾的`managementAuthorization`与`managementSubject`，两项缺一即拒绝配置。`managementSubject(scope): string`必须从服务器当前管理会话解析操作者，不能取自目标账号或表单。传入的sessionToken始终验证该操作者的真实Session。

委派授权逐操作检查`api.credentials.issue/all/rotate/replace/revoke/revoke_all`，资源类型为`api_credential_owner`、ID为目标subject、版本为目标当前身份指纹、属性owner为目标subject。无显式策略就拒绝，admin角色不自动拥有通配权限。跨账号签发／轮换／替换默认至少近期强度2，使用`delegated_minimum_strength`配置且不会低于全局minimum_strength；默认方法排除恢复码与持久登录恢复。目标账号仍须启用，申请范围取目标账号当前权限，而非管理员权限。

元数据的`creator_reference`和`issuer_reference`分别记录最初创建者与最近签发／轮换者的站点／租户／账号定位摘要，均参与完整签名声明。轮换保留原创建者，更新签发者；摘要不承诺匿名性，宿主负责可信账号关联及审计留存。管理员后续退出／降权不会自动撤销已签给服务账号的机器凭据；凭据绑定目标账号生命周期。紧急处理须显式撤销目标凭据或退役其签名密钥，不能依靠管理员Cookie过期。

可选工厂配置`api_credentials`需要authentication以及共享storage；keys为HmacKeys服务，request_guard、scope_provider为回调服务。启用委派时同时配置management_subject与management_authorization服务名，后者必须为Authorizer。策略放policy；工厂默认不生成密钥、账号、Session或账本。诊断只检查配置与服务类型，当前范围来源、业务授权、实际管理会话和HTTPS仍列为人工核实。

## 生命周期接口

| 方法 | 结果与约束 |
| --- | --- |
| issue(scope,subject,sessionToken,name,scopes,ttl?) | 返回IssuedCredential，秘密仅此次结果可取；每账号默认最多16项，期限默认1天、最大1年 |
| all(scope,subject,sessionToken) | 当前账号有界元数据列表，无秘密／摘要；过期项清理，状态更新不代表浏览器在线 |
| rotate(scope,subject,sessionToken,id,expectedGeneration) | 原子代际比较后换秘密，ID／名称／范围／原始到期不变；冲突或失效返回null |
| replace(...,id,expectedGeneration,name,scopes,ttl?) | 同时换秘密、名称／范围；可缩短期限，不能延长原始到期，旧秘密立即失效 |
| revoke(scope,subject,sessionToken,id) | 撤销该账号下此ID的全部代际，其他账号即使知道ID也不能管理 |
| revokeAll(scope,subject,sessionToken) | 原子清空并更换账号epoch，返回删除的有效项数；显式操作也可将旧策略账本重置到当前策略 |
| authenticate(scope,token,requiredScope) | 返回VerifiedCredential或null，必须明确一个服务器路由范围 |
| fromAuthorization(scope,header,requiredScope) | 只接受有界单Bearer头；不读取Cookie、Session、查询或JSON里的替代凭据 |

代际比较阻止并发轮换互相覆盖；原先generation的请求不会覆盖后来返回的新秘密。签发在请求保护之前记录旧epoch，撤销全部发生在其间时不能由旧准备流程重新加入凭据。秘密提交后响应丢失或后续身份复核失败，旧秘密可能已失效；不能自动恢复旧摘要，用户应通过已授权查询／撤销／重新签发处理。

## 受保护模式的委托审计

原生凭据委托可组合准确身份提供器、具体 `RolePolicy` 和直接使用 `SqlSink` 的 `AuditLogger`。审计必须使用状态策略的同一个 PDO、站点和业务时钟；在建立初始见证前初始化，并完整声明审计根表和记录表，物理容量不得小于审计策略容量。未声明完整来源的自定义授权策略、包装的审计回调或来源不匹配仍拒绝配置；显式 SnapshotPolicy 接入见下文。

此模式新增 `requestGuard` 动作 `audit_current`。其 `metadata.operation` 是原始管理动作，`metadata.phase` 为 `admission`、`before` 或 `return`，其余字段沿用原动作。该动作必须只读、可重复地检查当前请求权限；不能重复消费原始动作已验证的 CSRF 或请求预算。允许决定还会重复读取 `scopeProvider`，其返回必须反映当前权限。

系统在原生准入、写入前及返回前复核准确操作者、目标身份、会话、近期认证、对象权限和范围；操作者与目标的首次完整来源捕获合并，因子发现与完整摘要校验保留，结果不跨调用缓存；准备及写入共享原始期限，较短的审计期限同时收紧外层写入前检查。允许事件表达授权决定，不代表业务已经完成。明确的角色策略拒绝可提交一条脱敏拒绝事件，然后抛出 `authorization.denied`，不执行凭据修改。无效输入、初始会话、范围、容量等更早的拒绝不保证写入审计。

审计 SQL 与凭据存储没有跨存储原子提交。后续失败时保留已发生的记录及 pending 限制，不自动撤销、恢复或续办；最终返回检查失败不返回秘密。时钟异常以 `api_credentials.clock` 脱敏拒绝。当前验证及默认 MySQL 预算失败见[专项记录](native-audit-delegation-2026-10-22.md)，不能据此宣称完整稳定版通过。

## 当前身份、签名与共享账本

认证每次核验当前账号／凭据／角色与因子版本；明确禁用、删除或身份变化时按旧epoch和身份指纹条件清空旧凭据，不误删新身份已签发的替代账本。身份或权限服务故障拒绝本次操作；有效令牌不会只因临时依赖故障被永久撤销。最后使用时间表示凭据校验观察，不表示业务执行或网络交付成功。

新令牌是本组件专用的`ac1`有界随机Bearer格式，不是JWT或OAuth令牌。随机秘密只保存SHA-256摘要，HMAC-SHA256绑定站点／租户、账号定位值、epoch、ID、代际、期限和完整权限声明摘要；格式／MAC不成立时不访问凭据账本。随机秘密、签名和身份查询均在可重试事务外。权限、名称、身份或期限字段损坏不能通过重算普通存储摘要提升原令牌权限。

同一账号的凭据处于单个共享原子账本，避免查询索引与单令牌记录之间的跨键竞态。账号定位值是稳定摘要，不是匿名化承诺或授权证明。空账本保留epoch与观察时间；认证遇到缺失账本拒绝，不从令牌恢复状态。只有当前已认证的显式签发或撤销流程创建新账本；签发在请求保护前可初始化不含凭据的空epoch，保证首次并发准备使用相同代际，保护失败不会创建任何令牌。宿主限制账号／全站数量、保护持久性并管理账号退休后的数据清理。

时间倒退、超限、损坏格式及有效策略变化拒绝；已观察到过期的记录被清理，晚返回／无效时间的凭据不返回授权。精确清理仅删除相同epoch／ID／秘密摘要，不删除并发旋转的新代际。时限在回调返回处复核，不能强制中断内核或宿主I/O。策略在规范化前断开输入数组的外部引用，不改写调用方配置，调用方修改原变量或返回的options数组不会改变已验证策略。

## 策略、迁移与运维

`CredentialPolicy`选项为allowed_scopes、ttl、maximum_ttl、capacity、fresh_age、minimum_strength、delegated_minimum_strength、methods、io_milliseconds。容量1—16，最大期限1年，近期认证1—3600秒，操作总预算默认3000毫秒、范围1—30000。空范围允许列表默认拒绝所有签发及受保护路由。策略顺序规范化，策略指纹同时绑定账本和签名声明；有效策略改变不静默解释旧账本，可通过已授权revokeAll清空并安装新策略，不能把格式损坏当作允许重置。

旧`ApiKeys`的`sosk_`令牌不自动升级为账号绑定凭据；先部署新路由／管理流程、真实身份与权限来源，再由用户签发并替换客户端秘密，最后显式撤销旧令牌。认证失败不得继续尝试旧API令牌、Cookie或匿名身份。密钥轮换保留旧key_id用于过渡，移除旧密钥立即拒绝其MAC；轮换凭据使用当前密钥，但不延长到期。

生产必须使用满足原子性／持久性要求的共享存储；MemoryStore仅用于测试，SessionStore不能管理跨访客API授权。私有状态、HMAC密钥、业务数据库与日志分别保护，HTTPS和可信代理由部署配置。禁止记录完整Authorization、原始令牌或含秘密的异常／序列化对象，网页展示秘密后不缓存、不放URL或本地持久存储。

签名不能识别运维恢复的历史合法账本。备份恢复可能重新带回旧epoch、摘要和观察时间；受控恢复须结合所有节点的密钥退役或权威凭据版本提升，并验证旧令牌被拒绝。仅恢复文件／数据库、清空缓存或修改当前时钟不构成撤销保证；本组件不自动轮换生产密钥。

多个身份／凭据／业务数据源不具备全局原子事务。组件在I/O前后复核当前来源和精确代际，宿主仍需在实际业务读写时检查对象、权限版本、业务事务和期限。请求幂等、完整通知／审计和外部服务接入继续后续阶段，不因存在Bearer凭据自动成立。

## 原生HTTP接入与本地验收

[api-credentials.php](../examples/api-credentials.php)是独立、需显式部署的原生页面。运行前由宿主创建SQLite数据库、账号／文档表、0700状态目录、PHP Session目录及0600密钥文件，全部位于实际Web根外；页面不生成账号、表、目录、管理员或生产秘密。

必需环境变量前缀为`SOSECURITY_CREDENTIAL_EXAMPLE_`：DATABASE为私有SQLite文件，STORAGE为规范绝对状态目录，KEYS为私有HMAC配置文件，ORIGIN为固定实际HTTPS来源，DUMMY_HASH为默认bcrypt cost12对应的虚拟账号哈希。KEYS文件结构为`{"current":"key_id","keys":{"key_id":"标准Base64编码的随机密钥"}}`，原始密钥遵循HmacKeys预算。可选MFA_KEYS采用同一JSON结构，原始加密密钥必须32字节且与HMAC密钥分开；用途固定为`credential-example:mfa`，已有因子通过TotpFactors显式管理。未启用适配器或未绑定因子的强认证账号不能登录。

PATH默认`/api-credentials.php`，TTL默认86400秒且只能显式设为1—31536000整数；策略变更仍受旧账本迁移约束。HTTPS默认开启；仅隔离本地测试设为0并使用HTTP来源。示例检查实际HTTPS和Host，不信任任意X-Forwarded-Proto。代理需由宿主落实可信来源与实际TLS配置。

示例约定的业务结构如下，tenant固定`credential-example`；业务部署采用自己的迁移、备份、账号与文档来源。password_hash包括服务账号占位哈希，服务账号不能通过username登录；保存哈希同时参与当前身份版本。

```sql
CREATE TABLE credential_accounts (
  tenant TEXT NOT NULL, subject TEXT NOT NULL, username TEXT NOT NULL,
  password_hash TEXT NOT NULL, version TEXT NOT NULL, enabled INTEGER NOT NULL,
  roles TEXT NOT NULL, mfa_required INTEGER NOT NULL, kind TEXT NOT NULL,
  PRIMARY KEY (tenant, subject), UNIQUE (tenant, username)
);
CREATE TABLE credential_documents (
  tenant TEXT NOT NULL, id TEXT NOT NULL, owner TEXT NOT NULL,
  version TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
  PRIMARY KEY (tenant, id)
);
```

roles为JSON数组，kind只接受user／service。editor可读写自己的文档，reader只读；admin逐操作拥有显式凭据委派规则，不自动拥有文档权限。管理目标通过规范GET参数owner指定，CSRF范围绑定目标查询，实际操作者始终取服务器会话。签发／轮换后的秘密只在该响应显示；查询列表、刷新、Cookie和服务器Session不保存秘密。登录与TOTP完成后轮换原生Session，待完成TOTP表单绑定flow_id摘要，旧标签页不能验证另一个待登录账号。

`?api=document&document_id=a`为独立Bearer路由，GET读取有界文档，POST仅接受有界JSON的title／version并修改标题。有效范围、租户、所有权和字段授权在业务前检查；SQL读取仅投影授权对象／版本且限制正文8192字节、标题256字节，返回前复核凭据、对象当前所有权／版本和期限。写入使用SQLite事务、对象所有者／版本比较，并在提交前复核当前凭据与权限；失败回滚，跨存储最后校验与提交之间仍无全局原子承诺。入口240次／分钟、管理80次／分钟、有效API所属账号60次／分钟；实际REMOTE_ADDR经显式ClientIp解析，示例不推断代理信任。请求正文最多8192字节。

本地复验命令：`php tests/credentials.php`、`python3 tests/credential_vectors.py php`、`python3 tests/credential_http.py php`、加`--tls`验证私有CA真实TLS；加`--browser`驱动真实密码／TOTP移动Chromium。测试初始化使用独立测试数据和私有目录，TLS桥只存在测试代码，Python客户端验证测试CA，浏览器仅对该自签测试证书忽略信任错误。没有生产、常驻Apache、真实客户账号或独立审查结论。

参考：[Laravel Sanctum的令牌范围／撤销／期限](https://laravel.com/docs/13.x/sanctum)、[OWASP REST安全](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)、[OWASP授权](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)。

## 受保护的业务 SQL 写入

显式保护模式下，可通过原生工厂 `apiCredentials($stateAccountPolicy)` 返回的注册表调用 `withAuthorization($scope, $header, $requiredScope, $pdo, $tables, $businessPolicy, $prepare, $work)`，将 Bearer 准入、服务端 Intent／对象／字段权限和自有 SQL 事务放在同一次独立见证中。不要先开启 PDO 事务或套外层 `run()`；普通模式不提供这一保护契约。

`withAuthorization` 在业务完成后还会执行只读的当前Bearer／账号／范围／请求守卫核验，并在最终读取后检查凭据期限。宿主边界预算守卫需支持 `api.credentials.execute_check`；认证守卫和范围提供器应可重复、只读。整个请求、SQL事务与最终复核共用原预算。后置拒绝不撤回已提交的业务，不应据此盲目重放。见[修复及分阶段证据](native-business-return-2026-10-23.md)。

自定义业务策略使用独立入口 `withSnapshotAuthorization`，参数顺序与 `withAuthorization` 相同，第六个参数必须为 `SnapshotPolicy`。策略须绑定账号图中同一个 SQL 来源；普通 `PolicyProvider` 不受支持。SDK 在准入、效果开始前、最终返回前三次捕获事实并重新判定原 Intent。最终判定面对提交后的数据，因此策略必须定义合法结果状态；例如转移归属导致当前操作者失权时，SQL 已提交但结果仍拒绝交付，不会自动回滚或重放。策略评估器只做有界纯计算，不执行 I/O。两种入口均使用 `api.credentials.execute`／`api.credentials.execute_check` 边界动作，未增加隐式放行。见[专项记录](native-business-policy-2026-10-23.md)。

业务表须预先完整声明到准确 SQL 来源，全部写入者遵守同一见证／围栏。prepare 只读加载实际对象并验证参数；work 仅通过提供的 PDO、Intent 和版本比较更新写入声明表，不发送邮件等外部效果、不控制事务、不自动重试。业务返回值只有整个入口成功返回才可使用，未知效果保持 pending。接入细节见[业务 PDO 契约](state-boundary.md#bearer-与业务-pdo-事务组合)，完整宿主示例函数见 [StateDocuments.php](../examples/StateDocuments.php)。本轮有限证据及尚未执行的业务 HTTP／真实中断验收见[接入记录](state-business-integration-2026-10-21.md)。

原生受管宿主可增加第三个引导字段 `business_connection`，通过 `POST ?api=document` 调用上述组合，字段仅为 action／id／version／title；详见[实际宿主记录](state-business-host-integration-2026-10-21.md)。该记录含格式 3、TLS／Chromium、联合业务备份和真实中断证据，也保留一次未解释 503，整组未判通过。


原生新增账本现检查完整物理目录的文件余量：满额在 pending 前拒绝，逻辑过期文件仍占容量，已有账本合法更新不额外占文件。释放空间后同一服务／会话可重试；不会因此清除旧 pending。准确修前反例及范围见[容量准入记录](state-admission-capacity-2026-10-22.md)。

## 显式自定义原生委托策略

原生凭据委托可使用与完整SQL来源绑定的 `Authorization\SnapshotPolicy`，并选择无审计或准确SQL审计组合。未声明来源的普通 `PolicyProvider` 仍拒绝；必须实现专用 `SnapshotEvaluator`：声明准确行，由SDK捕获后交给纯计算决策；不得自行查库或访问外部服务。普通 `SnapshotPolicy::decide` 明确拒绝，不能将返回的决策作为可复用权限。无审计组合需要支持 `management_current` 请求守卫复核。具体绑定、配置摘要、故障及兼容边界见[接入说明](native-custom-policy-2026-10-23.md)。
