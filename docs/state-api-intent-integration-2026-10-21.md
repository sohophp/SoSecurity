# G1 账号 API 的准确意图回执与真实中断

日期：2026-10-21（Asia/Shanghai）。继续原 P1／G1，31 项／80 个有效工作小时上限保持。本组补齐原生受保护 `CredentialRegistry` 的操作者、目标和准确参数绑定，沿用现有 authorized 根结构，不扩展为完整恢复或全部写入者验收。

## 回执与实际批准的区别

原生八个入口完成真实只读准入后，返回不可变 `StateOperation` 描述；见证确认完整来源和根未改变，再允许它替换原内部意图。只接受准确 `api.credentials.issue/rotate/replace/all/revoke/revoke_all/authenticate`、同一作用域和原声明动作；不接受错动作、错 scope、非 authorized 描述、普通内部动作或生命周期混用。false 准入仍无效果返回，void 准入和普通内部工作保持原语义。

新增 `StateOperation::credential()` **只构造描述，不验证凭据或授予权限**。SDK 的原生准入继续验证实际账号／因子／会话／签名 API 凭证、宿主保护及当前权限，不能拿一个描述替代真实认证。服务器自建 admission 本来就是受信接入代码，仍须落实对应权限；本组没有把任意业务回调变成认证服务。

pending 和 current 使用同一份描述及摘要。发生效果后、最终预算或确认失败，保留原 pending 描述及原可信来源摘要；不把当前可读字节当作新基线、不重放签发、不启用账号。错误请求在 pending 前拒绝并保留之前的意图。

## 绑定契约

意图沿用 kind=`authorized`，action 为准确原生动作，scope／actor／target 使用既有范围和主体 SHA-256 域；委托记录实际操作者及独立目标，Bearer 记录实际凭证所有者。原始会话、Bearer secret 和客户端令牌不进入根。

`policy` 是下列数组的 SHA-256，域前缀为 `SoSecurity.Api.Credentials.AdmissionPolicy.1.`：site、scope、准确 `StateAccountPolicy::binding()`、`CredentialPolicy::fingerprint()`、原生委托 RolePolicy 指纹（无则 null）、当前 API 签名键 ID。新增纯 `RolePolicy::fingerprint()` 绑定完整标准化规则，包括角色、字段、对象所有权和属性条件；不只记录规则数量或服务名称。

`permission` 的域前缀为 `SoSecurity.Api.Credentials.AdmissionRequest.1.`，有序字段如下，均以 `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE` 编码后求 SHA-256：

| 字段 | 被绑定的实际数据 |
| --- | --- |
| entry | 八个实际入口之一；Authorization 头与直接令牌入口可区分 |
| actor／target | 实际作用域内的操作者和目标主体 |
| actor_identity／target_identity | 账号密码版本及当前因子绑定的实际身份摘要 |
| credential | 管理会话的原生 id／digest；Bearer 的完整已验签令牌 digest，不含 secret |
| parameters | 标准化的 owner、名称、scopes、TTL、id、预期 generation 或 required_scope；按对应动作固定字段及 null 默认语义 |
| allowed_scopes | 锁内已核对的实际当前能力列表 |
| observed | 准入所匹配的完整来源摘要 |
| policy | 上述准确策略摘要 |

签发的 TTL 和范围列表在宿主回调前标准化并复制；轮换的 null 名称／范围／期限明确表示保留原值，原值被完整来源摘要绑定。Authorization 头标准化为实际已验签令牌，大小写等效头不作为秘密原文保留。签发的新随机 id／secret 属于效果，不是请求参数；本回执不能重建或重发它们。

`authorized_at` 使用最后已经检查的准入时间，不重新读取时钟生成另一时间。Bearer 的范围回调若使时钟倒退，现在在 pending 前明确拒绝，不钳制时钟；回调期间过期和已有管理准入规则继续生效。

## 格式与部署

没有新的 SQL 结构、根版本或 FileSnapshot Profile。格式 2／3 使用已有 authorized 字段，完整意图摘要和根签名覆盖所有字段；格式 3 保留 generation／lineage。格式 3 的检查为独立的新域首次预置，不是隔离恢复后重新开放。

旧读取器可以理解已有结构，旧写入者却不会生成这份新的原生绑定；不能依靠格式拒绝来完成工作进程交接。迁移须升级／停止旧进程。未传纯策略的旧手工边界模式和其他授权入口没有被自动改写为这份回执，也不据此声称所有写入者已覆盖。

## 冻结验收

**已执行并通过：固定 27 条命令全部退出 0，准确输入保持一致，四次独立 MySQL 已关闭并清理。** 两端 SQLite／MySQL 分别通过准确意图 102 项、拒绝及规则完整性 43 项、委托 11 项、格式 3 为 12 项；八次真实 SIGKILL 的两个点分别为 13／14 项。原凭证两端各 3753 项、公开 API 71／106 项、只读权限 64 项、当前源码公开生命周期两端各 417 项、261 类公开签名及全源码静态分析通过，保留既有可选 turbo 扩展 GLIBC 启动警告。

本组固定 27 条命令，准确输入和退出状态见[执行记录](state-api-intent-evidence-2026-10-21/execution.json)，交付核对见[核对记录](state-api-intent-evidence-2026-10-21/delivery-check.json)。两端执行四组意图检查、旧公开 API 正常／拒绝、原凭证、只读权限、公开生命周期、公开签名和实际进程终止；独立 MySQL 功能／终止分别建实例，最后做全源码静态分析。

原始测试以实际密码／TOTP 会话、签名凭证和独立目标账号构造预期规范载荷，直接核对 pending／current 的原始已持久化内容；不会只检查字段存在或复用 SDK 意图构造器。拒绝覆盖错动作／scope／kind、描述不能认证、完整来源变化、规则四类条件指纹，以及范围回调中的时钟倒退。

真实 SIGKILL 覆盖两个点：pending 已持久化、效果尚未开始；API 效果完成、current 尚未写入。控制器核对信号退出，再以新 PHP 进程、新 PDO 和新服务图读取原准确回执；前者无新账本，后者存在一条实际凭证，二者均禁止隐式重放并保持 pending。测试专用预算钩子和非预置重建只属于测试运行框架，不添加生产入口或序列化服务对象。

普通凭证回归保持 8 MiB，完整受保护图 16 MiB；PHP7.2 使用私有 sodium／posix 及原生单调时钟，不称系统原版整轮通过。一般检查外层 240 秒，控制器 600 秒；SDK 原期限不变。MySQL 使用私有目录、禁 TCP 的 Unix socket，不连接业务数据库。达到本组停止条件后不继续收集等价绿色证据。

## 仍未关闭

本组是准确意图和中断证据，不是逐笔永久审计或安全恢复提交。自定义／带效果审计委托、旧版 ApiKeys 及其他授权／一次性证明、全部写入者及旧工作进程交接、最终账号启用和新密码／MFA 登录仍开放。见证／审计自身中断与维护、通知／队列、真实 HTTP／CSRF／浏览器、外部 SMTP／OIDC／实体设备／WAF、远端 CI、独立复核及最终同源码九版整轮未由本组关闭。完整 G1／G4／F01／R1—R6 保持未完成；未提交、推送或发布。
