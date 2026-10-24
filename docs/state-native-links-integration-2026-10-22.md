# 原生签名链接与同边界业务 SQL

日期：2026-10-22。属于既定 R3.5／F01 入口集成；31 项、80 个有效工作小时上限保持。本批交付限定为原生公开工厂、只读准入、业务事务与四种运行时／后端组合的定向验收，不扩展 HTTP 页面、重置工厂或恢复启用。

## 入口与权限

`Security::signedLinks($stateAccountPolicy)` 显式接收完整状态账号策略。要求准确的 witness／source／FileStore／Clock、站点、当前 SessionRegistry 和同一身份提供方的纯 RolePolicy。工厂固定缓存的账号策略绑定：等价对象复用，字段映射变更在 I/O 前拒绝。受保护工厂不传策略继续拒绝；普通非保护调用保留原契约。带有副作用审计或不同身份提供方的 Authorizer 不支持本原生路径。

原生对象使用 `issueFor / allFor / revokeFor / revokeAllFor` 管理、`verifyFor` 验证或 `withVerification` 执行业务。它的旧 `issue / verify / all / revoke / revokeAll` 入口明确拒绝，避免接受锁外构造的 Target 或遗漏当前管理身份。普通对象及既有手工边界接线保持原调用方式，手工保护模式先检查已进入准确边界，再调用外部请求保护。

每个 For 方法传入准确 PDO、完整业务表声明和服务端只读 `prepare(PDO, ?VerifiedSession): Target`。SDK 在独立见证排他锁内检查完整来源，然后管理操作从真实 SQL／密码／因子／会话重建当前身份，纯 RolePolicy 判断对象和字段。prepare 在锁内查询当前目标 owner／version，不能信任请求中的版本和所有者。回调是受信任宿主代码，SDK 不提供任意 PHP 沙箱；不得写入、输出、控制事务或发起外部效果，全部写入者必须共用边界。

匿名验证使用明确的签名持有者能力，不伪造账号身份，也不隐含授予 Cookie 对应账号的其他权限。目的、当前对象属性／版本、路径／参数、原始 URL、实际方法、期限、绑定、HMAC、当前证明代际和真实账本均在 pending 前检查。无效／过期／已消费／空查询结果不写 pending，普通权限拒绝亦如此。请求保护仅在准入阶段调用一次，须严格返回 true；管理入口仍由宿主校验真实请求、CSRF 和预算，验证入口仍须校验实际路由／方法及相应请求保护。

持久意图记录准确 `links.issue / verify / all / revoke / revoke_all / execute`、真实管理员摘要或显式 bearer 摘要、当前 Target 指纹、声明表名、观察来源摘要、证明／绑定摘要及策略摘要。策略绑定账号字段映射、RolePolicy、Link Policy、站点和实际当前签名密钥上下文；根记录不保存原始 URL、会话令牌或绑定明文。记录是描述，不是授权能力。

## 业务提交与故障

`verifyFor` 只返回当次验证结果，不能将其缓存为后续写入的权限。业务变更使用 `withVerification`：在同一见证内消费链接，独占一次 SqlTransaction，调用一次 `work(PDO, VerifiedLink)`，检查时间／会话／链接期限，提交业务 SQL，最后持久化 current 后才把结果返回宿主。禁止 work 输出正文、外部 I/O、DDL 或接管事务；不能自动重试。

[StateDocumentLinks.php](../examples/StateDocumentLinks.php) 使用已有 StateDocuments 的完整表声明，锁内读取实际 owner／version，POST 链接消费后按 scope／id／owner／version 比较更新 title 和版本。目标版本必须是未耗尽的规范正整数；输入 title 在进入效果前验证。示例是可信服务器接线，不自动注册路由或提供宿主 HTTP 验收。

业务抛错、期限跨越、提交后最终见证失败均保留 pending；已消费一次性证明不退款、不重放。真实中断点固定为 pending 持久化后、SQL 更新后提交前、SQL 提交后 current 前；新进程重新构造 PDO 和原生服务图，必须在任何 loader／guard／work 前拒绝 pending。中间停点另有竞争写入者，必须先等待原持有者死亡，再拒绝，不能绕过锁。

## 有限验收

[冻结执行清单](state-native-links-evidence-2026-10-22/execution.json)固定八条命令：PHP7.2／8.5 × SQLite／私有 MySQL，分别执行四个原生链接专项、既有原生 Grants 工厂、三个证明退役兼容专项以及三个真实 SIGKILL 点；SQLite 另执行普通 Links 和低层证明代际。其余四条为两端公开契约、PHP7.2 目标静态分析和 PHP7.2 语法。保护模式 16 MiB，普通专项 8 MiB。PHP7.2 使用先前私有 sodium／posix／CLOCK_MONOTONIC 环境，不代表系统原版 PHP7.2 验收。

冻结前失败及修正保留于[预检记录](state-native-links-evidence-2026-10-22/preflight-notes.md)。最终结果以冻结执行清单与交付核对为准；检查运行期间不修改冻结的源码／测试／契约输入。

**已执行并通过：固定八条命令全部退出 0，冻结输入前后哈希一致。** 四种组合的链接生命周期／拒绝／异常／公开工厂分别为 108／96／54／24 项；既有 Grants 工厂 26 项、证明退役／拒绝／续办 81／78／221 项。SQLite 两端另通过普通 Links 1575 项与低层代际 23 项。十二次真实 SIGKILL、四次等待竞争者均通过；新读取器在 loader／guard／work 前拒绝 pending。两端 263 类公开契约、PHP7.2 目标静态分析和 839 个文件 PHP7.2 语法通过，保留可选 turbo GLIBC 加载警告。

[交付核对](state-native-links-evidence-2026-10-22/delivery-check.json)确认四个测试根、十二个中断子目录和两次私有 MySQL 全部清理，没有在途测试。[库增量](state-native-links-evidence-2026-10-22/library-delta.json)为七个既有源码文件；新增一个业务示例，既有普通链接／代际、Grants 工厂、证明退役测试及受管 HTTP 示例字节保持。[API 增量核对](state-native-links-evidence-2026-10-22/api-additions.json)确认无新增公开类型，新增九个方法；Links 构造函数追加四个可选参数，Security::signedLinks 追加一个可选参数。去掉这些增量后，旧契约摘要完全一致。本批到此停止扩测。

## 停止边界

本批通过也只关闭上述原生 SDK 入口与定向检查。新入口 HTTP／浏览器、最终九版本整轮、完整恢复启用、受保护 ResetTokens 工厂，以及签名密钥／历史授权的其他处置仍开放。上一业务宿主 PHP8.5／MySQL 的未解释 503 保持失败，不用本组 CLI 通过抵销，不超出既定一次诊断额度重试。完整 F01／R1—R6 不关闭，不提交、不推送、不发布。
