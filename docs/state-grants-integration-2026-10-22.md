# 原生一次性操作授权与业务事务

日期：2026-10-22。继续既定 P1／G1、R3.4 与 G5 的 SDK 接入，31 项／80 个有效工作小时上限不变。上组业务 HTTP 的一次未解释 503 保持未关闭；本组不重新执行该诊断，也不以其他检查替代它。

## 交付行为

`Security::operations($stateAccountPolicy)` 显式选择原生模式。构造要求准确的认证 FileStore、缓存 SessionRegistry、Clock、边界及纯 RolePolicy；身份提供器不同、自定义策略或带效果审计时提前配置拒绝，不静默丢弃审计。原 `operations()` 与第七参数 StateBoundary 的手工组合保留，仍由宿主在外层实际授权边界内调用；两种实例分开缓存。原生实例不能作为手工组合／独立恢复审批的嵌套依赖。

原生 `begin`、`confirm`、`consume`、`revoke`、`revokeAll` 直接调用。锁内从完整来源重建当前账号、密码身份、因子及真实会话，以纯 RolePolicy 核对服务端 Intent 的对象／字段；格式预检通过后的请求守卫在锁内至多执行一次且在 pending 前。普通认证／权限／容量／不存在记录拒绝不更新会话、证明账本或独立见证；无新认证的正常确认拒绝也在 pending 前结束。

保持原单次契约：确认必须是同一会话 ID／创建时间、准备后秘密已轮换并满足近期强度；消费绑定批准后的实际会话秘密、认证时间及方式。有效且绑定的证明遇到已获对象权限但参数指纹改变时，在效果阶段销毁，返回 null，并正常完成 current；它不是可无效果重试的输入拒绝。确认阶段即使尚未重新认证，只要原强认证仍满足确认策略，已授权参数的改变也保持原有销毁行为。

## 消费与业务在同一边界

`Grants::execute(scope, subject, sessionToken, grant, pdo, tables, prepare, work)` 仅用于原生模式，必须使用完整 SQL 来源的准确 PDO 和已声明的一至四张完整业务表。prepare 是受信任的只读服务器加载函数，接收 PDO／当前 VerifiedSession，返回验证过参数的不可变 Intent；SDK 再做当前对象／字段权限和证明绑定判定。不得让客户端自报 owner、Resource 或策略决定代替加载与权限。

pending 之后才消费证明，随后开启 SDK 自有 SQL 事务，调用一次 work(PDO, Permit)，提交前／后检查时间与 Permit 到期，最后确认完整来源／current 才返回成功值。不得预先开启宿主事务、执行 DDL／COMMIT／ROLLBACK、切换连接或在工作回调发送外部消息。SDK 不沙箱化任意 PHP／SQL；全部关联写入者仍须共用见证／围栏。

SQL 回滚不会恢复已消费的文件证明。工作回调异常、提交前到期或提交后最终确认失败保持 completion_unknown／pending，禁止自动退回证明或重放业务。保留 `consume()` 的返回类型和原行为用于既有组合；受保护业务应使用 execute，将检查、消费和业务全部放在同一边界，不能把独立返回的 Permit 当作可缓存凭证。

新增 [StateDocumentGrants.php](../examples/StateDocumentGrants.php) 消费者展示参数验证、实际 owner／version 加载、明确 title 字段及版本比较更新，沿用 [StateDocuments.php](../examples/StateDocuments.php) 的表声明和 RolePolicy；不自动创建表或初始化权威。

## 准确意图及兼容

新增 authorized 动作 operations.begin／confirm／consume／revoke／revoke_all／execute；结构仍使用原格式 2／3 的八字段 StateOperation，不引入新根格式。主体字段指真实会话账号／证明账本所有者，业务对象及参数由 Intent 指纹绑定。权限摘要固定绑定入口、账号身份、真实会话引用、Intent、确认／授权引用、业务表名、完整观测摘要和策略摘要；策略摘要绑定准确 StateAccountPolicy、Operation Policy 和纯 RolePolicy。原始会话秘密、确认／授权秘密和业务参数明文不写入回执。

开发检查曾发现已标准化 Clock 上残留冗余默认值表达式，静态分析拒绝；已删除该冗余表达式，没有抑制诊断。公开候选审阅新增 SessionRegistry 的纯策略匹配方法、StateOperation 操作描述构造、Grants.execute、Grants 构造末尾可选 statePolicy 及 operations 的可选参数；类数量保持 261。普通 API 签名既有参数顺序及返回类型保留。

## 固定验证与停止

[execution.json](state-grants-evidence-2026-10-22/execution.json) 记录冻结内容和固定十条命令。两端各执行 SQLite 新操作授权与兼容组、私有 MySQL 正常／拒绝／工厂组、另一私有 MySQL 故障／普通 SQL 组和公开契约，最后检查库 src 静态分析及语法。普通操作授权／SQL 兼容检查保持 8MiB；保护服务图使用 16MiB。PHP7.2 是既有私有 sodium／posix／原生单调时钟解释器，不声明系统原版完整门禁。

新检查使用真实账号 SQL、认证文件、密码／TOTP 和保持 ID 的秘密轮换；包含无新认证拒绝、有效参数篡改销毁、一次性消费、取消、容量／对象／字段拒绝、角色撤销与旧角色＋会话／因子／证明文件回放、准确 pending/current 回执、真实版本更新、实际 SQL 回滚和已提交结果未知。未知结果以确定性异常／时钟注入验证，不冒充新入口真实进程死亡。

**初轮已执行并通过：** 固定十条命令全部退出 0，初轮输入未变；新生命周期／拒绝／未知结果／工厂分别为 112／73／72／20 项，四个运行时／后端组合一致，手工入口、原认证工厂、API 意图及 8MiB 普通操作／SQL 兼容检查同时通过。

**复核发现并复现的缺口：** 初轮通过后，补充字段映射变化的反例，原工厂未拒绝新的语义策略而复用了旧实例，定向用例退出 255。原始输出保留在 [cache-regression-before.log](state-grants-evidence-2026-10-22/cache-regression-before.log)。修复将缓存固定到 StateAccountPolicy.binding：同样语义的新策略对象仍复用实例，不同映射在 I/O 前明确拒绝。没有改变操作授权核心或既有公开签名。

**定向修复复验：** [cache-fix-execution.json](state-grants-evidence-2026-10-22/cache-fix-execution.json) 单独记录修正身份及固定八条工厂／契约／静态／语法检查，八条全部退出 0，执行中内容不变；修正后的四个运行时／后端组合工厂检查各为 26 项，原手工工厂各 116 项。原十条日志／源码清单保留，没有将两种测试源码写成一次最终整轮通过。新断言核对相同策略指纹复用、不同映射拒绝、错误来源拒绝、无构造 I/O、手工模式兼容和真实密码／MFA／业务 SQL。

最终[交付核对](state-grants-evidence-2026-10-22/delivery-check.json)确认：初轮十条、修后八条均通过，各自清单分别保存；初轮后的库代码只修改 Security 工厂缓存，其余新生命周期／拒绝／SQL 故障实现和消费者字节不变。六次私有 MySQL 目录及关联进程全部清理。两端 261 类公开契约、PHP7.2 目标库静态分析及变更脚本／消费者语法通过；保留既有可选 turbo 扩展 GLIBC 警告。原受管 HTTP 示例与上一组字节相同，没有重跑或关闭其未解释 503。

当前只收口这些 SDK 接入与缓存修复检查；没有启动最终九版本整轮。

## 尚未完成

本入口实际 HTTP／CSRF／浏览器、自己的真实强杀／并发与独立恢复退役清单尚未验收；上组其他业务 API 的强杀记录不能代替。其他授权／带审计策略、链接／nonce／重置证明及所有写入者、最终恢复启用和新密码／MFA 登录、通知／审计维护与外部目标、最终同源码九版整轮／CI／独立复核仍开放。完整 F01／R1—R6 不关闭，未提交、推送或发布。
