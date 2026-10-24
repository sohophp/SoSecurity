> 2026-10-22 G1／G4 前置：[工作进程栅栏来源](state-fence-source-2026-10-22.md)已复现并修复旧签名 open 文件回滚后重开工作的问题；实际目录完整字节进入来源，绑定栅栏及原生工厂强制核对覆盖。固定八条检查全部通过，四种组合和新进程拒绝回滚，十二个既有 HMAC 强杀点及四次竞争等待通过；输入保持、临时资源已清理。最终恢复启用、当前九版整轮及旧 503 仍开放，31 项／80 小时上限保持。

> 2026-10-22 G1／R1.4：[物理文件容量准入](state-admission-capacity-2026-10-22.md)已复现并修复 Links／ResetTokens／Grants／CredentialRegistry 满额新增账本时进入 pending 的问题；保留修前四个失败。固定八条检查全部通过，四种组合的16次容量拒绝及8次真实空位竞争通过，输入保持，公开清单字节保持，四个测试根和两次私有 MySQL 已清理；序列化／其他容量、其余写入者、最终恢复和当前九版整轮仍开放，31 项／80 小时上限保持。

> 2026-10-22 G1／R4.2：[原生 HMAC](state-native-hmac-integration-2026-10-22.md)将实际密钥环及签名策略纳入完整来源，接通准确工厂、nonce／容量只读准入、同边界 SQL 和旧配置新读者拒绝。固定八条检查全部通过，四种组合／十二次真实强杀及四次竞争等待通过，输入保持，四个测试根与两次私有 MySQL 已清理；在线提供器、Webhook／旧 ApiKeys、维护／最终恢复、当前九版整轮及旧 503 仍开放，31 项／80 小时上限保持。

> 2026-10-22 G1／R2.6：[原生重置证明](state-native-reset-integration-2026-10-22.md)已接入显式状态策略／请求授权工厂、锁内真实密码／因子／邮箱版本绑定和同边界消费／密码 SQL；固定八条检查全部通过；四种组合／十二次真实强杀和四次竞争等待通过，输入保持，四个测试根及两次私有 MySQL 已清理。完整 Recovery、原生 HTTP、其他授权／维护、最终启用、当前九版门禁及旧 503 仍开放，31 项／80 小时上限保持。

> 2026-10-22 G1／R3.5：[原生签名链接](state-native-links-integration-2026-10-22.md)已接入显式工厂、真实当前管理会话、锁内目标／只读准入和同边界一次性消费／SQL；本批固定八条定向检查全部通过，四种组合／十二次真实强杀及四次竞争等待通过，输入哈希保持，四个测试根和两次私有 MySQL 已清理。新入口 HTTP、受保护 ResetTokens、最终恢复、九版本当前整轮及旧 503 仍开放，31 项／80 小时上限保持。

> 2026-10-22 G1 当前：[原生一次性操作与业务事务](state-grants-integration-2026-10-22.md)已接通五个直接入口、真实重新认证、同边界证明消费／SQL 及准确意图；复核中复现并修正字段映射策略被缓存忽略的问题。初轮十条、修后八条定向检查通过，两端 SQLite／MySQL 记录分别绑定内容，六次私有 MySQL 已清理。新入口 HTTP／真实强杀、最终恢复及上组未解释 503 仍开放，完整 F01／R1—R6 不关闭，31 项／80 小时上限保持。

> 2026-10-22 G5 当前：[格式 3 业务宿主、浏览器与真实中断](state-business-host-integration-2026-10-21.md)已接入原生 Bearer 文档更新、联合业务／认证备份回放、四次 Chromium、十二个真实强杀点及四次并发等待后拒绝。初轮 PHP8.5／MySQL 一次所有者拒绝返回异常 503，单次带诊断复验通过但根因未明，整组仍未通过验收；剩余六项通过、资源已清理。SDK src／公开契约与上一组字节一致；不关闭完整 F01／R1—R6，31 项／80 小时上限保持。

> 2026-10-21 G5 当前：[原生 Bearer 与业务 PDO 事务组合](state-business-integration-2026-10-21.md)已将只读准入、服务端对象／字段授权、真实 SQL 提交与最终见证放入同一边界，加入文档版本比较更新示例。固定八条命令全部通过，四个运行时／后端组合通过、输入一致，两个自建 MySQL 已清理；本入口业务 HTTP、真实强杀／并发、格式 3 完整业务流程、其他入口与最终恢复仍开放，不关闭完整 F01／R1—R6，31 项／80 小时上限保持。

> 2026-10-21 G5 当前：[MySQL HTTP 与持续时钟到期](state-http-mysql-integration-2026-10-21.md)已补两端真实 MySQL HTTP／TLS，SQLite／MySQL 均核对请求中实际到期且 pending 前拒绝、旧 SQL／认证文件／PHP 会话回放拒绝。固定 12 条命令全部退出 0，六次 Chromium、八次实时到期检查通过，八个临时宿主和四个临时 MySQL 已清理；业务事务组合、其他入口和最终恢复仍开放，完整 F01／R1—R6 不关闭，31 项／80 小时上限保持。

> 2026-10-21 G5 当前：[原生受保护宿主 HTTP／TLS／Chromium](state-http-integration-2026-10-21.md)已接通同图登录／MFA、真实 CSRF／Origin 与 Cookie／Bearer 隔离，联合恢复旧 SQL、认证文件和 PHP 会话后旧令牌及旧 Cookie／CSRF 均拒绝。固定 11 条命令全部退出 0、输入一致，四个临时宿主已清理；MySQL HTTP／业务事务组合、其他入口及最终恢复仍开放，不关闭完整 G5／F01／R1—R6，31 项／80 小时上限保持。

> 2026-10-21 G1 当前：[账号 API 准确意图与真实中断](state-api-intent-integration-2026-10-21.md)已绑定实际操作者／目标、凭证摘要、标准化参数、身份／范围、完整来源和准确策略，pending／current 保留同一意图。固定 27 条命令全部退出 0、八次真实强杀通过，输入一致、四次临时 MySQL 已清理；其他授权／写入者、宿主 HTTP 与最终恢复仍开放，不关闭完整 G1／G4／F01／R1—R6，31 项／80 小时上限保持。

> 2026-10-21 G1 当前：[账号凭证 API 公开工厂与写入前准入](state-api-entry-integration-2026-10-21.md)已接通准确原生图的八个公开入口；普通拒绝在 pending 前结束，已发生效果的未知结果继续隔离。固定 27 条命令全部退出 0，输入一致、四次临时 MySQL 已清理；精确操作者／目标意图回执、自定义／带审计委托、其他授权及最终恢复仍开放，不关闭完整 G1／F01／R1—R6，31 项／80 小时上限保持。

> 2026-10-21 G4 当前：[账号 API 凭证原生退役与准确边界](state-managed-api-integration-2026-10-21.md)已接入同一实际服务图、八个入口的前置边界检查、固定空账本／代际和新批准续办。固定 25 条检查全部退出 0、12 次真实强杀恢复通过，输入一致、四次临时 MySQL 已清理；公开 API 宿主前置准入及工厂、其他证明和最终启用仍开放，不关闭完整 G4／F01／R1—R6，31 项／80 小时上限保持。

> 2026-10-21 G4 当前：[旧版 API 密钥主体代际处置](state-api-retirement-integration-2026-10-21.md)已接入准确独立批准、固定永久标记及未知效果续办，旧格式／旧代际密钥拒绝，新代际可签发。固定 27 条检查全部退出 0、12 个真实终止恢复场景通过，输入一致、四次临时 MySQL 已清理；受保护 API 工厂、其他授权和最终启用仍开放，31 项／80 小时上限保持。

# 验证记录

## F01 无状态变更预算拒绝（2026-10-21，本地）

2026-10-21 G1 无状态变更的预算拒绝：[真实回滚凭据与完整来源核对](state-budget-integration-2026-10-21.md)已接入三个公开生命周期。账号／最终预算拒绝只有在精确事务确认回滚、本次上下文有效且来源未变时才结束 pending；已提交尝试、文件变化、回滚失败及旧凭据重放保持未知。28 条初次检查、修正底层重放反例后的 8 条及两端普通预算 8MiB 检查通过，输入一致、两次临时 MySQL 已清理。已有合法进展的拒绝、地址变更授权及完整恢复仍开放，不关闭 G1／F01。

已执行并通过：两端 SQLite 和私有 MySQL 的实际账号／最终预算拒绝、两个入口形态的凭据重放拒绝、已提交尝试保留、覆盖文件变化／回调错误／回滚失败的隔离，以及受影响原始存储／授权／纯权限／上下文／生命周期／SQL／接口和静态检查。初次 28 条绿色后另有真实底层重放反例，修正后独立记录 8 条有限复验，不能把初次结果冒作已覆盖该遗漏。最终普通预算 8MiB 两端检查通过且 SDK 源码不变。PHP 7.2 使用私有 sodium／原生单调时钟，Fiber 未执行；PHP 8.5 Fiber 和两端子进程分别有结果。见[准确交付核对](state-budget-evidence-2026-10-21/delivery-check.json)。未执行真实 HTTP／外部验收、最终九版整轮及独立复核，尚未发行。

## F01 生命周期公开请求前置准入（2026-10-21，本地）

2026-10-21 G1 公开生命周期前置准入：[注册／两类恢复的公开方法](state-request-integration-2026-10-21.md)已接入准确边界前的输入／公共预算和锁内请求复查，三个实际 SDK 流程通过。首次 MySQL 完成确认超时保留原始失败；受限复用事务内表结构检查后，18 条修正检查及 4 条测试依赖检查通过，准确输入和资源清理已核对。账号／最终预算拒绝、地址变更授权、真实 HTTP 与最终安全恢复仍未完成，不关闭 G1／F01。

首次 20 条中 19 条通过、MySQL 一条失败，PHP 8.5 MySQL 在该次控制器中未执行；隔离诊断确认 `sql.timeout`。修正后 SQLite 两端实际流程、三类原回归、事务／DDL 与接口及静态共 18 条通过；只移除 SQL 测试的额外 sodium 依赖后，普通 PHP 7.2／PHP 8.5、两端 MySQL 和脚本语法 4 条通过。见[准确来源核对](state-request-evidence-2026-10-21/delivery-check.json)，不同快照不能拼为最终九版整轮。真实 HTTP／浏览器、SMTP、外部审批、发行与独立复核仍未执行。

## F01 生命周期连接保护（2026-10-21，本地）

2026-10-21 G1 生命周期后续：[连接声明与原始 SQL 入口保护](state-lifecycle-integration-2026-10-21.md)已接入主 SDK，固定 28 条命令全部通过、输入一致、临时 MySQL 已清理。新增生命周期测试在两端 SQLite／MySQL 各 171 条；四种初始化和实际注册流程已验证。原生公开请求前置检查、其余完整受保护流程、其他授权入口及最终安全恢复仍开放，不关闭完整 G1／F01。

已执行并通过：两端既有生命周期／工厂／事务与隔离恢复、API、独立禁 TCP MySQL 和 PHP 7.2 目标 level 5 静态检查，共 28 条。准确命令及输入见[执行记录](state-lifecycle-evidence-2026-10-21/execution.json)。PHP 7.2 使用私有 sodium／原生单调时钟；工具可选 turbo 扩展因 GLIBC 不匹配报警，但静态分析完成且无错误。开发快照的两项失败和修正详见接入记录，原始日志保留；本组不是最终九版整轮或外部验收。

## F01 显式认证工厂与纯策略（2026-10-21，本地）

已执行并通过：[认证工厂接入](state-factory-integration-2026-10-21.md)的前序两端 22 条运行检查；静态检查因一项不可达重复判空退出 1，修正后两端工厂／API、五份源码静态、入口语法及私有禁 TCP MySQL 共 7 条通过。MySQL 两端工厂各 110 条、旧因子工厂各 129 条，临时服务器关闭删除；没有授予全局 TRIGGER 权限。随后底层原始因子登记补齐格式 1 的提前拒绝，两端当前 SQLite 工厂各 116 条及五份源码静态共 3 条通过。每处变化及准确输入独立记录，[交付核对](state-factory-evidence-2026-10-21/delivery-check.json)通过，不拼接为同一快照整轮。

新检查执行真实登录、持久登录轮换、旧凭据拒绝、MFA 重新认证、当前策略及授权、旧认证文件恢复拒绝；构造／诊断及错误依赖拒绝没有业务 SQL、回调或状态效果。新增三项公开方法，251 个旧类型与全部原签名保留；指南中英文代码一致，两端语法通过。PHP7.2 使用私有原生单调时钟／sodium，静态可选 turbo 的 GLIBC 启动警告保留。第一次预检错用已轮换的旧会话、前序静态失败及弱格式登记复现均保留。

当前边界套件增至 29 个固定用例，本组没有重跑当前全套或九版本矩阵。当前保护工厂仅接入已声明的密码／受管理 FileStore 认证服务图，完整生命周期、其余 API／请求证明／后台写入者和最终安全恢复仍未完成。该组达到停止条件，F01／R1—R6 继续开放。

## F01 授权与嵌套存储入口修复（2026-10-21，本地）

已执行并通过：[入口修复](state-entry-fix-2026-10-21.md)的 17 条固定命令。PHP7.2 私有原生单调时钟／sodium 与 PHP8.5 的 SQLite／MySQL 新增入口各 71 条、独立恢复各 43 条；两端普通授权、认证、持久登录、原始存储和 API 检查通过。五份源码按 PHP7.2 目标、level 5 静态检查及入口语法通过；运行输入摘要始终一致，自建禁 TCP MySQL 已关闭删除。命令、源码／日志摘要和有限范围见[执行记录](state-entry-evidence-2026-10-21/execution.json)及[交付核对](state-entry-evidence-2026-10-21/delivery-check.json)。

修复覆盖五个授权入口的提前拒绝、早于目录登记构造的旧服务、准确会话边界、namespace 包装中的保护存储，以及保护会话与未保护存储的混合构造。旧复现及 API 检查脚本数据结构判断错误保留，不当成产品通过。MySQL 恢复目标使用 MySQL，独立管理员用隔离 SQLite；本组没有授予全局 TRIGGER 权限，不证明固定破坏性恢复的低权限适配完成。两份指南示例一致、两端语法及本地链接检查通过。

当前常规边界套件增至 28 个固定用例，本组只复验受影响部分；没有把历史 27 项与新专项拼成当前同一快照全套／九版门禁。完整工厂、生命周期／后台／API 写入者、最终安全恢复及外部验收仍未完成，F01／R1—R6 保持开放。

## F01 独立见证与显式认证边界（2026-10-21，本地阶段）

主 SDK 新增见证、物理目录守卫、当前权限判定及分阶段隔离恢复，范围见[接入记录](state-boundary-integration-2026-10-21.md)。前序冻结快照两端各八项命令通过，包含各 27 个 SQLite 边界用例、四类完整声明备份恢复与危险负面对照。静态工具先因默认 128 MiB 中止；提高工具限额后发现执行状态推断问题，修正为内部上下文类型。新快照仅三份输入有变化，两端受影响检查、API、39 份源码静态检查及入口语法已通过，控制器自建隔离 MySQL 两端各 27 个用例已通过；11 条增量命令均退出 0，运行输入摘要一致，临时数据库已关闭删除，见[交付核对](state-boundary-evidence-2026-10-21/delivery-check.json)。专项另外复现的 `Grants` 提前拒绝及嵌套包装识别缺口仍待下一组修复。准确快照分别见[前序执行记录](state-boundary-evidence-2026-10-21/final-execution.json)与[增量收口记录](state-boundary-evidence-2026-10-21/closure-execution.json)，不能合称同一快照完整门禁。

PHP7.2 使用私有原生单调时钟扩展与 sodium，Fiber 子场景未执行；PHP8.5 执行 Fiber。静态工具使用 512 MiB，SDK 用例仍为 16 MiB；可选 turbo 扩展的 GLIBC 启动警告保留。完整工厂／全入口、最终安全恢复、九版当前候选整轮、外部目标和实体设备未由本专项验收，F01／R1—R6 保持未完成。环境沿用 WSL 内自建服务，见[环境说明](testing-environment-2026-10-21.md)。

## F01 共用状态校验基础接入（2026-10-21，本地）

`Ledger`、`FactorRegistry`、`TotpFactors`、`ManagedFactorStore` 共用四个内部纯校验类型，原 232 类／接口公开签名保持。PHP7.2 私有 sodium 启动器与 PHP8.5 的共享校验、SQLite 账本、完整加密 MFA、认证、工厂、普通因子操作、迁移及恢复专项均通过；私有 MySQL 终态与各条日志见[接入记录](state-codecs-integration-2026-10-21.md)。八份运行源码的 PHP7.2 目标静态检查通过，可选 turbo 扩展启动警告保留。新增测试首次在 PHP8.5 因 `JsonSerializable` 兼容提示失败，修正测试方法声明后复验通过，初次失败保留。本专项不等于独立见证、全入口、防旧备份恢复或最终安全恢复已经实现，也不作为当前源码九版整轮证据。完整执行范围见[R1—R6 有限周期计划](full-plan-2026-10-21.md)。

## 幂等 SQL 元数据限量读取（2026-10-21，本地）

针对候选审查 F02，根、执行记录、历史与维护查询改为 SQL 返回前按实际类型／字节限量，正文保留独立长度和摘要检查。最终 PHP7.2.34／8.5.9 在 8 MiB 下 SQLite 输入边界及真实分页查询计划各 128 项，既有幂等／安全／正文预算／工厂各 135／190／20／48 项通过；两版控制器自建禁 TCP MySQL 的边界各 138 项，既有幂等／安全／并发各 135／190／31 项通过。两版 232 类／接口 API、两个源码的 PHP7.2 目标 level5 静态检查、语法与文档检查通过。MySQL 已关闭清理，工作进程已回收。

初版通过后查出 CASE 投影别名引入 SQLite 临时排序，明确原表排序列并补查询计划测试后，才复验最终源码；两个快照分别保存，不合并冒称同一快照。静态工具可选 turbo 扩展的 GLIBC 启动警告、此前测试控制器缩进错误均保留。准确命令、源码摘要和证据见[本轮有限验收](idempotency-bounds-fix-2026-10-21.md)。不修改数据库结构；未执行新消费者／归档、九版整轮、远端 CI、真实宿主、生产或独立审查。完整旧备份风险继续未关闭，未提交、推送或发布。

## 旧因子迁移账号安全通知（2026-10-20，本地）

已执行并通过：`tests/account-factor/migration-notices.php`在PHP7.2.34私有sodium运行时与PHP8.5.9的临时SQLite、控制器自建私有禁TCP MySQL各22项。真实迁移的`reserved`、`completed`、`activated`、`cancelled`及`reapproved`五种事件由可信回调写入`FactorNotices`；通知标识从原操作和本次审批随机编号确定性派生，拒绝完成阶段通知时保留`reserved`意图，重新审批可继续且不会与旧通知错误合并。两版通知基础各188项、固定邮件模板／发送预算各96项、232类公开API签名及全新Composer路径消费者各十二组加通知生命周期36项通过。只使用本地测试数据库；迁移历史批量维护事件不作为单账号通知，真实SMTP、目标宿主、远端CI与完整R2.7未由本关口验收。

## 因子替换取消与到期清理通知（2026-10-20，本地）

已执行并通过：`tests/account-factor/recovery-terminal-notices.php`在PHP7.2.34私有sodium运行时与PHP8.5.9的临时SQLite、控制器自建私有禁TCP MySQL各20项。真实`FactorRecovery`取消和保留期清理回调分别写入`factor_recovery_cancelled`、`factor_recovery_purged`加密通知；取消发布拒绝时SQL状态不变且可重试，清理发布拒绝时保留SQL流程和旧通知，报告`account.completion_unknown`，关闭态复核后可准确完成清理。两版全新Composer路径消费者各十一组加通知生命周期36项通过；两版新测试样例语法、Python脚本检查及`git diff --check`通过。临时MySQL控制器退出0；只使用本地测试数据库，物理删除不承诺随SQL回滚；真实SMTP、目标宿主、远端CI及完整R2.7未由本关口验收。

## 独立因子替换的固定安全通知（2026-10-20，本地）

已执行并通过：`FactorRecovery`成功替换时实际发出`factor_replaced`；补入`Notice::supports()`后，`FactorNotices`可同PDO保存与`factor_recovery_started`不同编号的无秘密加密通知。`tests/account-factor/recovery-notices.php`在PHP7.2.34私有sodium运行时及PHP8.5.9的临时SQLite、控制器自建私有禁TCP MySQL各13项；发布拒绝时账号绑定、通知和Outbox不提交，预先持久计费的证明尝试数加一且流程其他字段不变。两版`account-foundation`各178项、`account-send-budgets`各94项、232类／接口公开API签名及全新Composer路径消费者各十组加通知生命周期36项通过；两版语法、Python脚本及`git diff --check`通过。私有MySQL控制器退出0；只使用本地测试数据库，真实SMTP、目标宿主、远端CI及完整R2.7未由本关口验收。

## 因子恢复终态清理通知（2026-10-20，本地）

已执行并通过：`tests/account-factor/restoration-cleanup-notices.php`在PHP7.2.34私有sodium运行时与PHP8.5.9的临时SQLite、控制器自建的私有禁TCP MySQL各30项。取消后清理新因子与激活后清理旧因子的真实事件回调分别写入`factor_restoration_cleaned`和`factor_restoration_previous_cleaned`加密通知；发布拒绝时无新的SQL决定或通知队列记录，返回`account.completion_unknown`，通过新关闭态复核可完成准确清理。两版全新Composer路径消费者各九组加通知生命周期36项通过；语法、Python脚本检查及`git diff --check`通过。只使用本地测试数据库，物理清理不承诺随SQL回滚；真实SMTP、目标宿主、远端CI及完整R2.7未由本关口验收。

## 独立因子恢复的同库安全通知（2026-10-20，本地）

已执行并通过：`tests/account-factor/restoration-notices.php`在PHP7.2.34私有sodium运行时与PHP8.5.9的临时SQLite、控制器自建的私有禁TCP MySQL各22项。真实`FactorRestoration`事件回调在同一PDO事务分别写入恢复开始、激活的固定加密通知与`account.notice`队列引用；激活或取消时拒绝通知发布，账户、恢复记录、审计及队列均保持拒绝前状态。两版全新Composer路径消费者各八组加通知生命周期36项通过；MySQL实例退出后清理。`git diff --check`及新测试文件两版语法检查通过。只验证本地测试数据库；清理事件、真实SMTP、目标宿主、远端CI与完整R2.7未由本关口验收。

## 特权撤销的同库安全通知（2026-10-20，本地）

已执行并通过：`tests/account-factor/revocation-notices.php`在PHP7.2.34私有sodium运行时与PHP8.5.9的本地SQLite、控制器自建的私有禁TCP MySQL各13项。真实`FactorRegistry::privilegedRevocation()`成功撤销时，同PDO保存`factor_privileged_revoked`加密通知、审计和`account.notice`队列引用，由测试传输端按当前租约与发送预算处理；拒绝通知发布时，账号版本、撤销目录、审计、通知记录及队列事件一起回滚。两版全新Composer路径消费者各七组外加通知生命周期36项通过；MySQL实例退出后清理。仅验证本地测试数据库与测试传输端，其他MFA事件、真实SMTP、目标宿主、远端CI及完整R2.7仍未执行或完成。

## MFA通知密钥分页轮换（2026-10-20，本地）

已执行并通过：`FactorNotices::rotate()`在PHP7.2.34私有sodium运行时与PHP8.5.9的8MiB本地SQLite专项各36项，逐页重加密并重封存后，通知原文、编号、时间及Outbox正文／摘要保持一致；旧密钥在尚有未处理页时提前移除会安全拒绝，全部处理后仅新密钥可读取。真实普通因子管理回调在两版SQLite及私有禁TCP MySQL各13项，完成同库通知、测试传输端和分页轮换；私有MySQL实例结束后清理。两版独立Composer安装消费者各六组外加通知生命周期36项、两版455文件ZIP归档、两端232类／接口反射签名，以及原工作端50项／普通因子操作58项回归均通过。仅使用本地测试数据库；真实SMTP、其他MFA事件、目标宿主及远端CI未执行。Outbox密钥轮换仍是独立流程，本方法不改写队列。

## MFA 同库加密通知与测试投递（2026-10-20，本地）

已执行并通过：新增`tests/account-factor-notices.php`在PHP7.2.34私有sodium运行时及PHP8.5.9各22项，使用自动清理的私有SQLite验证同PDO发布／回滚、管理权限拒绝、当前读取权限、地址变化后停止、过期清理、工作端租约与发送预算拒绝。`tests/account-factor/operations-notices.php`在两版私有SQLite和控制器自建、禁TCP的MySQL各8项，实际`FactorOperations`管理事件回调把两条加密通知与Outbox引用同库提交，并由测试传输端逐条处理。受影响的旧账号通知基础、预算、工作端与普通因子操作在两版分别通过176／94／50／58项；`FactorNotices`列入232类／接口公开候选，PHP7.2／8.5反射契约一致、PHP7.2语法检查通过。两版全新Composer路径消费者各六组（含新通知回调）与455文件ZIP归档通过，严格Composer清单验证通过。MySQL专项仅使用临时测试实例，退出后清理。该证据不覆盖其他MFA事件回调、真实SMTP、目标宿主、同源码九版整轮或远端CI。

## MFA 无秘密通知类型与发送预算（2026-10-20，本地）

已执行并通过：PHP7.2.34私有sodium运行时与PHP8.5.9各运行`tests/account-foundation.php`，每版174项，覆盖固定MFA类型的无秘密加密通知、期限、错误秘密拒绝及原有私有SQLite通知／Outbox事务组合；`tests/account-send-budgets.php`各94项，覆盖特权撤销的固定模板、无操作URL、收件地址额度及重复尝试拒绝；`tests/account-dispatch.php`各50项，确认现有SQL租约、当前账号通知读取权限与工作端行为未退化。PHP7.2五个改动文件语法检查及`git diff --check`通过。上述测试只用本地测试数据，发送使用模拟传输端；MFA事件回调尚未写入可供`Dispatcher`读取的加密通知记录，正式MFA投递、真实SMTP和目标宿主未执行。

## 受管理 MFA 原生 HTTP 与 Chromium（2026-10-20，本地）

已执行并通过：`tests/managed_auth_http.py --browser` 在具备sodium的私有PHP7.2.34与PHP8.5.9各创建自动清理的私有SQLite账号、已迁移因子、工作进程栅栏、原生Session和回环HTTP服务。两端各74项HTTP检查覆盖POST／CSRF、错误密码与验证码、未完成挑战不得登录、8KiB预算、`no-store`／CSP／`nosniff`、密码加TOTP、强度2会话、Session ID轮换、旧Cookie／旧CSRF拒绝、退出及账号表不变。两端真实Chromium移动视口另完成HTML表单密码登录、一次性恢复码、`HttpOnly` Cookie轮换和退出，无页面脚本异常。两端最新ZIP归档各454文件，含原生样例及指南。仅测试本地私有库，未连接业务数据库。固定Playwright 1.58.2临时安装后成功；首次指向缺少`playwright-core`的旧临时目录时浏览器未启动，按环境失败保留。`bin/check.sh`已接入HTTP专项，CI增加PHP7.2／8.5浏览器步骤；远端CI、目标宿主当前权限／持久化、代理TLS及生产未执行。见[原生接入说明](managed-authentication-native.md)。

## 受管理 MFA 全新Composer消费者与归档（2026-10-20，本地）

已执行并通过：`tests/account_factor_consumer.py` 在具备sodium的私有PHP7.2.34及PHP8.5.9各新建Composer路径消费者，确认`Security`与`FactorRestoration`从安装包而非工作树加载；`factory`、`restoration`、`restoration-lifecycle`、`restoration-authentication`、`restoration-maintenance-durability`五组均退出0。新增工厂专项每版129项，涵盖实际密码／TOTP登录、会话强度、缺权威／冲突拒绝及旧模式兼容；其余四组各87／67／19／108项。消费者只建立自动清理的本地SQLite与私有目录。两端`tests/archive.py`各通过452文件ZIP清单，含受管理因子源码和接入指南，不含测试、vendor或私有配置文件名。CI已有该消费者入口，但远端未执行；路径消费者不等于真实下游、正式发行或完整R2.7验收。

## 受管理 MFA PHP7.2 隔离加密补验（2026-10-20，本地）

已执行并通过：重新核对私有启动器 `/tmp/sosecurity-sodium-runtime-akybbkwr/php72-sodium` 当前存在并实际加载 `sodium`、`pdo_sqlite`；用它运行 `tests/account-factor/factory.php` 在8MiB下通过129项，真实密码／TOTP登录、强度2会话、冲突与缺权威拒绝及旧模式兼容均执行。`tests/auth.php` 199项与 `tests/account-factory.php` 140项也在该PHP7.2.34运行时通过。三项均只用内存或自动创建的本地SQLite／私有目录。系统默认`php72`缺sodium的先前失败仍属实，但不能再描述为PHP7.2专项整体未完成；完整R2.7、真实宿主、外部CI及发布仍未验收。

## 受管理认证的原始 MFA 工厂边界（2026-10-20，本地）

已执行并通过：PHP8.5以8MiB运行本地SQLite的 `tests/account-factor/factory.php`，129项检查通过。在显式 `managed_factors=true` 下同时配置顶层 `mfa` 时，配置创建即拒绝，避免 `Security::mfa()` 保留同一工厂上的原始因子操作入口；关闭受管理选项后，原有 `mfa()` 仍可构造。受影响的既有认证199项和账号工厂140项分别通过；PHP7.2语法、两端231类／接口契约和`git diff --check`通过。此项只约束该工厂实例；宿主自行构造的旧因子对象和仍运行的旧工作进程必须另行停用。PHP7.2加密专项已由上方隔离运行时补验。

## 受管理 MFA 自动认证接线（2026-10-20，本地）

已执行并通过：启用 `authentication.managed_factors` 后，PHP8.5以8MiB内存限制运行本地SQLite的 `tests/account-factor/factory.php`，当时127项检查通过。实际密码加TOTP登录及强度2会话验证成功；关闭工作进程权限时登录拒绝；缺失因子服务、与旧`second_factor`冲突、缺目录及错误选项类型拒绝；旧显式`second_factor`接线仍可构造。构造和诊断不访问SQL或修改权威文件。受影响的原认证专项199项和账号工厂专项140项在PHP8.5分别通过；PHP7.2语法、两端231类／接口反射契约及`git diff --check`通过。PHP7.2实际加密专项已由上方最终129项补验；目标宿主、浏览器及完整R2.7另验。

## 受管理 MFA 登录适配工厂（2026-10-20，本地）

已执行并通过：`php85 -d memory_limit=8M tests/account-factor/factory.php` 完成115项检查，包括新`Security::managedSecondFactor()`返回强类型登录适配、实际TOTP证明、缺配置及工作进程权限拒绝、构造／诊断无SQL和权威副作用。`php72 -l`检查新增源码与专项语法，`php72 bin/api-contract.php`与`php85 bin/api-contract.php`均通过231类／接口的当前公开契约，`git diff --check`通过。测试只使用自动创建的本地SQLite与私有目录。

已执行但失败：直接用系统`php72`运行同一加密专项，在环境初始化时因未安装`ext-sodium`抛出`DependencyException`；这不是PHP7.2运行通过。随后具备所需扩展的私有PHP7.2启动器已通过最终129项专项；宿主登录接线、真实浏览器、远端CI与完整R2.7仍未执行。

## 锁定依赖机器可读快照（2026-10-20，本地）

已执行并通过：PHP7.2／8.5各运行`tests/lock_inventory.py`，对根包、`tools`和HTML Purifier验证项目的`composer.json`／`composer.lock`配对逐份生成确定性JSON，核对包名、锁定版本及两份原文件SHA-256；另外核对缺锁的OIDC可选包拒绝、含`?token=`来源URL拒绝且不输出秘密、超8MiB锁文件在8MiB PHP进程中于解析前安全拒绝。三份现有锁文件分别通过`composer validate --strict`；PHP7.2语法及`git diff --check`通过。测试只读取仓库文件与临时构造数据，不联网、不连接数据库。该内部清单不是标准格式完整SBOM，尚未覆盖无锁可选包的真实消费者、第三方来源可信性和公告审计；本地测试接入常规门禁后未重跑整版。

后续消费者接入已执行并通过：`tests/psr3_consumer.py php72`、`tests/psr15_consumer.py php72`及`tests/oidc_consumer.py php72`均在各自临时Composer安装与`audit --locked`后调用同一生成器，核对锁文件SHA-256、预期直接包和本地path来源脱敏，进程退出0。PSR-3日志适配、PSR-15预算适配及OIDC声明／关联／注销／会话、本地私有MySQL／Redis和本机TLS既有消费者检查随同运行并通过；临时安装及测试后端已清理。没有对真实下游或全部适配依赖组合生成正式保存的SBOM，也没有因此证明远端CI或生产来源可信性。

WebAuthn消费者补验已执行并通过：`python3 tests/webauthn_consumer.py php82`从当前源码在临时目录全新安装核心与可选包，精确锁定`web-auth/webauthn-lib` 5.3.9；`composer audit --locked`本次无公告并退出0。清单校验核对核心、WebAuthn包、`web-auth/webauthn-lib`及`web-auth/cose-lib`，本地path来源未输出原始绝对路径；文档列出的smoke、challenge、challenge-race、repository、persisted、device-management、device-race、recovery、recovery-race、migration十组组件命令均退出0，临时目录已清理。只验证PHP8.2本地FileStore／SQLite等组件路径；私有MySQL组合、浏览器和实体安全密钥未在本次运行。CI定义已加入PHP8.2条件入口，远端CI未执行。

版本范围补验已执行并通过：`tests/webauthn_consumer.py`另用具备必需扩展的私有PHP8.3.35运行时、本地PHP8.4.23及PHP8.5.9分别全新安装并运行同样十组组件命令，三个控制器均退出0；各次`composer audit --locked`返回无公告、清单核对通过，临时目录清理。加上前述PHP8.2结果，本地四版覆盖了可选包声明的PHP8.2—8.5范围；CI定义已扩到这四版但远端未执行。实体认证器、实际宿主审批／会话栅栏及生产仍未验收。

私有MySQL组合随后已执行并通过：`tests/webauthn_consumer.py --mysql php82`及`--mysql php85`各从当前源码全新安装并核对相同锁定依赖、执行十组组件检查，随后由`tests/mysql_check.py --webauthn`建立禁TCP临时实例，`repository.php`各通过27项MySQL仓库检查；两个控制器均退出0，临时消费者及数据库进程已清理。CI定义只在8.2／8.5端点追加该私有MySQL组合，远端未执行。该结果不覆盖真实宿主事务、设备、浏览器或生产。

浏览器同源消费者补验已执行并通过：设置本机Playwright目录后，`tests/webauthn_consumer.py --browser php82`及`--browser php85`各退出0。两次均从当前源码新建临时Composer消费者、锁定5.3.9并完成审计／依赖清单与十组组件检查，再用同一份自动加载文件运行本地Chromium虚拟认证器的HTTPS注册、登录及重放、过期挑战、篡改签名、错误Origin拒绝。浏览器测试只创建临时SQLite、两个127.0.0.1 HTTPS端点和自签名证书，临时目录已清理；自签名证书在测试浏览器中忽略证书错误，不构成生产TLS、实体安全密钥或真实宿主审批／会话栅栏验收。

随后把这条浏览器链接入CI定义，仅在PHP8.2／8.5安装精确Playwright 1.58.2和Chromium，并在同一全新消费者命令中追加`--browser`；PHP8.3／8.4仍只执行组件检查。已执行并通过：本地YAML解析得到26个步骤、临时npm安装能运行`playwright --version`并报告1.58.2、`git diff --check`。远端CI工作流和其浏览器环境**未执行**，以上本地检查不证明远端通过。

Signal API补验已执行并通过：浏览器测试在注册后从私有SQLite重新读取本账号`StoredCredential`并转换为`CredentialRecord`，由`acceptedCredentialsSignal()`生成当前有效凭据列表，再由本地Chromium实际调用`PublicKeyCredential.signalAllAcceptedCredentials()`；PHP8.2／8.5的全新消费者各退出0，原浏览器注册／登录和拒绝路径仍通过。首轮把`StoredCredential`直接传给信号生成器，按预期接口类型检查失败，已修正测试接线并重跑；不能将首轮计作通过。此项只证明当前有效列表的信号构造和调用，不证明删除后客户端列表真的更新，也不涉及实体安全密钥、真实宿主或远端CI执行。

删除后客户端同步补验已执行并通过：PHP8.2／8.5各从当前源码新建Composer消费者并运行十组组件测试和本地Chromium闭环。测试先用内置型与USB型两个虚拟认证器注册本账号两条真实凭据，服务端通过`DeviceManager`的测试授权接口删除第一条，再按数据库当前有效记录生成仅含第二条的信号；浏览器调用`signalAllAcceptedCredentials()`后，CDP读取确认第一认证器为0条、第二认证器仍为1条。两端均退出0，临时SQLite、证书与消费者已清理。两个先行测试方案分别因CDP拒绝跨认证器导入凭据、Chrome不允许同环境两个内置认证器而失败；改用USB型第二认证器后通过，失败方案不计作通过。此结论只覆盖Chromium虚拟认证器与本地测试授权，不证明实体设备、真实宿主近期认证／CSRF／会话栅栏、远端CI或生产。

宿主会话设备授权适配器补验：新增`SessionDeviceAuthority`，每次从宿主回调重读服务端会话并经`SessionRegistry`核验同账号、强度2与近期认证；证明由共享`CsrfTokens`签发并按会话和设备一次性消费，删除后要求仍为同一有效会话。首版PHP8.2／8.5全新消费者各十一组退出0、新增专项各9项；随后增加返回阶段不可重放检查，最终源码复验见下段。首轮测试倒拨固定时钟，被核心注册表正确拒绝；改为单调时间并建立新会话后重跑通过。另一次PHP8.5控制器未设置本机Playwright目录而在开始前退出，带正确环境重跑通过。专项只用内存原子存储与SQLite测试库，不是宿主真实HTTP／CSRF部署、恢复栅栏、远端CI或生产验收。

该阶段源码复验已执行并通过：`tests/webauthn_consumer.py`在PHP8.2—8.5四版各从当前源码全新安装、审计并核对锁定依赖，十一组组件检查均退出0，`SessionDeviceAuthority`专项每版12项；PHP8.5同一控制器另完成本地Chromium虚拟认证器闭环。返回阶段在核验前就清空请求内授权状态，新增断言确认重复调用以及身份变化后再次调用均不报告成功。临时消费者与SQLite数据已清理。当次尚未重跑的两端私有MySQL组合已由下文准确CI组合补验，不能以旧MySQL记录替代。宿主真实HTTP保护、持久通知、恢复栅栏、实体设备、远端CI和生产仍未执行。

可选包归档补验已执行并通过：`tests/optional_archives.py`对PSR-3、PSR-15、OIDC和WebAuthn四包各生成Composer ZIP，逐项比对运行时源码字节、必需元数据／许可证以及WebAuthn数据库结构和迁移；ZIP不能含测试或其他开发文件。发现修复前WebAuthn归档含`tests/`，OIDC归档还含`phpstan.neon`与Python缓存；两个包新增归档排除后四包均退出0。OIDC精确锁定已审查的上游1.0.2，严格Composer验证仅对其关闭版本约束宽窄提示，并在脚本中核对固定版本，其他严格检查保留。WebAuthn又用`--archive`从刚生成的ZIP解包安装：PHP8.2十一组组件与PHP8.5十一组组件／本地Chromium闭环均退出0，`SessionDeviceAuthority`可由归档加载。CI定义已改为四版归档消费者，但远端未执行；OIDC归档消费者随后另行补验，见下段。公开仓库和发布也未验收。

OIDC归档消费者已执行并通过：`python3 tests/oidc_consumer.py --archive php72`和`--archive php83`各从当前可选包新生成Composer ZIP，解包后全新安装核心、OIDC及上游精确v1.0.2；两端锁定依赖审计和机器可读清单通过。两端均完成声明43、客户端导出24、凭据对象导出42、关联110、注销栅栏50、联合会话70、签名回调83项，以及FileStore／私有禁TCP MySQL／私有Unix socket Redis双进程各10项、两数据库会话各36项和本机HTTPS回调／注销86项，控制器均退出0。临时消费者和私有后端已清理；CI定义已切换为归档路径但远端未执行。第三方发行方、真实宿主、公开仓库安装及正式发布未验收。

WebAuthn准确CI组合本地补验已执行并通过：`tests/webauthn_consumer.py --archive --mysql --browser php82`与`php85`各从当前源码生成ZIP并解包全新安装，核对上游5.3.9锁定依赖、运行十一组组件检查（其中宿主会话授权12项）、由测试控制器自建禁TCP私有MySQL运行仓库27项，再用同一消费者自动加载文件完成本地Chromium注册／登录、错误路径与删除后Signal API同步。两端控制器均退出0，临时消费者、SQLite与MySQL测试实例由控制器清理；没有连接业务数据库。这是CI中定义的准确组合在本机的结果，不证明远端CI、实体设备、真实宿主HTTP审批／会话栅栏、第三方服务或发布通过。

## 近期索引接入后 PHP7.2 完整私有门禁（2026-10-20，本地）

已执行并通过：在具备 sodium、Redis、PDO SQLite／MySQL 等必需扩展的私有 PHP7.2.34 运行时上，开启八个适用的`SOSECURITY_REQUIRE_*`关口，执行`tests/mysql_check.py --matrix /tmp/sosecurity-sodium-runtime-akybbkwr/php72-sodium`，控制器退出0。日志`/tmp/sosecurity-matrix-php72-recent-current.log`共495行，以`PASS full isolated matrix`结束；没有`FAIL`、致命错误或异常回溯。新增`RecentEvents`在FileStore、Redis、MySQL的30项定向检查及各8进程容量争抢均在同一轮通过；Outbox SQLite 243项、私有MySQL 195项输入边界和16MiB BLOB／含NUL TEXT的8MiB进程拒绝也通过。私有Redis、账号并发、HTTP／TLS和演示检查运行至终态。只有PHP7.2不具备原生Fiber的3条预期`NOT RUN`及此构建不支持Argon2id的2条`NOT APPLICABLE`；无其他跳过。测试控制器创建的私有MySQL／Redis进程和目录已清理。本次结果只证明当前工作树PHP7.2本地整合；其余八版同源码整轮、真实宿主权限与日志、远端CI、独立审查和发布未执行。

## 当前源码 PHP7.2 完整私有门禁（2026-10-20，本地）

已执行并通过：具备 sodium／Redis／PDO SQLite／PDO MySQL 等必需扩展的私有 PHP7.2.34 运行时，在全部适用 `SOSECURITY_REQUIRE_*` 关口开启后执行 `tests/mysql_check.py --matrix /tmp/sosecurity-sodium-runtime-akybbkwr/php72-sodium`，控制器退出 0；日志 `/tmp/sosecurity-matrix-php72-complete-current.log` 共 490 行，以 `PASS full isolated matrix` 结束。当前 `MetricsSink` 有限补采、`Diagnostics`、告警入队／工作者和原 Outbox 双数据库 NUL／超限拒绝均在同轮运行；私有无TCP MySQL、Redis、账号并发、HTTP／TLS及演示检查通过。日志只有 PHP7.2 无原生 Fiber 的 3 条预期未执行，以及 Argon2id 不适用的 2 条说明；无 `FAIL`、异常回溯或其他跳过。测试控制器创建的私有 MySQL／Redis 实例及目录均已清理。

此前先用系统 `php72` 启动同一矩阵，发现缺少 `ext-sodium`，该不合格运行在出现必需加密项跳过后主动终止，退出 130，私有实例已清理；它不计为完整门禁结果。上述通过只证明当前工作树的 PHP7.2 本地整合，不替代其余八版、真实下游、外部 CI、独立审查、真实通知目标或发布验收。

## R4.6 已观察阈值告警入队（2026-10-20，本地）

已执行并通过：新增`Audit\AlertOutboxPublisher`复用`SqlOutbox`，PHP7.2—8.5九版各在SQLite运行`tests/audit-alert-outbox.php`并通过31项；PHP7.2.34和PHP8.5.9另在测试控制器自建、禁TCP的MySQL上各通过31项，控制器整体退出0并清理实例。覆盖无告警不入队、两个轮询者同窗同ID、发送回执后再轮询不重复、窗口切换新消息、未初始化队列拒绝、事务回滚后可重试及正文无主体。九版公开签名反射通过228类／接口，PHP7.2语法检查及PHP7.2目标静态分析通过。PHP7.2／8.5各通过449文件Composer归档和全新本地路径消费者，消费者实际调用新入队接口。消息只证明已观察告警持久入队；真实通知通道、目标幂等、轮询漏窗与长期指标未验证。新增运行时代码后的完整整版门禁未执行；下方PHP8.3整版结果属于新增前的源码快照。

## R6.5 反向代理与 WAF 指南本地核对（2026-10-20）

已执行并通过：核对中英文指南各自的本地 Markdown 链接，均为 1 条且目标 `idempotency-native.md` 存在；对照当前 `src/Http/ClientIp.php` 确认指南描述的默认 `REMOTE_ADDR`、仅可信上一跳才解析 `X-Forwarded-For`、最多 32 跳和 2048 字节上限与源码一致。外部官方链接的可达性、实际代理链、WAF 规则、源站隔离和生产行为未在本次验证。

## 当前工作树 PHP8.3 完整私有门禁（2026-10-20，本地）

已执行并通过：具备所需扩展的 PHP8.3.35 私有运行时执行 `env -u SOSECURITY_TEST_MYSQL_SOCKET -u SOSECURITY_TEST_REDIS_SOCKET python3 tests/mysql_check.py --matrix /tmp/sosecurity-sodium-runtime-akybbkwr/php83-sodium`，整体退出 0；日志 `/tmp/sosecurity-r46-fault-current-php83.log` 共 480 行，以 `PASS full isolated matrix` 结束，无 `NOT RUN`、`FAIL` 或异常回溯。SQLite Outbox 输入边界 243 项、16 MiB BLOB／含 NUL TEXT 在 8 MiB 内存限制下安全拒绝 986 项、正文硬上限 8 项；私有禁 TCP MySQL 输入边界 195 项及正文硬上限 8 项均通过。固定审计指标 FileStore／私有 Redis／私有 MySQL 各八进程 80 次计数与容量拒绝通过；Redis 5 项、MySQL 6 项异常状态低内存拒绝通过。HTTP／TLS（包括修复后的本地 TLS 测试代理）运行至终态，私有 MySQL 实例已关闭清理。PHP7.2／8.5 的整版记录见下文；其他版本同一快照整版、真实下游、远端 CI、独立审查及生产未在本轮执行。

## 当前工作树发行归档、全新消费者与公开签名（2026-10-20，本地）

已执行并通过：使用具备所需扩展的PHP7.2.34私有运行时和PHP8.5.9，分别执行`tests/archive.py`与`tests/install.py`，四项均退出0。每版Composer ZIP归档包含448文件，核对全部`src/*.php`及所需示例／指南／SQL，排除`vendor`、测试、开发工具、演示入口、可选集成验证项目和私有配置文件名；各新建临时Composer路径消费者实际安装包并运行固定审计指标、账号／Outbox／Webhook、上传隔离和ZIP只读等公开接口。两版`composer validate --strict --no-interaction`均退出0。PHP7.2—8.5九版各执行`bin/api-contract.php`并通过227类／接口签名反射。所有消费者及归档使用临时目录，数据库只用本地测试数据；这不是公开仓库安装、真实下游、远端CI、生产或正式发布验收，也不代替同一最终门禁快照的九版整版运行。

## R4.6 固定类别审计指标与告警判定（2026-10-20，本地）

当前故障专项接入后的PHP8.5.9完整门禁：`env -u SOSECURITY_TEST_MYSQL_SOCKET -u SOSECURITY_TEST_REDIS_SOCKET python3 tests/mysql_check.py --matrix php85`整体退出0，日志`/tmp/sosecurity-r46-fault-current-php85.log`共506行，末尾`PASS full isolated matrix: php85`，私有MySQL已关闭清理。指标FileStore／Redis／MySQL八进程80次及Redis5项、MySQL6项12MiB异常状态低内存拒绝均通过；SQLite Outbox输入243项、16MiB BLOB／含NUL TEXT拒绝986项、正文硬上限8项，私有MySQL输入195项及正文硬上限8项通过；原生Fiber和适用HTTP／TLS均执行，无`NOT RUN`。日志在本地TLS幂等代理处理被客户端主动放弃的响应时出现一次`ssl.SSLEOFError`回溯，不能描述为无错误日志；对应幂等TLS专项仍报告437项通过。随后仅把该预期断线加入测试代理的明确捕获，`python3 tests/idempotency_http.py php85 --tls`退出0、437项通过，`/tmp/sosecurity-r46-idempotency-tls-php85.log`无回溯。代理修复后的整版门禁未重跑；核心运行时代码未因此改变。真实宿主、远端CI、可选包整版及生产未执行。

后续真实后端故障专项已执行并通过：PHP7.2—8.5九版各运行`tests/audit_metrics_redis.py`与`tests/mysql_check.py --audit-metrics`，每版每个后端均先通过八进程80次计数、固定阈值及第81次容量拒绝，再由私有Redis／MySQL服务端生成12MiB异常状态。8MiB PHP进程的`MetricsSink::inspect()`和后续审计写入均抛出`StorageException`，下游日志回调保持只执行原有一次；Redis每版5项、MySQL每版6项故障断言通过，临时服务由控制器关闭清理。首轮以`Redis::close()`作为断线模拟的测试在PHP7.2未得到预期异常，已执行但失败；该预设环境已换成服务端异常状态并在九版通过，不能把首轮失败称为产品拒绝证据。本轮修改了常规门禁测试入口，下面的PHP7.2整版通过对应修改之前的源码和门禁快照；新增故障专项接入后的整版门禁未执行。

当前源码整版补验：`env -u SOSECURITY_TEST_MYSQL_SOCKET -u SOSECURITY_TEST_REDIS_SOCKET python3 tests/mysql_check.py --matrix /tmp/sosecurity-sodium-runtime-akybbkwr/php72-sodium`整体退出0，日志`/tmp/sosecurity-r46-current-php72.log`共480行，末尾为`PASS full isolated matrix`。PHP7.2.34运行时具备sodium、posix、Redis、PDO MySQL／SQLite；指标27项8MiB检查、FileStore／私有Redis／私有禁TCP MySQL各八进程80次及容量拒绝都通过。SQLite Outbox输入243项、16MiB BLOB／含NUL TEXT在8MiB下拒绝986项、正文硬上限8项；私有MySQL输入195项及正文硬上限8项通过。账号、Webhook、HTTP／TLS等完整门禁后续段亦运行至终态，私有MySQL实例已关闭清理。日志只有PHP7.2缺原生Fiber的三项`NOT RUN`及构建不支持Argon2id的明确不适用记录；不将它们计作执行通过。相同新源码的PHP7.3—8.5整版门禁、可选包整版、真实宿主／告警投递、远端CI及生产未在本轮执行。

补充已执行并通过：`python3 tests/audit_metrics_redis.py php72 php85`及`python3 tests/mysql_check.py --audit-metrics php72 php85`均退出0。每个版本在私有Unix socket Redis和私有禁用TCP MySQL上分别由8个真实进程共提交80次，独立进程读取到总数80、认证类告警，并确认第81次因容量耗尽拒绝；私有实例由控制器启动及清理。FileStore八进程专项在调整后也以PHP7.2／8.5重跑退出0；测试统一使用固定的未来测试时钟，避免跨UTC日界导致窗口切换。两后端专项已接入`bin/check.sh`，但接入后的完整门禁未执行；PHP7.3—8.4真实后端专项、故障注入及真实宿主日志／告警投递未执行。本补充不改变下文原有证据范围。

已执行并通过：新增`Audit\MetricsSink`的PHP7.2—8.5九版`tests/audit-metrics.php`各27项8MiB定向断言、`tests/audit_metrics_process.py`每版八个真实进程共80次共享FileStore计数与固定认证类别告警判定，以及九版227类／接口反射契约；测试目录由控制器创建并清理。定向场景覆盖四类固定标签、未知事件拒绝、直接伪造记录拒绝、容量与配置变更拒绝、窗口切换、下游日志故障后计数保留、存储不可用／损坏拒绝、对象导出遮盖与序列化拒绝。PHP7.2／8.5当前源码各通过448文件Composer归档及全新本地路径消费者，并在复制后的包中实际调用`MetricsSink`；PHP8.2上的PHP7.2目标PHPStan无错误。计数在下游接收器前提交，只表示审计尝试；真实日志持久化、告警投递／去重、长期指标、远端CI、同一新源码整版门禁及生产未执行。

## 当前工作树发行归档与新消费者（2026-10-20，本地）

已执行并通过：使用加载`sodium`的本地PHP7.2.34及系统PHP8.5.9，分别执行`python3 tests/archive.py <runtime> /usr/local/bin/composer`和`python3 tests/install.py <runtime> /usr/local/bin/composer`，四个进程均退出0。两端Composer归档各447文件，源码清单齐全，排除`vendor`、`tests`、`bin`、`demo`、可选集成验证项目与私有配置文件名；两个独立临时Composer本地路径消费者均完成安装并运行公开API及本地SQLite使用路径，覆盖账号、Outbox、Webhook、上传隔离及ZIP只读检查。测试只用临时目录与本地测试数据；公开仓库安装、远端CI、真实下游、生产和正式发布未执行。此证据不替代同一当前源码快照九版本整版门禁。

## R6.2 OIDC测试后端目标隔离（2026-10-20，本地）

已执行并通过：向`python3 tests/oidc_consumer.py php72`注入伪造的`SOSECURITY_TEST_MYSQL_SOCKET`与`SOSECURITY_TEST_OIDC_REDIS_SOCKET`，整套门禁退出0，日志准确显示私有FileStore、私有无TCP MySQL、私有Unix socket Redis各10项双进程竞态、两种数据库各36项联合会话及本机HTTPS 86项。分别向`tests/mysql_check.py --oidc-process php72`注入伪造Redis socket、向`integrations/oidc/tests/redis_process.py ... php72`注入伪造MySQL socket，两个控制器各退出0并准确运行各自后端的10项竞态／36项会话。双目标直接传入`process_race.py`时按预期非零退出，明确报告后端冲突。所有真实连接仅指向控制器拥有的本地私有实例，临时实例退出后清理；未触及宿主数据库。远端CI与真实发行方未执行。

## 当前源码 PHP8.4 完整本地门禁（2026-10-20）

已执行并通过：使用已核验加载`sodium`、`posix`、`pcntl`、`redis`、`pdo_mysql`与`pdo_sqlite`的本地PHP8.4.23运行时执行`bash bin/check.sh /tmp/sosecurity-r43-full-runtimes-rjm6oal8/php84`，整体退出0。日志507行，无`NOT RUN`、失败或错误标记。Outbox SQLite输入边界243项、16 MiB BLOB／含NUL TEXT在8 MiB内存限制下拒绝986项、正文硬上限8项；私有无TCP MySQL输入边界195项及正文硬上限8项均通过。管理型MFA 54组、私有Redis、MySQL账号／Outbox并发、原生HTTP／TLS均走到并通过；私有MySQL目录已清理。只使用本地测试数据库，不连接宿主数据库。此结果是当前核心源码的本地整版门禁，不包含可选OIDC／WebAuthn包的整版接入、远端CI、真实下游、生产或独立安全审查。

## 当前源码 PHP8.3 完整本地门禁（2026-10-20）

已执行并通过：使用已核验加载`sodium`、`posix`、`pcntl`、`redis`、`pdo_mysql`与`pdo_sqlite`的本地PHP8.3.35运行时执行`bash bin/check.sh /tmp/sosecurity-sodium-runtime-akybbkwr/php83-sodium`，整体退出0。日志507行，无`NOT RUN`、失败或错误标记。Outbox SQLite输入边界243项、16 MiB BLOB／含NUL TEXT在8 MiB内存限制下拒绝986项、正文硬上限8项；私有无TCP MySQL输入边界195项及正文硬上限8项均通过。管理型MFA 54组、私有Redis、MySQL账号／Outbox并发、原生HTTP／TLS均走到并通过。测试控制器创建的私有MySQL目录已清理；没有连接宿主数据库。此结果是当前核心源码的本地整版门禁，不包含可选OIDC／WebAuthn包的整版接入、远端CI、真实下游、生产或独立安全审查。PHP8.4的后续整版结果见上节。

## R6.2 OIDC独立消费者门禁（2026-10-20，本地）

已执行并通过：`python3 tests/oidc_consumer.py php72`和`python3 tests/oidc_consumer.py php83`均退出0，临时Composer消费者锁定`jumbojett/openid-connect-php` v1.0.2，锁定依赖公告检查未发现公告。两版各通过声明43项、客户端导出24项、凭据对象导出42项、关联110项、注销栅栏50项、联合会话70项、签名回调83项、私有FileStore双进程10项、私有无TCP MySQL双进程10项及会话36项、私有Unix socket Redis双进程10项及会话36项、本机HTTPS回调／注销86项；脚本临时目录和私有服务在退出时清理。此门禁已写入PHP7.2—8.3 CI定义，但PHP7.3—8.2新入口及远端CI尚未执行；PHP8.4／8.5不在可选包声明范围，第三方发行方、真实宿主和生产未执行。

## R6.2 OIDC客户端凭据导出修复（2026-10-20，本地）

已执行并通过：`StrictClient`在构造后将真实客户端密钥保存在不参与普通对象导出的闭包中；授权码换令牌期间才临时装入上游v1.0.2对象，并在`finally`清除。`authenticateSubject()`在成功、错误状态、网络／签名／声明失败后均清除上游ID Token、访问／刷新令牌、响应与已验证声明；直接调用继承的认证、令牌setter、刷新、旧注销、其他授权方式、动态注册及外部重定向入口拒绝。七个受支持PHP版本各通过`client-debug.php`24项、`claims.php`43项、`proof-export.php`42项、关联110项、注销栅栏50项、联合会话70项及签名回调83项。PHP7.2／8.3本机HTTPS各86项覆盖真实换令牌与拒绝路径，并检查当前客户端对象的`var_export()`不含测试密钥或访问令牌；PHP8.2的PHP7.2目标静态分析无错误。可选包`composer.json`验证退出0，但因安全上精确锁定上游v1.0.2，Composer给出不建议精确约束的一般警告。

本轮没有第三方发行方、真实宿主、生产或PHP8.4／8.5验收。修复依赖上游v1.0.2内部字段；升级该依赖必须重新审查清理代码与协议闭环。本轮已在当前客户端源码上重跑：`tests/mysql_check.py --oidc-process`的私有无TCP MySQL七版各10项双进程竞态和36项联合会话全部通过；`integrations/oidc/tests/redis_process.py`的私有Unix socket Redis六版各10项双进程竞态和36项联合会话全部通过。控制器退出0并清理实例；系统PHP8.2缺`ext-redis`，该版Redis专项未执行。

## R6.2 已验证凭据对象导出边界（2026-10-20，本地）

已执行并通过：PHP7.2／7.3／7.4／8.0／8.1／8.2／8.3七版各通过`integrations/oidc/tests/proof-export.php`42项、关联110项、注销栅栏50项、联合会话70项及本地签名回调83项。对象导出专项确认`var_export()`、`print_r()`、JSON和嵌套导出均不含外部主体／提供方会话ID／注销令牌ID，公开getter保持；序列化、伪造反序列化和动态改写拒绝。七版另各通过`client-debug.php`5项与原`claims.php`43项，确认`StrictClient`的`print_r()`／`var_dump()`遮盖测试密钥、序列化拒绝；PHP7.2／8.3变更后本机HTTPS闭环各86项通过。PHP8.2执行PHP7.2目标的OIDC PHPStan无错误。对象格式变更后已执行并通过：禁用TCP的私有MySQL在七版各10项双进程竞态与36项联合会话；私有Unix socket Redis在六版各10项双进程竞态与36项联合会话；PHP7.2／8.3私有FileStore各10项双进程竞态及本机HTTPS回调／注销闭环各86项。测试控制器退出0并清理临时实例。系统PHP8.2缺`ext-redis`，该版Redis专项未执行。

修复前曾准确复现：`StrictClient`继承的上游v1.0.2客户端对象经`var_export()`暴露测试客户端密钥；探针只输出是否暴露，不输出密钥。后续已按本文件当前R6.2客户端凭据导出修复章节清除普通对象导出路径。官方发布列表截至本轮检查仍只有v1.0.2为最新稳定版，[上游版本请求](https://github.com/jumbojett/OpenID-Connect-PHP/issues/505)仍开放；因此没有把开发提交伪装成稳定依赖，PHP8.4／8.5仍不在可选包声明范围。这一段是修复前发现及依赖版本审查记录，不代表当前源码仍存在同一普通导出泄露。

## R6.2 提供方失联恢复解绑（2026-10-20，本地）

已执行并通过：独立Composer消费者安装的稳定OIDC依赖下，PHP7.2／7.3／7.4／8.0／8.1／8.2／8.3七版各执行`integrations/oidc/tests/links.php` 110项与`sessions.php` MemoryStore／FileStore 70项。覆盖请求保护拒绝、旧本地凭据和错误账号拒绝、独立审批严格返回、审批期间账号代际变化及同秒解绑重绑拒绝、新关联随机代际、旧版关联恢复解绑，以及解绑后联合会话失效而本地密码会话继续有效。`php82 tools/vendor/bin/phpstan analyse -c integrations/oidc/phpstan.neon --autoload-file=/tmp/sosecurity-oidc-consumer-vs4xmsgd/vendor/autoload.php --no-progress`退出0，无错误。

已执行并通过：`tests/mysql_check.py --oidc-process`在控制器自建、禁用TCP的私有MySQL实例上使用上述七个PHP版本各完成10项双进程竞态和36项联合会话；`integrations/oidc/tests/redis_process.py`在自建Unix socket私有Redis上使用PHP7.2／7.3／7.4／8.0／8.1／8.3六版各完成10项双进程竞态和36项联合会话；PHP7.2／8.3本机HTTPS回调／注销闭环各86项。测试实例退出后已由控制器清理。系统PHP8.2缺`ext-redis`，该版Redis专项未执行。真实宿主独立审批／审计／通知、第三方发行方、浏览器及生产验证未执行；此SDK入口不代表R6.2完整验收。

## R6.3 可选可信设备风险决策接入（2026-10-20，本地）

已执行并通过：原生认证示例对`step_up`／`blocked`结果新增不同处理，PHP7.2和8.5分别执行`python3 tests/device_risk_http.py <runtime>`，各40项本地HTTP断言且进程退出0。服务端固定风险快照从环境提供；测试覆盖POST／CSRF入口、错误码、无会话、`step_up`清Cookie并撤销原授权、完整密码登录后主动签发新授权、风险解除后旧凭据仍被拒绝、`blocked`清Cookie及撤销已关联会话。改动后的原`tests/remember_http.py`两版各182项通过，示例PHP语法与Python脚本语法检查通过；改动后PHP7.2／8.5发行归档各447文件清单通过。服务端测试数据为私有临时目录中的账号／会话／FileStore，无远端数据库或生产服务；静态环境风险快照不证明真实宿主信号来源或浏览器体验。

已执行并通过：PHP7.2—8.5九个本地运行时逐一执行`bin/api-contract.php`、`tests/device-risk.php`和既有`tests/remember.php`，各版分别通过226类／接口公开签名、72项风险专项及499项原记住登录专项，进程均退出0。专项涵盖固定优先级、缺失／非布尔信号拒绝、无效令牌不触发风险回调、要求重新认证时原子撤销设备授权及关联会话、不发放新会话；风险解除后旧令牌仍被拒绝、泄露判定撤销设备及关联会话、无效回调结果拒绝恢复、工厂缺失服务拒绝。另在PHP7.2／8.5完成628文件语法检查、447文件发行归档清单验证和各182项原生记住登录HTTP回归。测试只用本地MemoryStore及私有临时FileStore；尚未执行R6.3变更后的当前源码完整九版门禁、真实宿主信号来源、浏览器误判申诉和生产验证。前述其他整版通过记录对应本次风险接入前的源码快照。R6.3仍在实施中。

## 当前源码 ZIP 专项与 PHP8.3 中断门禁（2026-10-20）

已执行并通过：在当前工作树以 PHP7.2、7.3、7.4、8.0、8.1、8.2、8.3、8.4、8.5 逐一执行 `python3 tests/archive_inspection.py <runtime>`，九个进程均退出 0。装有 `ext-zip` 的 PHP7.2、7.4、8.1、8.2、8.4、8.5 各通过 47 项 ZIP 内容检查；未装扩展的 PHP7.3、8.0、8.3 各通过 5 项缺依赖安全拒绝。使用脚本创建并清理的本地临时测试文件；此结果仅覆盖 ZIP 专项，不代表九版本当前源码完整门禁或实际提取流程。

已执行但中断：额外启动的当前源码 PHP8.3.35 `bash bin/check.sh /tmp/sosecurity-sodium-runtime-akybbkwr/php83-sodium` 在本地 HTTP／TLS 阶段由操作员主动停止，整体退出 130，不能记为整版通过。停止前日志确认 SQLite Outbox 输入边界 243 项、16 MiB BLOB／含 NUL TEXT 在 8 MiB 内存限制下拒绝 986 项、正文硬上限 8 项通过；该次运行不提供 MySQL Outbox 或后续阶段的完成证据。历史 PHP8.3 整版记录对应更早源码快照，见下文。仅使用本地测试数据库；当前源码 PHP8.3—8.4 完整门禁、下游、远端 CI、正式发行及生产仍未验证。

## 当前源码 PHP8.2 完整本地门禁与运行时补全（2026-10-20）

已执行但失败：系统 `php82` 的完整 `bin/check.sh` 在 `tests/account-factor/operation-resolution-processes.php` 退出 1；原始错误指出缺少 POSIX 信号能力。该运行时有 `pcntl`、sodium 和 SQLite，但未加载 `posix`，因此本次中断是测试运行时能力不足，不能记为整版通过。

已执行并通过：现有私有 `php82-isolated` 运行时确认加载 `posix`、`pcntl` 和 sodium；失败项单独通过 31 项。随后在下载与外连对象导出修复后的当前核心工作树执行 `bash bin/check.sh /tmp/sosecurity-sodium-runtime-akybbkwr/php82-isolated`，整体退出 0。覆盖 PHP8.2.32 源码语法、224 类公开 API、对象导出专项、SQLite、私有无 TCP MySQL、Redis、本地 HTTP／TLS、原生 Fiber、POSIX 进程测试与适用的账号加密流程。Outbox 在 SQLite 通过输入边界 243 项、16 MiB BLOB／含 NUL TEXT 在 8 MiB PHP 内存限制下拒绝 986 项、正文硬上限 8 项；MySQL 通过输入边界 195 项及正文硬上限 8 项。重跑日志未见 `NOT RUN`、`FAIL`、PHP 致命错误或 Python traceback；私有 MySQL 进程及测试目录已清理。仅使用本地测试数据库；PHP8.3—8.4 当前源码完整门禁、真实下游、远端 CI、正式发行及生产未验证。

## 当前源码 PHP8.1 完整本地门禁（2026-10-20）

已执行并通过：下载与外连对象导出修复后的当前核心工作树执行 `bash bin/check.sh php81`，整体退出 0。覆盖 PHP8.1.34 源码语法、224 类公开 API、对象导出专项、SQLite、私有无 TCP MySQL、Redis、本地 HTTP／TLS、原生 Fiber 与适用的账号加密流程。Outbox 在 SQLite 通过输入边界 243 项、16 MiB BLOB／含 NUL TEXT 在 8 MiB PHP 内存限制下拒绝 986 项、正文硬上限 8 项；MySQL 通过输入边界 195 项及正文硬上限 8 项。日志未见 `NOT RUN`、`FAIL`、PHP 致命错误或 Python traceback；私有 MySQL 进程及测试目录已清理。仅使用本地测试数据库；PHP8.3—8.4 当前源码完整门禁、真实下游、远端 CI、正式发行及生产未验证。

## 当前源码 PHP8.0 完整本地门禁（2026-10-20）

已执行并通过：下载与外连对象导出修复后的当前核心工作树，使用带 sodium 的私有 PHP8.0.30 运行时执行 `bash bin/check.sh /tmp/sosecurity-sodium-runtime-akybbkwr/php80-sodium`，整体退出 0。覆盖源码语法、224 类公开 API、对象导出专项、SQLite、私有无 TCP MySQL、Redis、本地 HTTP／TLS 与适用的账号加密流程。Outbox 在 SQLite 通过输入边界 243 项、16 MiB BLOB／含 NUL TEXT 在 8 MiB PHP 内存限制下拒绝 986 项、正文硬上限 8 项；MySQL 通过输入边界 195 项及正文硬上限 8 项。PHP8.0 原生 Fiber 三项按平台能力标记 `NOT RUN`；日志未见 `FAIL`、PHP 致命错误或 Python traceback。私有 MySQL 进程及测试目录已清理。仅使用本地测试数据库；PHP8.3—8.4 当前源码完整门禁、真实下游、远端 CI、正式发行及生产未验证。

## 当前源码 PHP7.4 完整本地门禁（2026-10-20）

已执行并通过：下载与外连对象导出修复后的当前核心工作树，使用带 sodium 的私有 PHP7.4.33 运行时执行 `bash bin/check.sh /tmp/sosecurity-sodium-runtime-akybbkwr/php74-sodium`，整体退出 0。覆盖源码语法、224 类公开 API、对象导出专项、SQLite、私有无 TCP MySQL、Redis、本地 HTTP／TLS 与适用的账号加密流程。Outbox 在 SQLite 通过输入边界 243 项、16 MiB BLOB／含 NUL TEXT 在 8 MiB PHP 内存限制下拒绝 986 项、正文硬上限 8 项；MySQL 通过输入边界 195 项及正文硬上限 8 项。PHP7.4 原生 Fiber 三项按平台能力标记 `NOT RUN`；日志未见 `FAIL`、PHP 致命错误或 Python traceback。私有 MySQL 进程及测试目录已清理。仅使用本地测试数据库；PHP8.3—8.4 当前源码完整门禁、真实下游、远端 CI、正式发行及生产未验证。

## 当前源码 PHP7.3 完整本地门禁（2026-10-20）

已执行并通过：在下载与外连对象导出修复之后，带 sodium 的私有 PHP7.3.33 测试运行时执行 `bash bin/check.sh /tmp/sosecurity-sodium-runtime-akybbkwr/php73-sodium`，整体退出 0。覆盖源码语法、224 类公开 API、对象导出专项、SQLite、私有无 TCP MySQL、Redis、本地 HTTP／TLS 与适用的账号加密流程。Outbox 在 SQLite 通过输入边界 243 项、16 MiB BLOB／含 NUL TEXT 在 8 MiB PHP 内存限制下拒绝 986 项、正文硬上限 8 项；MySQL 通过输入边界 195 项及正文硬上限 8 项。PHP7.3 原生 Fiber 三项按平台能力标记 `NOT RUN`；日志未见 `FAIL`、PHP 致命错误或 Python traceback。私有 MySQL 进程及测试目录已清理。仅使用本地测试数据库；PHP8.3—8.4 当前源码完整门禁、真实下游、远端 CI、正式发行及生产未验证。

## 当前源码 PHP8.5 完整本地门禁（2026-10-20）

已执行并通过：在下载与外连对象导出修复及公开 API 候选更新之后，运行 `bash bin/check.sh php85` 整体退出 0。覆盖 PHP8.5.9 源码语法、224 类公开 API、对象导出专项、SQLite、私有无 TCP MySQL、Redis、本地 HTTP／TLS、原生 Fiber 与适用的账号加密流程。Outbox 在 SQLite 通过输入边界 243 项、16 MiB BLOB／含 NUL TEXT 在 8 MiB PHP 内存限制下拒绝 986 项、正文硬上限 8 项；MySQL 通过输入边界 195 项及正文硬上限 8 项。日志未见 `NOT RUN`、`FAIL`、PHP 致命错误或 Python traceback；私有 MySQL 实例及目录已清理。只使用本地测试数据库；PHP8.3—8.4 当前源码完整门禁、真实下游、远端 CI、正式发行及生产未验证。

## 当前源码 PHP7.2 完整本地门禁（2026-10-20）

已执行并通过：在下载与外连对象导出修复及公开 API 候选更新之后，带 sodium 的私有 PHP7.2.34 测试运行时执行 `bash bin/check.sh /tmp/sosecurity-sodium-runtime-akybbkwr/php72-sodium`，整体退出 0。覆盖源码语法、224 类公开 API、对象导出专项、SQLite、私有无 TCP MySQL、Redis、本地 HTTP／TLS 与适用的账号加密流程。Outbox 在 SQLite 通过输入边界 243 项、16 MiB BLOB／含 NUL TEXT 在 8 MiB PHP 内存限制下拒绝 986 项、正文硬上限 8 项；MySQL 通过输入边界 195 项及正文硬上限 8 项。PHP7.2 原生 Fiber 三项按平台能力标记 `NOT RUN`；日志未见 `FAIL`、PHP 致命错误或 Python traceback。私有 MySQL 实例及目录已清理。仅使用本地测试数据库；PHP8.3—8.4 当前源码完整门禁、真实下游、远端 CI、正式发行及生产未验证。

## R1.2 下载与外连对象导出防护（2026-10-20，本地）

修复前使用合成值确认 `Download\Request` 的条件请求头、`Download\LinkAccess` 的签名 URL／绑定值，以及 `Http\Outbound\Response` 的响应头／正文可由 `var_export()` 读取。修复后这些值通过闭包保留，公开读取接口继续返回原值；对象调试信息遮盖敏感值，序列化及旧对象反序列化明确拒绝。PHP7.2—8.5 九版各在 8MiB 内存限制下通过 54 项导出专项；PHP7.2／8.5 的外连各 80 项、下载分别 277／280 项通过，两端 224 类公开 API 签名及三个改动类的 PHP7.2 目标静态分析通过。全仓静态分析已执行但失败：提高内存限制后报告其他模块 72 个问题；首次 128MiB 运行因内存不足中断。仅使用本地测试数据；本次改动后的 PHP7.2／8.5 完整核心门禁见上文，PHP8.3—8.4 当前源码完整门禁、真实宿主与生产未执行。下文标明修复前的两端旧门禁仅保留历史证据。

## 当前PHP8.5核心完整本地门禁（2026-10-20）

已执行并通过：本次下载与外连对象修复前的工作树运行`bash bin/check.sh php85`退出0。覆盖PHP8.5.9上的SQLite、由脚本创建的私有无TCP MySQL、私有Redis、HTTP／TLS及原生Fiber测试；包括Outbox SQLite输入边界243项、16MiB BLOB／含NUL TEXT在8MiB内存限制下拒绝986项，MySQL输入边界195项及正文硬上限8项。日志没有`NOT RUN`、`FAIL`或PHP致命错误标记，私有MySQL实例与目录已清理。与前一条PHP7.2带sodium门禁合起来，仅证明当时固定核心代码在两个端点版本的本地整版结果；PHP7.3—8.4七个中间版本、真实下游、远端CI、生产和正式发行未执行。

## 当前PHP7.2核心门禁与缺sodium测试入口（2026-10-20，本地）

已执行并通过：本次下载与外连对象修复前的核心代码使用已验证可加载sodium的私有PHP7.2测试运行时，`bash bin/check.sh /tmp/sosecurity-sodium-runtime-akybbkwr/php72-sodium`退出0；适用的SQLite、私有无TCP MySQL、Redis、HTTP／TLS及加密账号流程均由同一门禁执行，私有MySQL实例已停止。PHP7.2不支持原生Fiber，其三个上下文专项按预期未执行；Argon2id在该构建不可用，拒绝路径已验证。日志曾记录测试TLS连接关闭时的`SSLEOFError`服务端堆栈，但测试进程及整版门禁均退出0，不把这条堆栈当作独立验收。

已执行但失败：系统`php72`缺少`ext-sodium`时，同一门禁在`tests/credential_http.py`创建加密测试预设环境处因`DependencyException`退出1；此前通过的SQLite、Redis、MySQL和部分HTTP测试不能替代整版通过。随后修复该测试入口：缺扩展的定向执行输出`NOT RUN`并退出0，设置`SOSECURITY_REQUIRE_CRYPTO=1`则按预期退出1；带sodium的定向HTTP专项592项通过。测试入口修复发生在上述整版门禁后，未重新执行整版门禁；其余八版当前源码完整门禁及生产验收未执行。

## R6.1 WebAuthn SQLite元数据限量读取（2026-10-20，本地）

已执行并复现：本地SQLite账号`generation`列被写入16MiB含NUL TEXT时，修复前PHP8.2在8MiB内存限制下调用`generation()`尝试分配16777248字节并致命退出。修复后SQLite SQL投影只返回整数类型的代际、设备数量和修订号，以及恰好64字节的文本凭据索引；异常值返回空值并拒绝，不把大字段传入PHP。PHP8.2／8.5各34项SQLite仓库检查通过，包括四类异常元数据拒绝；私有无TCP MySQL两版各27项、两版Chromium虚拟认证器注册／登录与拒绝路径通过，PHP8.2目标PHPStan level 5无错误。仅使用本地测试数据库，实体安全密钥及生产数据库未验收。

## R6.1 WebAuthn SQLite凭据字段限量修复（2026-10-20，本地）

已执行并复现：在本地SQLite `record_json` BLOB列写入16MiB含NUL TEXT，原`length(record_json)`返回0，PHP8.2以8MiB限制调用`find()`时尝试分配16777248字节并致命退出。修复后以`length(CAST(record_json AS BLOB))`取得真实字节长度，在SQL中返回空正文；PHP8.2／8.5各30项SQLite仓库检查通过，覆盖`find()`与`forUser()`对该超限值的拒绝和正常现存TEXT凭据读取。私有无TCP MySQL两版各27项通过，测试实例已清理；两版Chromium虚拟认证器注册／登录及拒绝路径通过，PHP8.2目标PHPStan level 5无错误。仅使用本地测试数据库，未执行生产数据库或实体安全密钥验收。

## R6.1 WebAuthn浏览器注册与登录（2026-10-20，本地）

已执行并通过：修复注册选项缺少算法列表后，PHP8.2／8.5各通过14项基础检查，并在临时SQLite、本地双HTTPS Origin及Chromium虚拟认证器上完成真实浏览器`navigator.credentials.create()`／`get()`与服务端持久化验签。两版均拒绝注册／登录挑战重放、旧断言响应提交到新挑战、篡改签名及错误Origin，并在拒绝后成功完成新登录。PHP8.2目标PHPStan level 5静态分析退出0。浏览器测试使用临时自签名证书及测试浏览器忽略证书错误，只验证本地协议流程；实体安全密钥、真实宿主审批／会话栅栏／通知、生产TLS和生产数据库未执行。核心九版当前整仓门禁未重跑。

## R6.1 WebAuthn账号恢复代际（2026-10-20，本地）

已执行并通过：可选包新建SQLite／MySQL表加入账号`generation`，注册必须提供预期代际并在事务内比较；`PersistedCeremonies`将该代际绑定到注册与登录挑战。PHP8.2／8.5的本地SQLite仓库各27项，私有无TCP MySQL仓库各27项，覆盖恢复时撤销32个设备、空账号代际推进、旧代际注册拒绝与新代际重绑。两版各7项恢复边界检查覆盖拒绝、全部撤销、旧注册／登录挑战拒绝、新挑战可用及完成阶段未知结果；本地SQLite旧表一次性代际迁移各通过。两版各五轮双进程旧注册／恢复竞态均未让旧设备在恢复后存活。私有MySQL实例与目录已清理。测试的`RecoveryAuthority`是合成对象，只验证接口调用顺序；真实宿主强审批、会话栅栏、通知、安全密钥、浏览器、生产数据库和当前核心九版完整门禁均未执行。

## R6.1 WebAuthn受权设备删除（2026-10-20，本地）

已执行并通过：PHP8.2／8.5各7项`DeviceManager`输入边界／拒绝／删除／末设备保护／未知结果检查，使用合成宿主授权回调和本地SQLite；两版各20项仓库检查包含新增`revokeKeepingOne()`。SQLite双进程分别删除两个设备的首轮测试出现子进程`database is locked`，原测试还误把子进程致命错误当作普通失败；修复为读设备数量前先取得SQLite写锁，并将异常状态视为测试失败。修复后两版各五轮双进程复验均恰好删除一个、保留一个设备。新增剩余凭据Signal API JSON的所有权与结构检查；真实浏览器调用未执行。授权回调仍须由宿主实现近期认证、单次请求证明及通知，不能把合成回调当作真实安全验收；恢复、生产环境和当前核心九版整仓门禁仍未执行。

## R6.1 WebAuthn凭据仓库（2026-10-20，本地）

已执行并通过：`SqlCredentialRepository`在PHP8.2／8.5的8MiB限制下，分别以本地内存SQLite及由`tests/mysql_check.py --webauthn`新建的私有无TCP MySQL运行18项检查。覆盖含NUL凭据ID、重复ID跨账号拒绝、站点隔离、计数器按修订号更新及旧快照拒绝、撤销、每账号32设备容量，以及数据库直接注入16MiB异常记录后`find()`／`forUser()`均不读取正文。`PersistedCeremonies`在两版SQLite各通过6项存量设备选项及未知凭据／超限响应拒绝；成功的真实签名验证未测试。第一轮双运行时MySQL测试在第二运行时因共用临时库重复建表失败；测试运行框架在每版前重置该私有库的两张测试表，最终源码两版重跑均通过，私有实例退出清理。可选包PHP8.2目标PHPStan level 5静态分析退出0、Composer清单和语法检查通过。未连接业务数据库或生产服务；设备授权删除、恢复、真实硬件和浏览器、当前核心源码九版完整门禁均未执行。

## R6.1 WebAuthn一次性挑战（2026-10-20，本地）

已执行并通过：可选包在PHP8.2独立Composer消费者实际解析并安装`web-auth/webauthn-lib` 5.3.9。PHP8.2／8.5各通过原11项构造／输入检查、新17项账号／会话／用途绑定、过期、重放及失败后消费检查；两版各在私有临时目录的四个进程用同一`FileStore`竞争挑战，恰有一名成功消费者，目录已清理。可选包Composer清单严格校验通过。只使用合成账号与本地文件存储，未执行真实安全密钥、浏览器、数据库凭据仓库或生产环境；核心当前源码九版整仓门禁未重新执行。

## R1.2 链接与请求／响应对象导出防护（2026-10-20，本地）

已执行并复现：PHP7.2上合成敏感值可由`var_export()`读出`Link\IssuedLink`的完整凭据URL、`Webhook\Request`的正文与签名头，以及`Idempotency\Request`／`Response`的业务字节。修复后四种对象用闭包保存值并拒绝旧对象反序列化，公开getter保持原字节。PHP7.2—8.5九版各33项8MiB专项与224类公开API签名通过；PHP7.2／8.5原签名链接各663项、Webhook验签各239项、SQLite幂等各135项通过，PHP7.2目标静态分析无错误。PHP7.2／8.5还通过SQLite幂等安全各190项、Webhook收件箱各201项、处理流程各287项，全新Composer消费者各自退出0，发行归档各445文件。测试使用合成数据与本地SQLite，未连接真实业务数据库、外部Webhook或生产服务；当前源码九版整仓门禁未完成。

## R1.2 配置对象导出风险核对（2026-10-20，本地）

已核对`Config::statelessCsrf()`与`Security::signedCsrf()`：`stateless_csrf.keys`是用于查询宿主`services`数组的服务名称，实际`HmacKeys`密钥不保存在`Config`。曾用合成字符串验证普通私有配置属性可被`var_export()`读取，但该测试不能证明真实密钥泄露。为避免无依据地破坏现有配置对象的序列化兼容性，已撤回针对整个`Config`的闭包封装与拒绝反序列化改动；当前`Config.php`字节摘要与本阶段修改前一致。使用方仍不应把敏感配置对象转储写入公开日志。

## R1.2 认证敏感对象导出防护（2026-10-20，本地）

已执行并复现：PHP7.2上`Auth\PasswordRecord`的合成密码哈希及`Auth\LoginResult`的合成MFA挑战值可由`var_export()`读出。修复后两个对象用闭包保存对应敏感值，保留原公开getter与密码身份版本计算，并拒绝旧对象反序列化。PHP7.2—8.5九版各18项8MiB专项与224类公开API签名通过；PHP7.2／8.5原认证流程各199项通过，PHP7.2目标静态分析无错误。未连接业务数据库或生产身份源，当前源码九版整仓门禁未完成。

## R1.2 Webhook验签密钥对象导出防护（2026-10-20，本地）

已执行并复现：PHP7.2上合成`Webhook\KeySet`原始密钥可由`var_export()`读出。修复后闭包保存原始密钥，拒绝旧序列化对象与旧式普通字符串属性；PHP7.2—8.5九版各10项8MiB专项断言及224类公开API签名通过。PHP7.2／8.5原Webhook协议各239项通过，PHP7.2目标静态分析无错误。PHP7.2／8.5的本地SQLite收件箱各201项及处理流程各287项亦通过。未调用真实Webhook提供器、业务数据库或生产服务，完整九版整仓门禁未完成。

## Outbox字段限量读取与超限拒绝收口（2026-10-20，本地）

已执行并通过：当前源码在PHP7.2与8.5的SQLite各运行`outbox-input-bounds.php`、`outbox-body-budget.php`和`outbox-hard-limit.php`；前两项使用8MiB PHP内存限制，覆盖完整字节范围、合法NUL正文、16MiB BLOB及NUL前缀TEXT的安全拒绝，超限输入在数据库写入前拒绝，异常读取不改变Outbox状态。私有无TCP MySQL控制器在PHP7.2与8.5各输出9项预期通过标记，其中输入边界195项、正文硬上限8项、索引历史6项；还覆盖核心、安全、恢复与并发。控制器进程结束且私有MySQL实例与目录已清理；没有连接业务数据库。源码269项、测试与脚本380项冻结摘要复核一致。

密钥与Bearer修复后的九版整仓顺序门禁为收口本项而主动中断，退出130；该轮没有整版通过标记，私有MySQL已清理。此前修复前源码的PHP7.2／7.3／7.4整版标记不属于当前源码。当前Outbox本地定向验证不代表九版整仓门禁、下游、生产或R1—R6全部完成。

## 密钥与Bearer导出修复后的全新Composer消费者（2026-10-20，本地）

已执行并通过：`python3 tests/install.py /tmp/sosecurity-sodium-runtime-akybbkwr/php72-sodium`及`python3 tests/install.py php85`各退出0。两份隔离临时消费者从当前工作树的Composer path仓库复制安装核心包，实际运行认证／撤销、记住登录、租约、操作授权、API凭据、Webhook与Outbox本地SQLite组合、账号生命周期、上传隔离和ZIP检查等导入／基本流程，并在完成后删除临时目录；没有连接业务数据库或第三方服务。仅证明PHP7.2和8.5的当前候选安装与相应测试入口，不代表其余七版消费者、公开仓库安装、下游或生产验收。当前源码完整九版门禁已中断退出130，尚无整版通过标记。

## R1.2 Bearer对象导出防护（2026-10-20，本地）

源码审查确认九种对象曾将完整短期令牌作为普通私有字符串属性保存，`__debugInfo()`和`__sleep()`无法阻止`var_export`读取属性；其中`Api\Credential`此前也没有拒绝`serialize()`。当前九类对象改以闭包保存令牌、保留公开`token()`字节结果，并拒绝旧对象反序列化。已执行并通过：PHP7.2—8.5九版各62项8MiB定向断言，覆盖会话／记住登录／API／租约／操作／Webhook及下载会话访问对象的常见导出、序列化与旧对象拒绝。PHP7.2与8.5各执行认证199、持久登录499、API协议200、账号API凭据3753、租约418、操作392、下载280及SQLite Webhook处理287项并通过；两处重试测试改为比较公开令牌及元数据，仍检查同一输入重试得到同一结果。PHP7.2语法622文件、224类九版公开API签名、PHP7.2目标level5静态分析均通过，PHP7.2／8.5发行归档各445文件通过。数据库只使用本地SQLite测试数据；当前源码完整九版门禁已中断，独立审查未执行。

## R1.2签名与验证码密钥对象导出修复（2026-10-20，本地）

修复前已执行并复现：仅使用合成密钥，`SigningKey`的`var_export`／`serialize`暴露原始字节；`Turnstile`、`Recaptcha`、`HCaptcha`的`print_r`／`var_export`／`serialize`均暴露。当前实现改用闭包保存私有密钥，并对四类对象拒绝序列化与旧对象反序列化。修复后已执行并通过：PHP7.2—8.5九版各99项8MiB定向断言，覆盖`print_r`／`var_dump`／`var_export`／JSON、旧序列化对象、异常重建状态、原有API签名和三个验证码服务端请求；九版各85项验证码模拟响应、200项API签名／凭据测试及224类公开API反射清单均通过。PHP7.2语法检查621文件通过；PHPStan首次按工具默认128MiB并行内存上限中断，改为512MiB后按PHP7.2目标、level5退出0。未调用第三方验证码服务、未使用真实密钥或业务数据库。

为修复此确认的泄露，同一私有无TCP MySQL九版顺序控制器在PHP8.0阶段有序中断，整体退出130；修复前PHP7.2／7.3／7.4已有各自整版通过标记，但不能算当前修复后源码的整版结果。测试MySQL进程与私有目录均已确认清理。当前修复后的九版完整门禁待重新执行；独立审查、下游和生产未执行。

## R1.1昂贵操作与危险功能目录（2026-10-20，文档）

已执行并通过：对照当前`src/`的ZIP、HTML、GD图片、ClamAV、受限HTTP、密码成本、状态存储及Redis固定Lua入口，核对[清单](resource-risk-inventory.md)中的默认单次限额、来源链接和宿主剩余责任；另搜索当前`src/`的PHP`unserialize()`、PHP`eval()`、动态PHP包含及进程启动入口，未找到此类调用。此检查只是当前源码静态盘点，不能证明第三方解析器、宿主自定义代码、进程级资源隔离或目标部署容量安全。

## 仓库级依赖清单边界（2026-10-20，文档）

已执行并通过：读取根包、HTMLPurifier验证项目、PSR-3／PSR-15可选包及开发工具的`composer.json`和现有`composer.lock`，核对[依赖清单](dependency-inventory.md)所列核心零第三方PHP锁定包、HTMLPurifier`v4.19.1`、PHPStan`2.3.1`、两份可选包的未锁定范围及开发／发行边界。该清单仅是仓库快照，不证明来源可信、使用方安装版本、全部间接依赖安全或SBOM完成；公开公告和真实部署检查未在本项执行。

## R1.1 ASVS安全编码与架构域逐项映射（2026-10-20，文档）

已执行并通过：对照固定Git对象`5cf9b032440be53ce345ab3c130fda46ba1ce7a2`的V15原文，SHA-256为`4c068e82b157159e9ab7099daecb40af4c2642ad791751f791a26785dead6b22`；21个条款编号与[控制矩阵](security-control-matrix.md#安全编码与架构域逐项适用与证据)数量、顺序完全一致。映射依据当前Composer清单、漏洞响应、外连、授权、预算、租约及威胁模型区分组件证据和宿主责任，并明确依赖时限／物料清单等未完成项。这是文档映射检查，不证明依赖安全、实际部署、全部业务入口或ASVS等级验收。

## 当前源码PHP7.4完整私有门禁（2026-10-20，本地）

已执行并通过：修复Cookie字节预算、接入ZIP检查后的同一固定源码，在九版本顺序控制器中输出`PASS full isolated matrix: /tmp/sosecurity-sodium-runtime-akybbkwr/php74-sodium`，随后开始PHP8.0。该版包含SQLite／私有无TCP MySQL的Outbox输入边界243／195项、正文硬上限各8项，以及SQLite 16MiB BLOB／含NUL TEXT在8MiB内存限制下安全拒绝986项；适用的Redis、账号、并发与HTTP检查均由同一`bin/check.sh`完成。269个主SDK PHP源码摘要与门禁启动前一致。当前PHP7.2、7.3、7.4各有整版通过标记；PHP8.0—8.5、九版本控制器整体退出码和私有MySQL最终清理仍待确认。本地测试数据库结果不代表下游或生产验收。

## 当前源码PHP7.3完整私有门禁（2026-10-20，本地）

已执行并通过：修复Cookie字节预算、接入ZIP检查后的固定源码，在九版本顺序控制器中输出`PASS full isolated matrix: /tmp/sosecurity-sodium-runtime-akybbkwr/php73-sodium`，随后已开始PHP7.4。该版包含SQLite／私有无TCP MySQL的Outbox输入边界243／195项、正文硬上限各8项，以及SQLite 16MiB BLOB／含NUL TEXT在8MiB内存限制下安全拒绝986项；适用的Redis、账号、并发、HTTP／TLS检查均由同一`bin/check.sh`完成。269个主SDK PHP源码摘要与门禁启动前一致。PHP7.2／7.3已有各自整版通过标记；PHP7.4—8.5、九版本控制器整体退出码和私有MySQL最终清理仍待确认，不能把两版结果扩展为九版或生产验收。

## 当前源码发行归档双运行时复核（2026-10-20，本地）

已执行并通过：补入依赖及资源风险清单文档后，`python3 tests/archive.py /tmp/sosecurity-sodium-runtime-akybbkwr/php72-sodium`与`python3 tests/archive.py php85`分别退出0，两份临时Composer ZIP归档各包含445个文件。脚本核对归档中的PHP源码集合与当前`src/`完全一致，Outbox／ZIP检查、配置、指南、示例和许可证等必要文件存在，并拒绝`vendor/`、测试、开发工具、演示、可选集成目录及私有配置文件名。归档在临时目录生成并清理；这仅证明本地候选文件清单，不是公开发布或第三方安装验收。

## 当前源码PHP7.3 Outbox双数据库边界（2026-10-20，本地）

已执行并通过：同一九版本顺序控制器的PHP7.3阶段，在SQLite通过Outbox输入边界243项、16MiB BLOB／含NUL TEXT于8MiB内存限制下安全拒绝986项、正文硬上限8项；私有无TCP MySQL通过输入边界195项及正文硬上限8项。PHP7.3整版、其余七版、控制器整体退出码和私有MySQL最终清理仍待确认；这些定向结果不能替代整版验收。数据库仅为本地测试实例。

## 当前源码PHP7.2完整私有门禁（2026-10-20，本地）

已执行并通过：修复Cookie字节预算、接入ZIP检查后的固定源码，在九版本顺序控制器中输出`PASS full isolated matrix: /tmp/sosecurity-sodium-runtime-akybbkwr/php72-sodium`，随后已开始PHP7.3。该PHP7.2整版包含SQLite／私有无TCP MySQL的Outbox输入边界243／195项、正文硬上限各8项，以及SQLite 16MiB BLOB／含NUL TEXT在8MiB内存限制下安全拒绝986项；其余适用的Redis、账号、并发、HTTP／TLS检查也由同一`bin/check.sh`完成。269个主SDK PHP源码摘要与门禁启动前一致。这里只证明PHP7.2这一版的本地整版结果；PHP7.3—8.5、九版控制器整体退出码和私有MySQL最终清理仍待确认，不代表生产或下游验收。

## 当前源码PHP7.2 Outbox双数据库边界（2026-10-20，本地）

已执行并通过：接入ZIP检查及Cookie字节预算后的固定源码，在当前九版本顺序门禁的PHP7.2阶段，SQLite Outbox输入边界243项、16MiB BLOB／含NUL的TEXT在8MiB内存限制下安全拒绝986项、正文硬上限8项；私有无TCP MySQL Outbox输入边界195项、正文硬上限8项。当前源码269个PHP文件摘要与门禁启动时一致。这里只记录已输出的Outbox定向结果；PHP7.2整版及其余八版仍在运行，不能据此写成完整九版通过。数据库均由测试控制器在本地创建，未连接业务数据库。

## R1.1 ASVS数据保护域逐项映射（2026-10-20，文档）

已执行并通过：对照固定Git对象`5cf9b032440be53ce345ab3c130fda46ba1ce7a2`的V14原文，SHA-256为`a9ba33b7c77379fed0f27fd019945e10fa143c63b8c4e4783b7cf587c9f56039`；13个条款编号与[控制矩阵](security-control-matrix.md#数据保护域逐项适用与证据)的数量、顺序完全一致。已按源码和指南区分下载禁缓存、默认图片重编码、签名链接URL凭据例外与宿主浏览器／代理／数据分类责任。这是文档映射检查，不证明全站敏感数据处理、生产环境或ASVS等级验收。

## R1.1 ASVS配置域逐项映射（2026-10-20，文档）

已执行并通过：对照固定Git对象`5cf9b032440be53ce345ab3c130fda46ba1ce7a2`的V13原文，SHA-256为`f66ef1306eba07e04fcd0f23b52d082747f1b4fba0a19934167fb35507afba6d`；21个条款编号与[控制矩阵](security-control-matrix.md#配置域逐项适用与证据)的数量、顺序完全一致。矩阵区分SDK可提供的配置约束与宿主的服务连接、密钥库、服务器及生产部署责任；此项仅验证映射，不证明目标站点配置或ASVS等级验收。

## R1.1 ASVS自包含令牌域逐项映射（2026-10-20，文档）

已执行并通过：对照固定Git对象`5cf9b032440be53ce345ab3c130fda46ba1ce7a2`的V9原文及SHA-256，7个条款编号与[控制矩阵](security-control-matrix.md#自包含令牌域逐项适用与证据)的顺序、数量完全一致。核对`SignedTokens`、`Links`和`HmacKeys`的私有格式签名、期限及用途／受众绑定；矩阵明确不提供通用JWT／JWS／SAML验证或OAuth发行方受众管理。此项只证明映射准确，不证明外部令牌或宿主环境通过验收。

## R1.1 ASVS Web前端域逐项映射（2026-10-20，文档）

已执行并通过：对照固定Git对象`5cf9b032440be53ce345ab3c130fda46ba1ce7a2`的Web前端文件原文及SHA-256，31个条款编号和顺序与[控制矩阵](security-control-matrix.md#web前端域逐项适用与证据)逐行完全一致。矩阵依据本库Cookie、CORS、CSRF、下载、安全头和跳转源码区分可用能力与宿主责任，明确CSP执行、HSTS子域、COOP、浏览器能力、跨域页面与真实站点全入口仍未验证。这是文件映射检查，不是ASVS等级认证、真实浏览器或生产验收。

## R1.3 Cookie编码字节预算（2026-10-20，本地）

已执行并通过：`Cookie::header()`在PHP7.2—8.5九版各通过8项8MiB定向断言，验证名称／等号／编码值合计4096字节恰好接受、超1字节拒绝、百分号编码膨胀、合法NUL编码及4MiB原始值在编码前安全拒绝。原有短值格式与异常类型保持。为先修复该边界，接入ZIP后的九版本顺序整仓门禁在PHP7.2阶段主动中断（控制器退出130），没有整版通过标记；对应无TCP私有MySQL目录和进程已清理。此中断不算当前源码整版通过或测试失败。后续完整门禁需要从修复后的固定源码重新运行；生产和下游未执行。

## R5.1 ZIP公开接口与文件控制映射（2026-10-20，本地）

已执行并通过：`ArchiveInspector`三类错误的`reason()`分别返回`configuration.archive`、`upload.archive`及缺少`ext-zip`时的`dependency.archive`；构造上限、返回字段和无提取副作用按源码与[公开API清单](public-api.md)逐项核对。[迁移说明](migration.md)与[文件控制矩阵](security-control-matrix.md)已区分只读预检和实际解压、内部文件类型验证及宿主私有父目录责任；10份相关文档的381个本地相对链接存在。该结果不证明224类全量公开行为完成复核或稳定冻结，也不证明实际宿主符合ASVS。

## R6.4 ZIP只读检查接入（2026-10-20，本地）

已执行并通过：新`ArchiveInspector`已接入主SDK，六个装有`ext-zip`的运行时（PHP7.2／7.4／8.1／8.2／8.4／8.5）各通过47项定向断言；没有该扩展的PHP7.3／8.0／8.3各通过5项构造和缺依赖拒绝断言。恶意测试样例覆盖路径穿越、隐藏路径／保留名、重复／大小写冲突、链接、目录冲突、深路径、超量条目、伪造计数／CRC／本地头、压缩比、嵌套ZIP／bzip2／xz和含NUL名称；入口不接受提取目标。PHP7.2／8.5公开API签名224类、619文件语法、Composer清单、两版442文件发行归档及两版全新Composer消费者实际调用均通过；PHP7.2目标level5静态分析由PHP8.5运行时执行并退出0，可选Turbo扩展因本机GLIBC较旧未加载。检查仅使用本地临时文件和8MiB PHP内存限制。新增源码的完整九版门禁、真实宿主及生产尚未执行；上一条九版整版门禁属于接入前冻结源码。

## 当前源码九版本完整私有门禁（2026-10-20，本地）

已执行并通过：PHP7.3／7.4／8.0／8.1／8.2／8.3／8.4的七版本顺序控制器整体退出0，包含七个各自的`PASS full isolated matrix`标记；PHP7.2／8.5独立控制器此前均退出0。七版本共用的无TCP MySQL实例及临时目录已由控制器清理，268个主SDK PHP源码与测试前摘要全部一致。本轮九版均覆盖SQLite／私有MySQL的Outbox字段限量读取、含NUL及超限拒绝；PHP8.4分别通过SQLite输入边界243项、16MiB BLOB／含NUL TEXT在8MiB限制下拒绝986项、正文硬上限8项，私有MySQL输入边界195项及正文硬上限8项。整版还运行适用的Redis、HTTP／TLS等检查；PHP7.2—8.0的原生Fiber场景因运行时不支持未执行。该结论只适用于接入ZIP检查前的冻结源码与本地私有测试环境，不证明远端CI、真实浏览器、下游项目或生产验收。

## Outbox限量读取九版本定向复核（2026-10-20，本地）

已执行并通过：当前工作树在PHP7.2—8.5九版的本地SQLite与私有无TCP MySQL测试中，Outbox字段读取边界、含NUL数据及超限拒绝均取得通过结果。顺序控制器中的PHP7.3—8.4每版分别通过SQLite输入边界243项、16MiB BLOB／含NUL TEXT在8MiB内存限制下拒绝986项、正文硬上限8项，以及私有MySQL输入边界195项、正文硬上限8项；PHP7.2／8.5由独立私有控制器验证并退出0。PHP8.4整版门禁与七版本控制器整体退出仍待确认，因此这段只记录Outbox定向结果；所有数据库仅为本地测试实例，生产、下游及远端CI未执行。

## PHP8.3当前完整私有门禁（2026-10-20，本地）

已执行并通过：七版本顺序测试控制器内，当前工作树PHP8.3的`bin/check.sh`成功结束并输出`PASS full isolated matrix: /tmp/sosecurity-sodium-runtime-akybbkwr/php83-sodium`；控制器随即开始PHP8.4。该版SQLite Outbox输入边界243项、16MiB BLOB／含NUL TEXT在8MiB内存限制下的读取拒绝986项和正文硬上限8项通过；私有无TCP MySQL输入边界195项、正文硬上限8项亦通过。原生Fiber上下文场景及该版适用的私有Redis、MySQL、HTTP／TLS检查由整版门禁执行。PHP8.3使用隔离sodium扩展包装器，没有修改系统PHP；268个主SDK PHP源码文件的摘要在整版标记后再次全部匹配。七版本控制器尚未整体退出，PHP8.4不能据此记为通过；所有数据库仅为本地临时测试实例。

## PHP8.2当前完整私有门禁（2026-10-19，本地）

已执行并通过：七版本顺序测试控制器内，当前工作树PHP8.2的`bin/check.sh`成功结束并输出`PASS full isolated matrix: /tmp/sosecurity-sodium-runtime-akybbkwr/php82-isolated`；控制器随即开始PHP8.3。该版SQLite Outbox输入边界243项、16MiB BLOB／含NUL TEXT在8MiB内存限制下的读取拒绝986项和正文硬上限8项通过；私有无TCP MySQL输入边界195项、正文硬上限8项亦通过。原生Fiber上下文场景及该版适用的私有Redis、MySQL、HTTP／TLS检查由整版门禁执行。PHP8.2使用隔离扩展包装器；没有修改系统PHP。另在整版标记后使用`/tmp/sosecurity-r52-src-freeze.sha256`核对268个主SDK PHP源码文件，全部匹配。七版本控制器尚未整体退出，PHP8.3／8.4不能据此记为通过；所有数据库仅为本地临时测试实例。

## R6.4隔离ZIP检查候选（2026-10-19，本地原型）

已执行并通过：隔离目录 `/tmp/sosecurity-r64-candidate` 的只读检查原型在PHP7.2／7.4／8.1／8.2／8.4／8.5六个具备`ext-zip`的运行时，以`memory_limit=8M`验证正常二进制NUL内容、精确条目／容量边界及路径穿越、绝对／反斜线路径、隐藏段／尾随点／Windows保留名、重复／大小写冲突、隐藏嵌套归档、高压缩比、ZIP内符号链接、源文件符号链接、目录冲突、含NUL名称、5000条目录项、伪造目录计数和CRC篡改的拒绝。PHP7.3／8.0／8.3缺少`ext-zip`，三版均按预期明确拒绝。候选在扩展打开前有界解析中央目录；这些结果仅证明隔离原型与测试样例，不是主SDK、发行包或九版本完整门禁的验收。源码接入、更多恶意样例、宿主流程及实际归档处理仍未执行。

## PHP8.1当前完整私有门禁（2026-10-19，本地）

已执行并通过：七版本顺序测试控制器内，当前工作树PHP8.1的`bin/check.sh`成功结束并输出`PASS full isolated matrix: php81`；控制器随即开始PHP8.2。该版SQLite Outbox输入边界243项、16MiB BLOB／含NUL TEXT在8MiB内存限制下的读取拒绝986项和正文硬上限8项通过；私有无TCP MySQL输入边界195项、正文硬上限8项亦通过。三个原生Fiber上下文场景及该版适用的私有Redis、MySQL、HTTP／TLS检查通过。控制器尚未整体退出，PHP8.2—8.4三版不能据此记为通过；所有数据库仅为本地临时测试实例。

## PHP8.0当前完整私有门禁（2026-10-19，本地）

已执行并通过：七版本顺序测试控制器内，当前工作树PHP8.0的`bin/check.sh`成功结束并输出`PASS full isolated matrix: /tmp/sosecurity-sodium-runtime-akybbkwr/php80-sodium`；控制器随即开始PHP8.1。该版SQLite Outbox输入边界243项、16MiB BLOB／含NUL TEXT在8MiB内存限制下的读取拒绝986项和正文硬上限8项通过；私有无TCP MySQL输入边界195项、正文硬上限8项亦通过。私有Redis、MySQL、HTTP／TLS适用检查也由整版门禁执行。原生Fiber三项因PHP8.0不支持而未执行。控制器尚未整体退出，PHP8.1—8.4四版不能据此记为通过；所有数据库仅为本地临时测试实例。

## PHP7.4当前完整私有门禁（2026-10-19，本地）

已执行并通过：七版本顺序测试控制器内，当前工作树PHP7.4的`bin/check.sh`成功结束并输出`PASS full isolated matrix: /tmp/sosecurity-sodium-runtime-akybbkwr/php74-sodium`；控制器随即开始PHP8.0。该版SQLite Outbox输入边界243项、16MiB BLOB／含NUL TEXT在8MiB内存限制下的读取拒绝986项和正文硬上限8项通过；私有无TCP MySQL输入边界195项、正文硬上限8项亦通过。私有Redis、MySQL、HTTP／TLS适用检查也由整版门禁执行。原生Fiber三项因PHP7.4不支持而未执行。控制器尚未整体退出，PHP8.0—8.4五版不能据此记为通过；所有数据库仅为本地临时测试实例。

## R5.3漏洞响应与发布门禁文档（2026-10-19）

已执行并通过：依据现有`SECURITY.md`、发行候选工作单和测试入口编写[中英文漏洞响应与安全发布门禁](security-response.md)，并检查两份指南与安全政策、导航、工作单以及R5.3跟踪的本地链接均存在；`git diff --check`通过。该验证只证明流程文档和链接一致，未执行独立安全审查、正式候选发布或生产部署。R5.3仍为“实施中”。

## R6.5代理／WAF指南（2026-10-19，文档）

已执行并通过：对照当前`ClientIp`源码和原生入口契约完成中英文[代理／WAF指南](reverse-proxy-waf.md)；本地脚本检查两份新指南及导航／使用指南的相对链接均存在，`git diff --check`通过。指南依据Nginx、Apache及OWASP CRS官方资料说明代理可信链和WAF调优边界；本轮未部署真实代理／WAF、未执行浏览器或生产验收，故R6.5保留“已实现待验证”。

## PHP7.3当前完整私有门禁（2026-10-19，本地）

已执行并通过：正在运行的七版本私有测试控制器内，当前工作树PHP7.3的`bin/check.sh`已成功结束并输出`PASS full isolated matrix: /tmp/sosecurity-sodium-runtime-akybbkwr/php73-sodium`，控制器随即开始PHP7.4。PHP7.3的SQLite Outbox输入边界243项、16MiB BLOB／含NUL TEXT在8MiB内存限制下的读取拒绝986项和正文硬上限8项均通过；私有无TCP MySQL的输入边界195项、正文硬上限8项也通过。该版还运行了私有Redis、MySQL、HTTP及TLS适用检查；原生Fiber三项因PHP7.3不支持而未执行。七版本测试控制器尚未整体退出，PHP7.4—8.4六版不能据此记为通过。测试仅使用控制器创建的本地临时数据库。

## 可选适配包独立归档（2026-10-19，本地）

已执行并通过：`python3 tests/optional_archives.py`分别对`integrations/psr3`、`integrations/psr15`执行严格Composer清单校验和ZIP归档检查；每包准确包含Composer清单、源码、独立README和与核心包一致的MIT许可证。CI配置已加入该检查，但远端CI未执行。两个可选适配包的临时Composer消费者新增`composer audit --locked`，已分别使用PHP7.3通过PSR-3 1.x、PSR-15检查，另以PHP8.1通过PSR-3 2.x／3.x检查；四次审计均报告没有安全公告。核心根目录`composer audit --locked`因没有已安装依赖而退出1，不能据此声称依赖审计通过；HTMLPurifier集成锁定依赖审计已执行并通过。没有连接业务数据库、发布包或执行真实下游验收。

## 当前PHP8.5完整私有门禁与消费者（2026-10-19，本地）

已执行并通过：`python3 tests/mysql_check.py --matrix php85`在当前工作树上由私有无TCP MySQL控制器启动`bin/check.sh`，两者均退出0并输出`PASS full isolated matrix: php85`。门禁检查616个PHP文件语法、223类公开API、审计主体与容量30项8MiB断言及八进程竞争；SQLite Outbox输入243项、16MiB BLOB／含NUL TEXT读取986项在8MiB下通过，私有MySQL Outbox输入195项及正文硬上限8项通过。私有Redis、ClamAV、账号生命周期、原生HTTP／TLS及PHP8.5适用Fiber场景亦由同一门禁执行；临时MySQL目录`/tmp/sosecurity-mysql-bjfj78d_`已删除，未发现对应实例仍运行。

已执行并通过：`tests/install.py`分别以PHP7.2／8.5安装当前核心包并运行已覆盖的公开接入流程；`tests/archive.py`两版各检查434个发行包文件与开发产物排除，且已加入`AuditLogger`、`BudgetedSink`及审计接入指南的包内存在断言后重新通过。可选PSR-3适配另在当前工作树的临时Composer消费者重跑：`psr/log` 1.1.4覆盖九版PHP7.2—8.5，2.0.0与3.0.2各覆盖六版PHP8.0—8.5，均退出0。核心消费者脚本不专门调用新增`BudgetedSink::inspect()`，该方法由九版审计定向与两版完整核心门禁覆盖。所有数据库均为测试控制器创建的本地临时库；生产、真实下游、远端CI及完整R1—R6未验收。当前完整门禁只完成PHP7.2与8.5两端，其余七版待复验。

## 当前PHP7.2完整私有门禁（2026-10-19，本地）

已执行并通过：在当前工作树上运行`python3 tests/mysql_check.py --matrix /tmp/sosecurity-sodium-runtime-akybbkwr/php72-sodium`，测试控制器与`bin/check.sh`均退出0并输出`PASS full isolated matrix`。该运行时只在私有包装器加载sodium／POSIX；两份扩展均与RPM签名校验通过的包内文件逐字节摘要一致，未修改系统PHP。门禁检查616个PHP文件语法、223类公开API、当前审计主体／预算30项8MiB断言与八进程额度竞争；SQLite的Outbox输入243项、16MiB BLOB／含NUL TEXT读取986项在8MiB下通过，私有无TCP MySQL的Outbox输入195项及正文硬上限8项通过。加密账号、原生HTTP／TLS、私有Redis和MySQL适用测试亦由同一门禁完成；PHP7.2原生Fiber与Argon2id执行不适用。控制器创建的私有MySQL目录`/tmp/sosecurity-mysql-3wcl51l0`已删除，未发现对应实例仍运行。

初次直接使用系统`php72`运行同一控制器退出1：`tests/credential-setup.php`需要sodium，而该运行时未加载扩展；其之前的通过项不得记作完整门禁。包装器经校验后重跑才取得退出0。此次只是PHP7.2本地完整门禁，当前工作树的其余八版完整门禁、可选PSR-3独立消费者的本轮重跑、远端CI、生产及发布仍未执行。

## R4.6共享审计容量查询（2026-10-19，本地）

已执行并通过：`BudgetedSink::inspect()`新增当前共享固定窗口容量查询；`tests/audit-budgeted-sink.php`在PHP7.2—8.5九版8MiB限制下各通过30项断言，覆盖查询前后余额、跨实例一致、额度耗尽与窗口到期、查询不扣额度、日志写入失败后额度已保留，以及后端故障向外抛出。223类公开API契约在九版通过；新方法已写入候选清单，`src/Audit/BudgetedSink.php`按PHP7.2目标静态扫描无错误，PHP7.2语法和`git diff --check`通过。定向检查未重跑完整九版仓库门禁；无业务数据库、远端CI、生产指标平台或真实告警。容量决策只是并发时刻的快照，不预留下一事件；查询仍使用可能重写等值状态的`AtomicStore::transact()`。

## R4.6可选PSR-3审计适配（2026-10-19，本地）

已执行并通过：`composer validate --strict --working-dir=integrations/psr3`；独立临时Composer消费者安装`psr/log` 1.1.4后，PHP7.2—8.5九版均通过`tests/psr3-audit.php`，覆盖固定消息／级别、含NUL主体的完整字节假名、额外／错误字段拒绝、无效级别拒绝、私有对象导出和日志后端异常传播。PHP8.0—8.5六版另以`psr/log` 2.0.0和3.0.2分别独立安装并通过同一检查。新增PHP文件的PHP7.2语法及Python消费者脚本语法通过，九版CI矩阵已加入适配检查但远端未执行。所有消费者安装在临时目录，未连接业务数据库或真实日志后端；接口调用成功不证明日志持久化、告警或业务事务一致性。完整R4.6仍待完成。

## R4.6共享审计事件预算（2026-10-19，本地）

已执行并通过：`Audit\BudgetedSink`与`AuditLogger`组合在PHP7.2—8.5九版各完成19项8MiB断言，覆盖同一私有FileStore的两个独立实例共享额度、不同站点隔离、窗口到期后重新接收、非共享内存后端拒绝、直接传入异常记录在扣减前拒绝、接收器故障不退款及私有回调不经对象导出泄露。`tests/audit_budgeted_process.py`在九版各启动八个独立PHP工作进程，固定额度三次，均恰好三次接受、五次以`audit.capacity`拒绝；所有临时存储目录结束后删除。九版公开API契约为223类／接口，PHP7.2／8.5新Composer消费者安装退出0；两份审计类按PHP7.2目标静态扫描无错误，新PHP／Python测试与`bin/check.sh`语法通过。没有连接业务数据库、执行远端CI、生产日志接收或真实告警。额度耗尽会阻止要求审计的操作，宿主须配置入口预算与独立告警；日志适配、长期主体基数、指标、告警和完整R4.6继续。

## R4.6审计主体字节预算（2026-10-19，本地）

已执行并通过：`tests/audit-budget.php`在PHP7.2—8.5九版的8MiB限制下各16项断言；含NUL主体按完整字节HMAC，1024字节合法，1025字节／NUL前缀超限及1MiB主体均在sink调用前拒绝。未知敏感上下文字段不进入记录，字段类型错误也不调用sink，sink异常继续抛出。PHP7.2／8.5各通过`tests/run.php`13组（包含审计）、`tests/authorization.php`77项及`tests/portable-core.php`48项；PHP8.5私有对象导出77项通过。`src/Audit/AuditLogger.php`、新测试的PHP7.2语法与`bin/check.sh`语法检查通过；PHP7.2目标PHPStan只扫描该类且无错误。本轮只使用内存／本地临时测试存储，没有业务数据库、远端CI或生产验收。日志适配、全局频率／主体基数、指标、告警和诊断分层仍待完成。

## R4.5原生报表预算调用顺序（2026-10-19，本地）

已执行并通过：`tests/native-report-budget.php`在PHP7.2—8.5九版各27项断言，使用真实`SessionRegistry`、`CsrfTokens`、`Authorizer`、私有FileStore和模拟身份源。GET、无效会话、错误CSRF均在资源加载器及业务回调前拒绝；资源不存在返回404、跨作用域加载结果抛出安全异常、对象归属不符拒绝。有效请求只执行业务一次，后续预算耗尽返回429及正的`Retry-After`；预算存储故障抛出且业务回调不执行，业务回调故障后额度保留、重试被429拒绝；已撤销会话仍拒绝。`runReportPost()`及测试的PHP7.2语法检查、`bin/check.sh`语法检查通过；上一轮PHP7.2／8.5两版新Composer消费者安装检查退出0，归档中的原生示例可加载。本轮没有重跑安装检查。临时目录已清理，没有连接业务数据库。尚未执行真实宿主HTTP／浏览器、业务数据库事务、生产或完整R4.5验收。

## R4.5上传隔离配置预设（2026-10-19，本地）

已执行并通过：`examples/configuration-presets.php`新增上传隔离预设；PHP7.2—8.5九版各执行`tests/configuration-presets.php`的57项工作流断言，两份文件的PHP7.2语法检查通过。缺失扫描器／部署目录时工厂拒绝；补齐私有目录和扫描器后只构造隔离队列，不调用扫描器、创建任务或写状态目录。测试使用自建临时目录并清理，没有连接业务数据库。原生业务调用顺序、生产后端和完整R4.5未在此轮验证。

## 可选 PSR-15 请求预算适配（2026-10-19，本地）

独立Composer消费者安装本地核心包与`integrations/psr15`可选包，以及PSR-7／PSR-15接口和Nyholm PSR-7响应实现。PHP7.2—8.5九版均已执行并通过：放行后下游各调用一次，预算拒绝不调用下游且按决策设置`Retry-After`，错误主体或错误拒绝响应在配置阶段拒绝，存储故障不降级放行，无重试时间的拒绝不伪造该响应头。新增账号预算宿主示例后重新执行九版消费者，缺失／停用账号在下游前拒绝、客户端伪造账号头不改变预算主体、不同账号保持独立额度。测试只使用内存存储及临时Composer目录，没有连接业务数据库。初次锁定的旧Guzzle PSR-7版本被Composer安全公告拦截，未关闭该拦截；随后改用支持PHP7.2的Nyholm稳定版。九版CI矩阵已加入此独立消费者检查，YAML可解析，远端CI未执行。未执行真实框架路由／认证链、生产后端或发行包；完整R4.5继续。

## Redis限量读取与隔离元数据后端（2026-10-19，本地）

已执行并通过：私有无TCP Redis中由服务端生成16MiB含NUL状态值，PHP7.2／8.5均在8MiB内存限制下完成各17项限量读取断言；超限值在原子STRLEN/GET脚本内拒绝，事务回调未执行，合法65536字节状态、512字节ready与含NUL的合法值仍按完整字节处理。两版旧Redis集成各31项通过；PHP7.2实际重启恢复三个阶段通过。旧版直接GET的8MiB耗尽已在隔离测试中实际复现，不能把旧版结果计为通过。phpredis脚本新增STRLEN权限要求；显式诊断新增`bounded_read_permission`，默认诊断不连接Redis。

上传隔离核心在PHP7.2／8.5分别使用私有Redis及无TCP MySQL，各完成535项断言；原生Security工厂在Redis各12项、MySQL各11项通过，证明显式初始化、跨实例持久读取、扫描后的准确文件读取和作用域隔离。两个后端各版均通过三个真实进程场景：管理员拒绝胜过暂停的干净扫描、SIGKILL后租约到期恢复、暂存预留进程终止后安全清理。私有ClamAV 1.4.6使用本地测试签名数据库，与Redis／MySQL元数据后端在PHP7.2／8.5各完成36项干净文件放行、签名拒绝及限额断言；原FileStore与ClamAV组合在PHP7.2同样36项通过。MySQL控制器退出0、临时实例删除；Redis和ClamAV控制器均停止其自身实例并删除目录。原FileStore的PHP7.2核心535项及三个进程场景再次通过；PHP7.2／8.5公开API均为222类型，430文件归档通过。SDK源码PHP7.2目标PHPStan检查退出0且无分析错误；本机PHPStan可选turbo扩展因glibc版本不符发出启动警告，分析器仍完成。初轮PHP7.2测试辅助依赖缺失的posix扩展、工厂测试样例把含NUL文件标成txt而被类型校验拒绝，均已修正；对应初轮失败不计为产品风险反例。

当前源码补验：九版PHP7.2—8.5各使用独立私有无TCP MySQL，通过535项核心、11项原生工厂及三个真实进程场景，控制器退出0并删除临时目录。安装ext-redis的七个默认本地版本（PHP7.2／7.3／7.4／8.0／8.1／8.3／8.5）各在私有无TCP Redis通过17项限量读取、535项核心及12项工厂，控制器均退出0并清理；本地默认PHP8.2／8.4未安装ext-redis，默认运行时专项未执行，私有包装器补验见下。

补充本地运行环境：PHP8.2／8.4默认还缺少POSIX扩展，首次完整门禁均在账号因子真实进程测试处退出1，不能计为通过。随后从本机软件仓库下载经`rpm -K`签名验证的POSIX、Redis、igbinary及msgpack RPM，只提取扩展到私有临时目录并由单独包装器加载，没有安装或覆盖系统PHP。两版包装器均已通过隔离Redis的管理员竞争、SIGKILL租约恢复和staging清理三个真实进程场景，且各通过36项私有ClamAV测试签名／正常／限额组合断言；控制器均退出0，私有Redis／ClamAV及测试目录清理。两版包装器完整门禁最终也均退出0。

当前源码完整`bin/check.sh`在PHP7.2—8.5九版均已执行并取得退出码0，均强制Redis、MySQL、加密及隔离TLS检查；PHP7.2／7.3／7.4／8.0使用私有sodium包装器，PHP8.2／8.4使用上述私有POSIX／Redis包装器。九份最终日志各包含Redis原子限量读取17项、隔离Redis核心535项和工厂12项；均无`FAIL`、PHP警告或异常。PHP7.2—8.0的三个原生Fiber场景未执行（运行时不支持），PHP7.2的Argon2id执行与校准不适用；PHP8.1—8.5日志无跳过项。私有MySQL控制器终态0，其测试实例均已停止清理；没有使用业务数据库。首次直接使用缺sodium的默认PHP7.2运行完整门禁退出1，以及PHP8.2／8.4默认环境缺POSIX的退出1，均保留为环境失败，不计入通过。当前`bin/check.sh`已纳入私有Redis限量读取和隔离核心专项。

未执行生产Redis／MySQL、Redis Cluster、公开发布、远端CI或外部安全审查；本地测试签名不代表生产病毒检出率。R4.4本地阶段已验证，完整R1—R6继续。

## 历史因子清单终态（2026-10-19，本地隔离候选）

当前 `/tmp/sosecurity-state-factor-inventory-bound-dedb6bik/acceptance.json` 在完整账本根、所有记录封存／正文摘要／集合与恢复游标认证后，枚举固定旧版、当前目录及四类已保留工作流中的历史／待处理／取消坐标，最多八个坐标一页，不返回秘密材料。跨采集和跨页保持同一组合摘要，游标绑定完整观测；主体已禁用仍可只读采集，不调用宿主业务审批／因子证明，也不执行销毁。

已执行并通过：PHP7.2—8.5九版351条关联／语法／主SDK原211类API检查，每版新增清单166项、既有入口／工作进程边界50项；44候选源码PHP7.2目标level5静态通过。原211类既有成员九版保持，四个工作流仅增加8个内部候选读取方法。PHP7.2／8.5私有无TCP MySQL各16组589项正常断言及共八个准确反例，原87574控制器实际退出0，实例fkc8c9dk已停止并删除；最终666份冻结输入保持。当前SQLite另有八个准确反例：三个清单规则变种和一个准确错误继承源码各两版，分别取得遗漏待处理因子、混合快照、旧签名集合替换及移除必需状态边界的标记。前三种是清单错误接受证据，最后一种实际完成工作进程迁移并读到有效因子，不混称已完成带授权的因子销毁。

首版yzkpmmml复制了主SDK同名FactorRecovery，漏掉父候选已有的rotateWorkers边界检查；其333条／665份输入及两版MySQL28条正常＋6个对照虽终态0并清理，但在 `results-known-inheritance-gap.json` 明确不验收。修正版恢复准确父版检查，其他43份运行时保持；四个工作流去掉新增只读方法后与各自准确基线逐字节一致。初轮测试预设存在未初始化引用、重复bootstrap和遗漏预期revision等错误，修正记录与失败日志保留于首版目录，不计为安全反例；测试脚本生成器的引号语法错误发生在执行前，也未作为成功执行证据。

摘要兼容复用首版 `digest-compat.json` 的18次对照：同一份174行私有SQLite数据库、含NUL复合键、NULL／空值及0xff字节，跨过64行扫描边界，九版父版与分页版摘要一致；修正版SqlStateSnapshot与分页版字节相同。这里没有将这18次改称在修正版目录重新执行。主SDK仍252源码／211公开候选，尚未接入此44份候选或执行完整SDK门禁、生产、外部服务和发布验收；完整R1—R6保持。下一步准确物理字节CAS、永久空封存／迁移回执、独立强审批及未决回执约束见[历史因子清单](account-state-factor-inventory.md)。


## 历史因子清单的同次快照分页基础（2026-10-18）

隔离候选 `/tmp/sosecurity-state-slot-pages-etdlw7e6/acceptance.json` 在完整SQL扫描中同时采集有界页面、准确总数与主键游标，筛选按完整字节执行，覆盖NULL、NUL后缀、复合主键及来源筛选遗漏拒绝。单页最多8条，行64KiB、选定值合计256KiB，限制在SQL前检查。结果是数据，不授予处置权限；尚未执行历史因子／恢复码销毁或接入SDK。

已执行并通过：九版PHP共252条关联／语法／主SDK211类API检查，652份冻结输入结束后保持；两版私有无TCP MySQL22条正常及2个准确错误二次读取对照，原控制器退出0，实例e6ogt2if删除；40份候选源码PHP7.2目标level5静态通过。错误实现保留原摘要却另取新页面，ABA回切后实际写入测试SQL并触发危险标记；修正版没有该写入。首轮对照漏做选择器归一化，产生非安全原因失败，原记录保留，不计为准确反例；修正后两版SQLite与MySQL均取得准确标记。初轮字节专项与最终130条含NUL复合主键专项分别保留，不将早期计数冒作最终执行。仅本地合成数据，未执行完整SDK门禁或生产验收。

## 固定账号处置、结构侧作用与元数据可见性（2026-10-18）

最终隔离候选 `/tmp/sosecurity-state-containment-policy-g_vbp0nd`提供最多八个明确主体的固定禁用处置：准确完整来源与选定账号、独立真实强认证／准备后重新认证／一次性Grants、持久化pending先于SQL、十列完整字节匹配、提交前当前权限复核及显式未知结果。原密码／角色／地址验证清空，凭据／地址版本推进、状态disabled且要求MFA；原可信摘要／未知SQL保留，普通业务继续隔离。处置前旧会话与密码实际有效，处置后拒绝；未选及跨作用域账号保持，NUL旧值按完整字节匹配，实际八账号与连续两批、子进程／Fiber／克隆借用均有检查，详见[行为与边界](account-state-containment.md)。

首版ou_bjde8的657条九版／46组私有MySQL、每版721／723项均终态0，647份输入保持且实例rzwr6d2b清理；之后两个准确SQLite触发器／级联反例实际改变未选数据，故保留为已知依赖缺口版本而非最终验收。只留主键匹配的两版变体也实际覆盖审批后变化的账号，完整匹配版本回滚。

依赖修正版iwz1jub_的684条九版检查终态0，649份输入保持，候选覆盖的原211类完整公开成员另与父版九版保持，静态通过；原私有MySQL50组现已实际退出0，每版753／755项，原实例0rlnti42清理，649份冻结输入保持；后续部分撤权缺口单列，不据此验收该配置。两版隐藏触发器检查证明普通DML账号可见列表为空但root定义的触发器仍可执行；修正类各17项通过，实例6vkewv2i清理。随后准确部分撤权对照确认全局授权标志也不足：该类两版均实际写入后触发危险标记，补充类各18项通过，原控制器退出0、实例3v5xoqh0清理。最初仅移除库级授权、尚未形成限制的设置断言失败保留；独立元数据探针在同一私有服务器以SHOW GRANTS及实际可见列表验证设置后，再完成准确前后对照，未把设置失败计作反例。

最终g_vbp0nd仅增加MySQL分支对partial_revokes配置的拒绝（该配置或查询能力不支持时安全拒绝，不自动更改数据库设置），另39份运行时与SQLite分支字节保持；补充类与最终文件字节完全相同。更新文件九版语法、全40份静态通过；最终策略版常规两版私有MySQL50组已实际退出0，每版753／755项，650份输入保持，原实例wrfqtroz清理。当前本地候选阶段验收为同目录acceptance.json。没有把父版684条当成当前文件的新一轮完整SDK门禁。当前40份候选尚未接入SDK，低权限独立元数据读取适配、MySQL完整结构来源、精确因子／队列处置、全宿主写入者、原生管理与完整R1—R6继续。


## 受审批且仍隔离的新代际（2026-10-18）

隔离候选 `/tmp/sosecurity-state-successor-tk2v5zrv` 新增格式3及准确预期代际、强类型签名预览与独立一次性审批，在原权威文件同一inode写入 `quarantined`。原可信摘要、未知操作标识及完整描述保留；旧读取器与错误代际拒绝，普通工作回调为零，不能初始化覆盖。审批前状态变化、过期、错误授权、最终撤权与写入确认失败均有实际拒绝测试；失败后保持关闭或隔离，未采纳当前数据库。见[交接边界](account-state-successor.md)。

最终候选38源码、636输入冻结；九版684条中675条关联／语法通过，9条因覆盖类与主源码反射路径不符失败。该反射脚本原本过滤主源码以外的方法，不能用于覆盖候选；失败保留，补充主SDK原211类九版接口及允许准确两种源码路径的原211类父候选完整成员对照均通过。没有修改或放宽主SDK公开契约，也没有声称新增候选类已发布。两版私有无TCP MySQL24组、每版289项通过，控制器退出0、实例pto9pm9b清理；静态目标70200／level5通过，最终输入仍保持。无原生Fiber的四版只执行进程部分。

候选见证另补进程／Fiber持锁归属：两版准确旧源码在父工作区间实际获得另一排他锁并写入SQL，修正版各5项通过。首轮PHP72直接启动器缺少sodium、初次静态128MiB超限、新锁测试缺失预算函数均单列为运行环境／测试失败，不能作为安全反例；有效前后对照采用已存在的隔离sodium运行时和正确测试函数。验收 `acceptance.json`及原矩阵、修正API、MySQL、锁反例与失败说明均在同一候选目录。

这仍是未接入SDK的候选阶段；隔离中的账号凭据／会话／因子／队列处置、全部宿主写入者、业务恢复提交、工厂／原生界面及完整门禁尚未完成。原主SDK LocalEpochFence MySQL88731是另一独立运行，已另行取得实际终态0及实例清理；两套证据分别记录。


## 原生会话撤销的近期认证（2026-10-18）

`examples/authentication.php` 对 `revoke`／`logout_all` 增加 `VerifiedSession::recent(300, time(), 1)`，记住登录恢复不能通过。普通退出仍可执行。`tests/auth-example-browser.cjs`建立第二个真实浏览器会话，核对恢复后撤销被拒绝且该会话保持、全部退出被拒绝且当前身份保持、重新认证后撤销成功；随后完整持久授权／退出流程通过。测试运行器增加可选原生示例目录，仅用于明确选取分发示例或本地对照源码。

PHP7.2／8.5 本地 Chromium 均通过；移除新增权限检查的两版对照实际撤销第二会话后触发 `UNSAFE_SESSION_TERMINATION_WITHOUT_REAUTH`。九版语法通过。首轮浏览器误用恢复后保留的当前管理编号作为目标，正确自我撤销后等待列表超时；已保留原失败，改用第二个真实会话后通过，不能把初次失败解释为未拒绝越权。两版原生 HTTP 各192项通过。证据 `/tmp/sosecurity-session-recent-ua62dzf0/final-report.json`、`syntax.json` 和 `http-report.json`，均只针对自有临时账号、存储和127.0.0.1服务器；没有生产或其他宿主结论。

同时按固定发布Git对象核对 ASVS5.0.0 V7 的19条条款与当前源码／责任矩阵，原始文件及blob摘要一致。映射核对不等于所有接入要求已验收；全局管理撤销、宿主Session ID、真实SSO及全部写入者仍分别跟踪。


## 主SDK本地权威上下文与父锁保持（2026-10-18）

LocalEpochFence在主SDK补齐进程／原生Fiber归属、有效工作句柄和关闭清理归属；子进程仅关闭自己的描述，不显式解锁父进程。准确旧代码的进程借用、关闭清理借用、外部Fiber、过期克隆及子进程释放父SH锁均实际写入本地测试SQL后触发危险标记；组合候选另确认StateBoundary克隆可逃逸写入，并已禁止克隆。两版共十二个准确反例通过，主SDK与组合候选静态目标70200／level5通过，原211类接口初查保持。代码无公开签名／封存格式变化，八组上下文检查纳入常规账号因子入口。

原组合定向19123已实际退出0：225条调用、213条执行通过、12条无原生Fiber未执行，哈希保持。原主SDK九版13655已实际退出0：558条测试调用中546条执行通过、12条无原生Fiber未执行，每版54组账号因子关联与八组上下文调用完成，原211类九版接口保持，最终冻结清单保持；原私有MySQL88731现已实际退出0，实例1n8318m3及原PID结束并清理；52条调用中49条执行通过，3条PHP7.2原生Fiber不可用未执行，每版分别1668／1677项断言，最终509份输入保持。当前阶段终态 `/tmp/sosecurity-fence-context-l3fcyte_/acceptance.json`，原在途记录保留；完整边界见[上下文说明](account-fence-context.md)。主源码252／公开类211；仅本地测试数据，未部署或更新在途旧代码。完整安全新代际、全部写入者和R1—R6继续。

## 独立关闭的真实授权策略绑定（2026-10-18）

首版关闭候选后续确认实际策略分离：控制权限硬编码300秒，而真实Grants.maximumAge可更短；30秒边界的真实会话在pending后才被拒绝。另以真实恢复码登录通过了TOTP专用预览门槛。修正版 `/tmp/sosecurity-state-retirement-bound-rwhdrz_u` 在只读阶段使用实际Grants.maximumAge／methods，增加规范化方法集合并采用严格近期性边界，两个摘要域更新为2；未自动升级旧预览或改写旧操作。前版945条及MySQL终态证据保留，但results-known-policy-gap明确不作最终审批策略验收。

原九版会话86690实际退出0：990条全通过、638份冻结输入保持，九次SQL摘要与首版完全相同；关闭／策略／身份专项每版314项，实际支持Fiber的五版为317项，权限输入另增6项。原211类API九版保持，26个既有／三个上下文／四个准确首版策略反例通过；两版另确认实际认证拒绝导致pending的底层原因。原私有MySQL13681实际退出0，22条、两版174／177项通过，专属实例5pu28ma3已删除，静态61025中的最终分析目标70200／level5通过。修正版只有三份运行时与首版不同，最终哈希再次核对保持，汇总为候选acceptance.json。仅本地测试数据库，未接入主SDK，安全新代际、全部写入者及完整R1—R6继续。

## 独立审批关闭未决旧权威（2026-10-18）

[关闭候选](account-state-retirement.md)绑定准确短期封存预览、真实独立管理角色／密码MFA／新的重新认证／一次性Grants，核对实际数据库与目录分离，关闭后保留原操作号、原摘要和未知SQL结果。另修正StateBoundary进程／Fiber归属，准确旧代码的两版派生进程与单版Fiber反例均实际写入后触发危险标记。

原九版会话20547实际退出0，945条全通过，632份冻结输入保持，九次SQL摘要与前版完全相同；每版新增259项，支持Fiber的五版为262项。原211类API九版保持，29个准确反例及PHP7.2目标level5静态通过。后续静态一度因70200目标无法识别版本分支中的Fiber而失败，增加内置类存在检查后通过，没有规则抑制。原MySQL会话41045已实际退出0，业务侧MySQL／独立控制侧SQLite的16条定向命令、两版145／148项通过，专属实例l87e4x68已删除。另两版各15项真实未消费授权复用证明、各11项业务凭据跨域拒绝通过；最终源码与测试哈希再核对保持。

汇总 `/tmp/sosecurity-state-retirement-dgpmpm_b/acceptance.json`。37份运行时隔离源码尚未接入SDK；永久关闭不等于安全启用新代际或恢复业务，不能自动采纳数据库或重放未知操作。全部宿主写入者、其他活动门槛、正式SDK整合与完整R1—R6继续，仅本地合成测试数据，未发布／生产验收。

## 状态见证持久化操作记录（2026-10-18）

[操作记录候选](account-state-operations.md)在显式格式2的pending前绑定准确动作、作用域、已验证操作者／目标、权限要求、实际策略及检查时间，内部调用不虚构身份。33份运行时隔离源码，首轮774条中765条通过，九条失败均为同一新测试把审计条数断言放错位置；原日志／输入保留，源码及摘要保持。仅修正测试位置后，两个新专项九版18次、每版107项通过，正式测试与通过副本字节一致；不称为完整重跑774条。原211类API九版保持，26个准确反例均触发预期危险行为标记，PHP7.2目标level5静态通过。

首轮MySQL因同一测试错误退出1、实例清理；修正版原会话36628实际退出0，两版各七组251项通过，专属实例r_8h7xyw已删除，最终源码／修正测试哈希再次核对保持。完整汇总 `/tmp/sosecurity-state-intent-hzlh8i2r/acceptance.json`。尚未接入SDK，独立强审批未知结果恢复、受控格式交接／安全代际、全宿主写入者与完整R1—R6继续；没有自动采纳pending数据库。仅本地合成数据库，未发布或生产验收。

## Outbox 精确超限与完整字节续验（2026-10-18）

本次沿用现有SQL字段投影字节限额、实际BLOB类型检查和完整正文摘要校验，仅补充测试。`outbox-body-budget.php` 将逐字段超限样例收紧为恰好超出1字节，并补齐错误存储类型的四类业务入口拒绝及独立连接快照核对。`outbox-input-bounds.php` 新增全部256种原始字节精确达到策略上限的完整往返，以及追加1字节NUL在SQL和权限回调前拒绝。

已执行并通过：PHP7.2／8.5的本地临时SQLite各五组、1782项断言，包括字段／正文986、输入边界243、硬上限8、核心175、安全370；前两组使用8MiB内存限制，覆盖16MiB异常字段安全拒绝。两份测试通过PHP7.2语法检查。日志保存在 `/tmp/sosecurity-outbox-defensive-2e_5x0p8`。本次未执行其他七版PHP或完整SDK门禁。

私有无TCP MySQL原会话45898已实际退出0，两版各九组、1561项断言通过，专属实例 `/tmp/sosecurity-mysql-mlh5vk17` 已停止并删除。输入哈希在MySQL结束后再次核对保持，汇总为日志目录内的 `final-report.json`。首次静态入口 `vendor/bin/phpstan` 缺失，分析未运行；改用仓库已有 `tools/vendor/phpstan/phpstan/phpstan.phar` 后，Outbox、共享SQL字段及事务类在PHP7.2目标、level5下静态分析通过。测试仅使用本地合成数据，没有连接业务数据库，未提交或发布。

当前工作区再次复验：上述七份关键源码／测试输入与前次记录的 SHA-256 全部一致，PHP7.2／8.5 SQLite 各1782项、私有无TCP MySQL 各九组1561项及PHP7.2目标level5静态分析再次通过。MySQL控制器实际退出0，独立临时实例已停止并删除；结束后再次核对七份输入保持不变。本次没有追加运行时代码变更，记录见 `/tmp/sosecurity-outbox-recheck-gv6vudj_/final-report.json`，仅验证本地合成数据，未执行完整SDK门禁或生产测试。

## 目录账本封存与完整集合的一致拒绝（2026-10-18）

候选 `/tmp/sosecurity-state-ledger-8ma54m6h` 复核配置绑定版的纯读取边界。准确旧版在七类已由当前检查点确认的异常账本样例中，真实业务读取拒绝，而权限回调仍执行了测试SQL；PHP7.2／8.5共十四个准确反例均取得 `UNSAFE_PERMISSION_BYPASSED_DIRECTORY_LEDGER_*` 标记。这里验证的是两套读取规则的一致性，不将经测试写入者确认的新摘要当成未经权威确认的数据库篡改绕过。

- 新候选让真实Ledger与固定权限读取共用 `LedgerState` 的规范封存编码、元数据认证和正文摘要校验；使用实际登记服务的账本策略及准确密钥环。目录视图包含完整根／记录字段、正文、当前格式／代际／策略、修订／时间／保留边界与历史摘要；另从同一次完整SQL扫描取得规范化主键前缀的准确记录数。额外来源过滤不能隐藏该前缀下的成员，所有过滤须由该前缀严格蕴含，否则查询前拒绝。
- 首轮PHP7.2七类各10项、共70项通过：记录封存、有效封存但根策略／历史不符、正文摘要不符、当前钥环已退役的旧键、额外命名空间记录及根时钟异常。真实业务与固定权限读取都拒绝，权限业务回调和pending持久化均未执行，见证保持current。前缀计数另29项，覆盖空组、多条、精确键、NUL、隐藏筛选、无额外COUNT查询及跨连接写入；九版API保持、静态通过，原始源码反例与其输入哈希分别记录在extra-report。
- 初轮完整747条中746条退出0，PHP8.2并发计数样例失败；输入哈希及共享摘要保持。原日志、测试和控制器保存在before-observer-transaction。补上回调内事务回滚后，十二次PHP8.2复测仍失败；诊断确认错误发生在观察连接新一代写入后的第二次快照BEGIN，而非计数逻辑。测试辅助写入补齐异常路径closeCursor，观察连接的两次写入均改为明确提交／回滚；十二次三并发复测随后全通过。运行时账本、计数与事务实现未据此放宽。失败样例可能留下合成SQLite测试目录，未进行跨任务批量删除。
- 首个私有MySQL控制器退出1：新加入的通用账本测试漏传mysql参数，没有读取环境中已有的测试socket，按归属保护在连接前拒绝；不是缺少account-test-owner。已补齐参数，归属校验与无TCP启动不变，原实例 `/tmp/sosecurity-mysql-cd6kkeok` 已停止并删除。未把拒绝启动记成运行时测试通过。

修正后的九版完整747条矩阵已实际终态0：会话22128，所有命令退出0，618份输入哈希保持，九次SQL摘要与前版完全相同；每版新增99项。原私有MySQL会话77670已实际退出0，日志含80条PASS记录，专属实例 `/tmp/sosecurity-mysql-txnz9dwh` 已停止并删除，结果记录于候选目录mysql-acceptance.json。当前复核原618份输入中616份仍相同，仅两份Outbox边界测试已在后续专项补强；账本候选运行时代码未变化，不再将当前全清单描述为哈希保持。诊断用SqlTransaction副本仅用于保留原异常定位，没有写入候选src或主SDK；首次诊断加载器误把候选自动加载脚本的返回值当成Composer对象，修正后才取得上述定位。

本轮仍未接入SDK。统一入口、动作／目标绑定的pending、独立强审批未知结果／安全代际、全部宿主写入者及完整R1—R6继续；没有生产、提交、推送或发布。

## 固定权限阶段与准确运行时配置绑定（2026-10-18）

当前候选 `/tmp/sosecurity-state-permission-bound-58axyqpj/progress.json`；[权限设计](account-state-permissions.md)说明适用范围。独立见证自行核对完整摘要，再以固定账号／角色／凭据／会话／因子读取判断权限，普通拒绝发生在pending前；已有任意回调入口尚未统一，也未接入主SDK。

- 已执行并通过：九版PHP7.2—8.5共639条关联／语法命令，614份冻结输入在结束后再次核对保持。每版新权限检查213项，包括真实MFA会话、当前角色及账号／因子／会话状态、恢复登录例外、准确动作／作用域／目标、近期认证、无副作用拒绝、立即合法重试、未知SQL副作用及pending回执丢失；还覆盖实际MFA禁用后的密码会话强度选择，以及真实会话策略收紧后的空闲／绝对期限。基本权限64、输入19、当前状态53、未知结果17、密码强度22、角色／身份指纹各7、服务绑定7、空闲8、绝对9。原有认证／会话／持久登录、MFA205项及因子恢复后真实登录关联也在本轮矩阵执行，没有以纯解析测试替代它们。
- 九版原211类公开成员保持，只追加可选构造参数或新方法；本候选新类型尚未作为正式SDK公开API分类／冻结。PHP7.2目标level5静态通过，可选turbo扩展GLIBC警告保留。主SDK仍为252源码／211公开候选。
- SQLite两版共12个反例全部按预期退出255并触发准确标记：忽略当前角色或凭据指纹会实际写入测试SQL；延后权限拒绝会把正常拒绝变成pending未知结果；恢复旧idle／absolute常量会允许超出当前会话期限的凭据。准确前版代码另实际允许同一SQL副作用，随后真实idle10登记服务拒绝同一凭据，触发 `UNSAFE_PREVIOUS_POLICY_AUTHORIZED_EXPIRED_CURRENT_SESSION`。反例覆盖了实际行为，不使用缺失方法或参数不兼容作为失败证明。
- 前版 `/tmp/sosecurity-state-permission-jo1sgbii` 的594条、两版私有MySQL及API／六个SQLite反例原运行均已结束，源码保持、控制器退出0，实例 `/tmp/sosecurity-mysql-9vwdgdlr` 删除；但独立会话期限缺口已被确认，故该版明确不验收为最终权限配置，记录在results-known-gap.json。没有把其绿色矩阵当成安全结论，修正版从实际服务绑定取得策略，并限制准确存储／适配器／因子服务／时钟／密钥环。
- 该配置绑定版原私有MySQL控制器已结束：会话7287实际退出0，42组、PHP7.2／8.5各664项及十四个MySQL反例通过；实例 `/tmp/sosecurity-mysql-ajfp419x` 删除，614份输入哈希再次核对保持。后续目录账本封存缺口已有实际反例，该版不作为最终权限读取验收，汇总见results-known-ledger-gap.json。仅本地自建无TCP测试实例，无业务库，没有重启替代原运行。

首轮直接使用未加载sodium的系统php72在进入候选前失败，改用既有隔离sodium运行时后通过；首个静态检查发现纯解析抽取后一个私有方法未使用，移除后通过。outcomes-first.log漏用已加载测试辅助函数，password-first.log误读execute返回字段；仅修正测试后通过，原失败及说明均保留。当前阶段还需账本封存／策略／密钥退役边界一致性复核、统一入口、全宿主写入者、动作／目标绑定的强审批未知结果与安全代际、正式配置／HTTP／CSRF／浏览器、消费者／发行包及完整R1—R6；没有生产、提交、推送或发布。

## FileStore与组合来源的同次采集（2026-10-18）

`/tmp/sosecurity-state-view-axdex448/acceptance.json` 记录SQL采集之后的物理／组合视图候选。本阶段新增 `FileStateCapture`、`CompositeStateCapture` 及具体来源的纯选择器规范化；普通digest协议保持，主SDK未接入。它没有把原始会话文件解释为已验证会话，也没有执行TOTP／恢复码消费或权限批准。

- 已执行并通过：九版PHP7.2—8.5共432条关联／语法命令，覆盖新视图、SQL来源、完整原始物理状态、组合见证、完整旧备份拒绝、认证／会话／持久登录及准确作用域；392份冻结源码／测试输入哈希保持。新 `file-view.php` 每版44项、`composite-view.php` 每版39项、`view-race.php` 每版8项；补充 `view-budget.php` 每版39项，共每版新增130项。补充测试及其26份来源／反例／测试输入另在extra-report中固定并核对哈希。
- 精确1MiB选定值来自4个实际完整来源采集，含16份64KiB返回值；两轮结果同时存在于受实际 `memory_limit=8M` 限制的进程。核对实际内存用量及分配器预留量，后者允许恰好达到8MiB；第五个选定来源在读取前拒绝，未选中来源仍计入完整摘要。选择器被调用方引用修改不改变已规范化请求，缺失文件与零字节文件区分，原始NUL字节与真实FileStore编码数据保持。
- 九次共享SQL摘要与前版逐字节一致；同一物理路径及inode的旧版／新版各九次、合计18次摘要对照完全相同，测试源文件保持，排序临时目录已清理。没有因实现变化自动采用旧权威或更换来源协议。
- PHP7.2／8.5私有无TCP MySQL共18组正向测试、每版227项通过，包含同次采集、独立提交后改写、跨页一致性、组合来源与真实密码／MFA／会话完整旧备份拒绝。原会话70847已取得终态0；自建实例 `/tmp/sosecurity-mysql-xn9p_48o` 已停止，目录删除。新源码在MySQL运行结束后再次核对392份哈希保持；没有重启替代原结果。
- 两后端、两版本共八个准确反例全部按预期退出255。省略两轮一致性检查后，程序实际返回旧摘要／旧文件值，而独立观察已是新文件，触发 `UNSAFE_COMPOSITE_CAPTURE_ACCEPTED_CHANGED_PHYSICAL_STATE`；放开未选中插件摘要回调后，回调实际修改测试表，触发 `UNSAFE_READ_ONLY_CAPTURE_INVOKED_EFFECTFUL_PLUGIN`。这些是移除防护的隔离反例，不代表主SDK曾具备此尚未接入的接口。
- PHP7.2目标level5最终静态分析通过；可选turbo扩展的已知GLIBC加载警告仍保留。主SDK252份运行时、211类公开候选未改变，未执行本候选的正式工厂／原生HTTP／浏览器、消费者发行包或完整SDK门禁，不把局部矩阵当成这些验收。

后续由独立见证自己采集并核对准确签名摘要，再对当前账号、角色、会话与因子绑定执行固定无副作用评估；外部构造采集对象不能代替批准。pending前明确拒绝、动作／目标绑定、未知结果强审批与安全代际、全部宿主写入者、其他物理后端及完整R1—R6继续。仅本地隔离数据库与合成数据，无生产、提交、推送或发布。

## 当前权限字段与完整摘要同次采集（2026-10-18）

隔离候选 `/tmp/sosecurity-state-capture-_6rot5gs` 基于准确作用域版本新增 `SqlStateCapture` 与SQL来源的固定选择器采集。主SDK运行时及API清单未改动；详见[入口边界](account-state-entries.md#只读权限视图的同次-sql-采集候选)。本次没有把采集结果当成权限凭据，正式权限评估与pending前拒绝仍未实现。

- 已执行并通过：`matrix-final-report.json` 的九版PHP7.2—8.5共378条关联／语法命令，382份冻结程序哈希保持。新增 `capture.php` 每版SQLite72项；`extra-report.json` 的 `capture-commit.php` 每版5项。两者覆盖同一摘要事务内的跨页选定字段、精确类型化复合主键、缺失／筛选行、NULL／空BLOB／NUL、返回值不可变、选择器在SQL前拒绝、单条64KiB及合计256KiB精确预算、未选中损坏行仍拒绝，以及COMMIT后独立连接立即改写时不混用新值。
- 九次共享SQL测试数据的摘要彼此相同，也与准确作用域前版完全相同，没有借此更换快照协议或采用旧权威。PHP7.2目标level5静态分析通过；安装的可选turbo扩展GLIBC加载警告保留，不计为已加载该扩展。
- 已执行并通过：PHP7.2／8.5的SQLite与私有MySQL共四个准确反例。反例只将选定字段改为完整摘要事务结束后再次查询，实际触发 `UNSAFE_SQL_CAPTURE_RETURNED_NEW_ROWS_WITH_OLD_DIGEST` 并退出255；正常版本返回摘要对应的旧字段，即使独立观察连接已看到新值。
- 私有无TCP MySQL原完整关联控制器已确认退出0：`mysql-final.py`、`mysql-final.log` 的34组全部通过，PHP7.2／8.5各401项；另有extra-report中每版5项提交后竞态通过。原会话72507终态已取得，进程2903140与服务进程2903479均已结束，实例 `/tmp/sosecurity-mysql-np5ni3yu` 目录删除；382份冻结程序哈希再次核对保持。终态汇总见acceptance.json，没有重启替代原运行。

初次PHP7.2采集测试把事务所有权检查所需查询也列为禁止，已保留失败说明并改成验证宿主事务数据与显式回滚保持；并未放宽事务所有权保护。新提交后测试首次执行有PHP字符串转义语法错误，修正后才运行上述正式extra清单。静态检查初次误用不存在的vendor/bin/phpstan，日志static.log保留；正确使用tools/vendor/bin/phpstan后的static-retry.log通过。没有生产、提交、推送或发布；物理状态同次采集、组合一致性、固定无副作用权限评估、独立强审批恢复及完整R1—R6继续。

## 实际入口、存储门槛与准确作用域（2026-10-18）

基础入口候选 `/tmp/sosecurity-state-entry-nxttobie/acceptance.json`：九版351条核心／语法／既有流程及两版私有MySQL30组全部通过，379份冻结程序保持；每版SQLite1147项、MySQL320项。原211类九版成员对照保持，只有可选构造参数追加与新方法。八个移除防护的反例均取得准确危险副作用。实例 `/tmp/sosecurity-mysql-1v05ioiw` 控制脚本终态0且目录清理。后续确认此基础版未校验入口与见证准确作用域，不能把该快照当成最终修正。

后续 `/tmp/sosecurity-state-scope-xt6nm5az/acceptance.json` 的九版360条全部退出0，两类共享数据共18次摘要一致；每版SQLite1160项，含新入口196项、既有认证／持久登录698项。两版私有MySQL32组、各333项，控制器实际终态0；实例 `/tmp/sosecurity-mysql-oo8n0t7n` 已停止、目录删除。380份冻结运行时及测试输入保持，PHP7.2目标level5静态通过，仍保留已安装可选turbo扩展的GLIBC警告。主SDK252源码／211公开候选保持，新增入口及来源仍在隔离目录。

真实密码／MFA登录、会话重新认证、持久凭据恢复／撤销及准确旧FileStore备份拒绝均走实际SDK入口，不再仅在测试外层手工包装。外层操作只提交一次检查点，内部会话调用加入同一上下文；宿主公开请求防护／独立预算回调、无效令牌及输入上限在受保护状态或提供器访问前拒绝，不发布pending；防护及当前权限回调使用合成准许／拒绝，不代表HTTP的CSRF令牌、浏览器或完整宿主授权接入已验收。锁内当前权限复核没有省略，嵌套公开调用也执行公开门槛；当前权限失效或回执不确定仍保守保留未知结果。真正无副作用的锁内权限阶段和独立恢复未完成，不将这些保守阻断当作可用性缺口已关闭。

新格式2栅栏绑定见证身份，真实受审批交接使旧权威永久关闭，新登记客户端可在活动上下文中继续验证原会话；目录／物理因子／恢复／管理预览／登记读取在上下文外先拒绝且没有SQL。后续工作进程交接不能移除所需见证。移除见证、存储门槛、当前权限及禁止降级的两版八个反例分别观察到旧会话重新认证、真实未授权写入、未获当前权限仍发放挑战、以及取消强制边界后在上下文外读取当前因子。准确旧作用域实现的两版反例实际以另一租户恢复的旧密码完成认证；后续修正的13项作用域专项在九版及两版MySQL均通过，提供器／源状态未被读取，本租户登录保持。

两个独立Composer消费者各七组196项通过，17个相关类的Reflection来源均为安装副本，262源码与候选包哈希相同，外部测试只依赖安装副本的自动加载器、示例和SQL。221类本地API提案经PHP7.2核对，392文件候选归档无vendor／tests／bin等开发条目；此包没有合入主SDK或发布，也不替代完整发行包验收。初次包API命令缺少自动加载器、初测误用结果getter／错误工厂名称／在上下文外自动初始化等失败均保留，修正工具或测试后再运行，未放宽运行时门槛。

详细设计见[入口边界](account-state-entries.md)。所有宿主PDO写入者、注册／邮箱恢复／后台入口、完整自动管理门面、强类型当前权限阶段、未知动作／目标绑定的独立强审批与安全代际、其他物理后端及多作用域分区、正式配置／诊断／原生HTTP／浏览器和完整R1—R6继续。仅本地合成身份与自建测试数据库，无生产、提交、推送或发布。

## 来源上下文与不可变构造引用（2026-10-18）

`/tmp/sosecurity-state-context-9x0z0k2n/acceptance.json` 记录当前隔离来源候选。最终九版171条核心／语法命令及SQL／物理两类共享数据18次摘要对照全部通过，每版SQLite266项，358份冻结程序与final-source-before.json一致。目录指纹采用原始路径字节编码及格式2，非UTF-8目录保持可用；两个不同目录、同PDO、相同文件字节不能采用对方独立检查点。组合构造逐项捕获对象，不保留调用方数组元素引用；外部替换或删除原数组不改变来源，提供器自身覆盖／连接复核保留。

两版私有无TCP MySQL18组、每版137项全部通过，控制脚本终态0，实例 `/tmp/sosecurity-mysql-dbifhnpe` 已停止并清理。初轮171条中PHP7.2—7.4三组二进制目录测试漏设PDO异常模式，归档在before-pdo-test-mode；只修正测试显式异常模式后完整九版重跑。MySQL未加载该SQLite专属测试，实际使用的源码／依赖未变；准确旧文件映射与其运行前清单在acceptance.json保留，不把两份全文件清单混为一份。首次PHP7.2目录反例也仅因测试设置失败，未计有效反例；最终negative/final-report.json两版四项均退出255并触发准确副作用标记，区分旧实现真的采用他处权威与构造引用改变。目标PHP7.2 level5静态通过，可选turbo扩展的GLIBC警告仍保留。

来源与真实完整备份包装仍未接入SDK。全入口／全部写入者、权限及副作用阶段、独立未知结果强审批、安全代际、其他物理后端、正式工厂／原生入口／消费者及完整R1—R6继续；没有生产、提交或发布。

## 固定宿主来源的真实完整认证备份（2026-10-18）

隔离候选 `/tmp/sosecurity-auth-snapshot-7itc8d6m/acceptance.json`：九版153条核心／语法、九次共享SQL摘要全部退出0；两版私有无TCP MySQL18组、静态通过，355份冻结程序哈希保持。每版SQLite252项、MySQL137项，MySQL控制器实际终态0，实例 `/tmp/sosecurity-mysql-s3ju5yim` 已停止并清理。准确六表固定配置含宿主实际密码、身份、审计、签名目录／意图及Outbox全部字段，保留16KiB账本及1MiB Outbox正文能力；物理来源包括全部会话／因子FileStore文件。

实际密码／TOTP登录、恢复码轮换和独立会话撤销两类各11／12项，真实旧会话先被拒绝，原SQL字段类型和原始文件字节恢复后重现原组合摘要，认证回调未执行，按account.witness_stale拒绝。`negative/report.json` 两版六个准确反例全部退出255；省略比较或只摘要SQL会实际重新认证旧会话，明确出现UNSAFE_TYPED_COMPLETE_BACKUP_REAUTHENTICATED_REVOKED_SESSION。旧SQL来源没有结构定义摘要时，COLLATE改动会改变真实查询结果却保留原摘要，新结构测试准确失败，不是语法或装载错误。

新增显式完整SQLite原生声明31项及结构语义11项，覆盖VARCHAR长度不可信、实际字节／类型、完整配置、错误驱动、表排序规则、持久／临时触发器及索引。定义最多16KiB／对象合计128项，SQL端先判断长度。原始 `before-schema-semantics/` 和初始日志保留。

初轮MySQL在PHP8.5的实际内存断言失败，`before-memory-ceiling/` 保存当时153条通过快照及失败MySQL日志；独立诊断实例 `/tmp/sosecurity-mysql-bl1zo8br` 观测分配器预留8388608字节、实际峰值3815760字节、有效限制8M后同样按预期触发原断言。只修正测试允许预留量等于强制上限并增加实际用量／有效限制检查，运行时代码保持。最终完整矩阵及私有MySQL重新执行；前一失败实例与诊断实例均清理，不计作正常通过。

候选仍未接入SDK；另发现非UTF-8目录指纹可能碰撞、构造数组引用影响组合来源，后续 `/tmp/sosecurity-state-context-9x0z0k2n` 修正验证中。当前证据只证明上述固定宿主的受控入口包装，不代表所有认证／变更／维护入口、未知结果独立审批、安全代际或完整规划完成。

## 有界 FileStore 与组合状态来源（2026-10-18）

`/tmp/sosecurity-file-snapshot-j1piv3sz/acceptance.json` 确认隔离候选完成本阶段验证，未接入SDK：九版 `matrix-final-report.json` 117条核心／语法命令全部退出0，每版185项运行断言，包含父SQL来源111项、物理来源47项、一万文件容量7项及组合20项。SQL与物理两类共享数据共18次跨PHP7.2—8.5摘要一致；269份冻结相关程序与 `final-source-before.json` 核对无变化，新增独立文件向量程序另存于本阶段。目标PHP7.2 level5静态退出0，仍有已安装可选turbo扩展的GLIBC启动警告，未影响分析。

私有MySQL控制脚本终态0，12组、两版各110项，包含跨连接分页与真实SQL／FileStore组合。实例 `/tmp/sosecurity-mysql-mebw9e4d` 已停止且目录清理。组合源两轮一致，组件名字顺序不影响摘要，准确PDO／覆盖变化拒绝。独立见证确认新SQL密码和物理会话状态后，将合成数据恢复至原始SQL及文件状态、核对原组合摘要后，业务回调未执行且以account.witness_stale拒绝；不是原始真实认证入口已接入的证据。

物理来源固定目录身份、完整文件字节与文件名，256条分块排序、最多16路归并，内存不依赖全目录文件名数量。实际10000文件创建次序打乱，摘要与独立顺序生成的参考值相同，边界容量拒绝并清理私有临时文件。16MiB异常状态文件在8MiB PHP限制下先按元数据拒绝；64KiB合法值、NUL后字节、真实FileStore编码、文件／锁命名、符号链接／硬链接、权限及目录替换均覆盖。`negative/nul-truncation.log` 的真实退化代码退出255并触发Expected false, got true，证明NUL后字节不能省略。

初版文件输入测试把合法独立临时目录列为应拒绝，首次组合测试漏传持久化帮助方法的目录参数，均失败并修正测试，保留files-first.log及composite-first.log。两次初轮静态先后指出冗余类型判断，改用有界stream_get_contents并保留失败日志，未关闭检查。当前只声明本地私有FileStore，其他物理后端／TTL、宿主VARCHAR等SQL声明、真实完整认证备份、全部入口／请求前置权限与副作用边界、安全代际及独立强审批仍未完成，完整R1—R6保持进行中。

## 独立状态见证的强类型 SQL 来源（2026-10-18）

隔离候选 `/tmp/sosecurity-state-snapshot-y70ghjk4/acceptance.json` 已完成本阶段复验，未接入SDK。`matrix-final-report.json` 九版63条核心／语法命令全部退出0，九次共享SQLite数据摘要一致；`consistent-pages-final-report.json` 九组实际跨连接分页测试全部退出0，合计每版111项运行断言。精确1MiB正文保持可用，16MiB异常字段在8MiB PHP内存限制下拒绝；一万条记录按主键有界翻页，实际查询计划没有临时排序。263份冻结相关程序文件与 `final-source-before.json` 一致，主SDK252源码／211公开候选未增加此来源。

`mysql-final.py` 与 `mysql-consistent.py` 控制脚本实际终态0，共十组，两版各90项。八组核心使用 `/tmp/sosecurity-mysql-odlfg7wd`，两组分页使用 `/tmp/sosecurity-mysql-0m0e2325`，均为自建无TCP实例且目录已清理。MySQL要求显式REPEATABLE READ；独立连接在翻页间提交对已读行、未读行和新增行的修改，本次摘要保持原代际，下次摘要改变。SQLite使用现有BEGIN IMMEDIATE，独立写入连接先被锁拒绝，摘要提交后写入成功；不通过改变事务语义取得通过。

BLOB固定筛选值原按文本绑定会在SQLite静默漏选，`blob-filter-before.log` 保存初始失败；修正为按声明绑定BLOB，空值／NUL／非UTF-8选中行的变化会改变摘要，未选中行不影响。`blob-filter-negative.log` 通过准确旧源码映射再次触发预期255及 `Expected false, got true`，不是编译错误。原先54条／六组MySQL记录保留在 `before-blob-binding/`，不能作为修复后的快照使用。

初版分页测试误以为SQLite允许同时提交，九次均失败，保存在 `consistent-pages-before/`；修正测试后九次通过。首次静态命令路径不存在退出1，正确工具路径的PHP7.2目标level5检查退出0，日志还保留已安装可选turbo扩展因GLIBC不符无法加载的启动警告，分析本身无错误。当前仅有界SQL来源；组合物理存储、全部认证／修改入口、未知结果审批与安全代际迁移仍未完成，不代表完整备份防回滚、完整SDK或生产验收。

## 受控首次绑定与重新绑定候选（2026-10-18）

`/tmp/sosecurity-factor-enroll-n7ignuq7/acceptance.json` 确认782组选取检查通过，未接入SDK：九版最终 `enroll-selected/report.json` 729组、两版私有无TCP MySQL双后端最终52组及静态1组。每版九版父进程3247或3248项、10项实际旧读者子进程断言及16次候选源码／示例语法检查；新增首次绑定专项480或481项，差一项来自确认／取消争抢的允许胜出分支，不是失败结果被忽略。

九版初轮 `enroll-matrix/report.json` 保留729组中的5处PHP8.1—8.5测试接口兼容失败：EnrollmentJsonProbe.jsonSerialize没有返回类型，严格错误处理在继承JsonSerializable时终止，尚未运行输入处理。唯一改动是该测试方法声明:string，SDK／示例／共享辅助代码未变；`fixture-signature-before/delta.json`、`fixture-signature-final/report.json` 保留前后哈希及九版输入39项重跑。最终报告选取720组未受影响记录及9组修正记录，不篡改原失败。最终326文件与 `final-source.json` 核对，不能将整段开发过程描述为326文件从未变化。

MySQL主批次控制脚本退出0，52组覆盖两版各两后端的首次绑定11套和原正常操作／实际自身审批两套；测试方法修正后另建私有实例重跑四组输入，退出0。最终 `mysql-selected.json` 选取48组未受影响主批次及4组修正后的输入，各版本父进程1160—1162项、6项实际旧目录读者子进程断言。另有九版输入补充9组，合计13组补充执行；这些不额外增加782组最终唯一场景。主实例 `/tmp/sosecurity-mysql-72wyl3uu` 已停止且目录清理，输入补充实例也由控制脚本成功停止／清理。

新增正常40、取消37、尝试25、激活安全85、提交分类25、实际自身审批46、输入39、交接19、进程141或142、旧目录读者父进程7、最后回调意图16项。新增进程组九版SQLite和四种MySQL组合共13次，455个业务工作进程、143次实际SIGKILL；旧读者及fsync辅助进程另计。覆盖意图已提交但未创建槽位、物理准备后、pending提交后、尝试提交后、物理证明后、激活SQL及COMMIT前后、取消和清理前后中断；准备、确认及确认／取消各八进程争抢。结果只允许一次激活或持久取消，不产生孤立槽位认证权限，取消不会删除当前已激活因子。

新的准确一次性授权和新因子证明后，同PDO提交MFA标志／凭据版本／格式3 enrolled指针与完成通知。实际自身审批采用当前密码登录、准备与确认各一次近期密码重新认证／归属Grants，错误代际／操作编号／权威绑定拒绝；已有启用MFA不能走初始低强度路径。激活后旧密码会话失效，新登录要求已绑定TOTP；实际前一正常候选的current／adopt读取代码拒绝enrolled目录。禁用后重新绑定使用新独立槽位，不恢复旧adopt备用路径。

准备URI及恢复码不存SQL或自动重发；外部因子状态不属于SQL事务，SQL回滚后可能已经证明目标，目录仍不激活。显式新授权和新TOTP可继续，但仅返回空数组，旧恢复码无法重放；完成已提交后再次确认返回null。尝试计数先提交，随后在锁定的准确意图视图内执行有界外部证明和激活，防止其他尝试抢走行版本后消耗不可交付证明。预览过期、账号停用或缺失时，管理取消／清理仍可执行；retired不能由该正常流程恢复。

实际COMMIT回执丢失反例发现，reserved尚未赋值时原型报告sql.cleanup。准备意图、确认尝试及原正常操作意图保留阶段现有提交前就绪见证，明确报告account.completion_unknown；不以异常类别推断已成功，须检查签名意图／计数。`reservation-before/` 保存修复前源码／失败；`negative/report.json` 的一个修复前实现及两个刻意移除意图／清理复核的退化实现均退出255，后两者明确观察到不应发生的物理证明／删除，不计作正常通过。

初轮还曾用只捕获StorageException的测试帮助方法检查证明前的普通权限拒绝；修正为检查正确基类与精确原因，并补核对物理pending／enabled状态。历史日志保留。测试运行脚本第一次生成有一处括号语法错误，未开始执行，修正后启动；没有把该生成失败计为测试结果。

源码和辅助行为关联覆盖包括受管理正常操作、因子替换／退役／栅栏／回收／权威轮换／回执维护、共享Ledger、注册、双地址、邮箱恢复及MFA基础。所有所选任务终态，无活动句柄。新服务终态／过期／缺失意图的前置权限与public预算补核、旧原始认证／修改入口统一、活跃账号特权撤销、操作保留期／容量／未知流程管理、跨账号并发、独立恢复、正式通知／原生POST／CSRF／缓存／浏览器和SDK工厂／API／消费者／完整门禁仍需完成。未执行生产或本阶段正式SMTP／浏览器；没有完整R2.7或完整R1—R6完成结论。

## 正常MFA管理隔离候选（2026-10-18）

`/tmp/sosecurity-factor-operations-vsjcx42d/acceptance.json` 确认最终658组通过，未接入SDK：`operations-matrix/report.json` 九版621组全部退出0，312个相关程序文件SHA256保持，每版2767项父进程断言、7项实际旧读者子进程断言及15次候选源码／示例语法检查。包含共享Ledger、注册、双地址、邮箱恢复、因子替换／退役／栅栏／回收／权威轮换／回执维护的关联检查，不是完整SDK门禁。

新增正常操作专项每版433项：正常58、准确代际原子操作32、安全48、输入30、实际自身审批42、真实进程190、禁用目录12、最后意图12、权威交接9项。PHP7.2／8.5的私有无TCP MySQL、FileStore／独立MySqlStore组合共36组，每版866项父进程及6项实际旧目录读者子进程断言，控制脚本退出0；另有静态1组通过。最终实例 `/tmp/sosecurity-mysql-17v5k5e7` 已停止并清理，全部活动句柄终态。

三类正常操作各有五个实际SIGKILL检查点、同一签名预览八进程争抢。九版SQLite加四种MySQL组合共13组，累计507个业务工作进程／195次SIGKILL；实际旧读者和fsync辅助进程另计。验证prepared意图先持久化、提交前后SQL状态区别、恢复码只返回一次、账号版本／目录／通知与审计回滚，以及逻辑禁用提交后物理清理失败的显式恢复。真实自身审批使用当前密码、TOTP、近期重新认证、归属策略与一次性参数绑定Grants；准确自身转换后，禁用／恢复码轮换的旧会话失效，重加密会话保持。未测试不同账号及后台维护在COMMIT后并行推进的全部组合。

准确代际原子接口拒绝旧ID时不消费新因子证明；恢复码轮换拒绝TOTP重放并废除旧码，重加密后仅持新密钥的读取方可验证。重加密在两次存储访问之间若有正常时间推进和代际替换，旧实现使用捕获的旧时间会误报mfa.clock；修复使用当前时间校验并保留竞争者完整状态。原始源码／失败证据在 `cas-clock-before/`。

禁用使用目录格式3的disabled墓碑，区分从未绑定与明确禁用，阻止旧adopt重新采用尚未清理的旧物理因子；实际前一候选current／adopt读取代码在独立子进程中拒绝该格式。没有DDL变化，但旧读写进程必须显式停止，不能以租约到期推定停止。受控首次绑定及disabled重新绑定尚未实现，不能恢复旧采用入口作为备用路径。

最后审批／清理权限回调即使不改变账号，也可能同PDO重新封存操作意图；外部恢复码替换和物理清理前必须复核该行与根。旧实现曾先替换恢复码或先删除物理因子，再因SQL条件更新失败报告未知。四组修复前反例保存在 `negative-final.json`，均退出255；清理的额外 `intent-clean-physical-negative.log` 明确验证旧物理因子已被删除，不只比较异常类型。这些刻意失败不计入正常658组。

初轮测试曾误将已失效旧会话的Grants消费预期为返回null，实际是按契约抛出认证拒绝；篡改预览有效期时，越界会触发结构校验，测试改用范围内的签名篡改；撤权后读取管理状态也会拒绝，测试恢复管理权限再检查持久化状态。首次静态检查发现一个未使用闭包捕获，已移除。保留对应初轮日志，没有把这些中间结果计作最终通过。

签名历史意图在外层账本认证及权威重绑定后可检查；过期预览不能重新授权执行，历史内层预览签名不会阻止外层账本密钥轮换后的只读检查。外部原子因子存储和SQL不是一个事务，prepared状态不等于外部操作尚未发生；未知结果不自动退款证明、重试操作或再输出恢复码。操作保留期／容量清理、prepared显式处置、受控首次绑定与全部旧入口迁移、独立恢复、正式通知／原生HTTP／CSRF／缓存／浏览器及SDK接入仍需完成。没有生产、正式SMTP、完整SDK或完整R1—R6验收结论。

## 工作进程回执维护与回调后授权复核候选（2026-10-18）

`/tmp/sosecurity-factor-receipts-2c3etjg0/acceptance.json` 确认最终555组通过，候选尚未接入SDK。九版 `receipts-matrix/report.json` 的522组全部退出0，299个相关PHP文件哈希保持；每版2334项父进程断言、4项实际旧读者子进程断言及13次语法检查。覆盖共享Ledger、注册、双地址、邮箱恢复以及因子目录、替换、退役、栅栏、回收和轮换的关联检查，不等于完整SDK门禁。

两版私有无TCP MySQL使用FileStore／独立MySqlStore执行28组回执核心／安全／输入／实际独立操作员审批／进程／语义异常／撤权检查，另各一组真实签名1000条满额维护，共30组、每版744项父进程断言，控制脚本退出0。SQLite补充两版各12项满额检查及静态检查通过；满额拒绝不会先关闭活动权威，分页清理后轮换和工作流可恢复。只连接自行创建的本地测试实例，最终实例 `/tmp/sosecurity-mysql-eyq_06if` 已停止并清理。

新增回执进程组九版SQLite和四种MySQL组合共13次，累计312个业务工作进程与104次实际SIGKILL，覆盖清理／重封存的副作用前后及COMMIT前后中断、同一预览八进程争抢、审计与Outbox意图一次性。保留当前权威入站回执，即使已到期；重封存保留payload、owner、kind及created_at／updated_at／retire_at。正文分页50条85次SQL、选择读取50条137次SQL；16MiB异常字段在8MiB限制下拒绝。三个刻意退化实现（误删当前回执、审计后采集快照、逐条重扫历史）均退出255，记录在 `negative/report-final.json`，不计入正常通过组数。

实际反例确认最终预算回调可以撤销通用权限或独立审批；旧实现返回了已撤权预览，或提交回执删除／因子切换后才报告完成未知。最终顺序为预算、适用独立审批、当前通用权限及数据库事实复核，新增42项覆盖全部相关检查点；拒绝后通过独立连接检查实际账号／工作流／回执／审计和通知状态。旧源码与失败日志保留于 `late-budget-before/`、`approval-budget-before.log`；独立审批反例曾只预期旧完成未知异常，修复后为提交前明确拒绝，已调整测试以同时检查真实持久化状态，未把错误分类差异当作通过。

两轮中间快照分别保存在 `before-late-budget-*` 和 `before-approval-budget-*`；后一522组九版虽通过，但缺少新增独立审批反例，不能替代最终快照。确认追加缺口后主动SIGINT中断其MySQL，退出130，实例 `/tmp/sosecurity-mysql-t35g279a` 已清理，明确不计通过。最终快照对应的九版522、MySQL30、SQLite满额2及静态1组全部完成。未执行正式SMTP、原生HTTP／浏览器、生产或完整SDK门禁；完整MFA管理、独立恢复、SDK接入和完整R1—R6仍需完成。

## R2.7 邮箱丢失恢复SDK整合终态（2026-10-18）

`/tmp/sosecurity-mailbox-u_qp6jwd/acceptance.json` 汇总已接入SDK的邮箱恢复核心：230个源码、191类公开候选，原188类既有成员签名保持。主工作区187组检查全部通过，含九版各10个源码语法、191类API、每版275项新流程／强审批／故障／维护／投递／工厂及错误目标／用途授权检查，另保留旧账号工厂140项；230个源码静态通过。249个相关源码／测试／门禁文件在执行及后续MySQL期间哈希保持。

PHP7.2／8.5自建无TCP MySQL各通过265项，其中包括48个并发工作进程及提交前后两次SIGKILL；两版SQLite也各运行同样的48进程／两次终止，合计192个并发工作进程／8次SIGKILL。并发申请仅生成一组通知，确认仅完成一次；提交前终止保留原账号且已消费的测试审批不退款，需要新的显式审批；提交后终止保留实际地址变更和两份完成通知，重复调用不再次变更。

两版实际SQLite＋SMTP各4个场景通过，捕获邮件的收件地址、恢复路径和挑战摘要与源流程一致；发送前撤权不上传正文，服务器接受后撤权或回复丢失不完成自动地址变更。该组合使用测试审批实现；独立的真实组件组合使用操作员密码、TOTP及一次性操作授权，并在九版分别拒绝错误目标／用途的授权，不声称生产审批服务或真实收件箱验收。

两版全新Composer消费者从实际安装包调用 `mailboxRecovery()`，完成新邮箱证明、强审批阶段、地址及双版本推进，验证密码／角色／MFA等字段保留。发行归档363文件，全部源码入包检查通过。本轮未重新执行整库完整门禁、原生HTTP／CSRF／缓存／浏览器、生产或独立审查。

保留初次测试运行框架失败：SQL回滚用例尝试添加触发器，被既有安全表结构校验拒绝，随后改用测试PDO的语句故障钩子；投递用例重复加载测试bootstrap导致重声明，改为独立传输模拟对象；并发审批样例误调用不存在的FileStore.get，改用原子transact读取。均未降低运行时拒绝条件。隔离216组、可移植维护／API补充检查及接入后的187组分别保留。

新核心不移除或替换因子、不自动登录；独立强审批是必要条件，审批预览数据不能作为审批能力。因子替换编排、独立恢复／代际运维、原生入口及完整R2.7和R1—R6仍未完成。代码与测试仅在SoSecurity及自建本地临时环境中执行，未提交、推送、发布或部署。

## R2.7 通知投递SDK整合终态（2026-10-18）

`/tmp/sosecurity-mail-1vjjklzk/acceptance.json` 汇总接入后的主工作区证据：223组检查全部退出0，其中九版各15个源码语法检查、188类API、预算／领取／工厂／摘要基线与实际SMTP／SQLite组合；另含两版真实CLI、FileStore并发及独立Composer消费者，发行归档359文件。265个相关源码／测试／门禁文件在执行及后续MySQL检查期间哈希保持，227个源码静态检查通过；原180类既有公开成员签名保持。发行包另逐项核对全部源码及工作端文件确实入包，不把归档成功等同于发布。

九版各26个实际SMTP场景、各4个SQLite＋SMTP场景通过。主工作区PHP7.2／8.5分别在自建、禁用TCP的临时MySQL实例执行投递50、工厂纯构造／拒绝30、既有账号工厂140项，并各完成4个实际SMTP组合场景；实例正常停止。SMTP仅使用自有环回TLS或私有Unix接收端，证书与测试账号为临时数据；发送前撤权不上传正文，接受后撤权或回复丢失不自动重发，不证明真实收件箱送达。

两版实际CLI各4个投递场景、4种错误参数、4种不安全配置拒绝及导入无副作用通过。两版FileStore分别24进程竞争一个通知，仅一份发送许可；各在reserved、started、accepted、unknown四个阶段SIGKILL，只有正文开始前的reserved允许后续有界尝试，其余保留不确定／接受状态并拒绝自动重发。共享存储的生产恢复权威仍由宿主提供。

保留三类初始反例与修复证据：旧libcurl路径接受16MiB超长回复，改用受限协议流后拒绝；旧Claim／Message的普通导出展开领取秘密／正文，改为静态闭包状态并拒绝反序列化；候选整合后五版原8MiB工厂检查内存耗尽，密码基线改为逐项生成摘要，九版对照确认原7618条摘要完全一致，并通过固定摘要集和原工厂检查。原288组候选报告保留5项内存失败，独立45组修正检查及接入后223组均通过；测试运行框架未传环境变量等初始失败也未删除。

本阶段没有重新执行整库完整门禁、原生HTTP／CSRF／缓存／浏览器、生产、远端CI或独立审查。旧邮箱丢失／因子替换编排、恢复运维及完整R2.7与R1—R6仍未完成。未提交、推送、发布、部署或测试业务数据库。

## R2.7 密码恢复SDK整合终态（2026-10-17）

`/tmp/sosecurity-recovery-pkkyjcdp/acceptance.json` 汇总当前工作树：23组检查、108次语法及Shell／差异检查全部退出0，399个代码／测试／资源／门禁文件在执行期间保持且与当前哈希一致。九版180类公开API通过，原178类已有公开成员签名保持；219个源码PHPStan level5／PHP7.2目标通过。PHP7.2／8.5 SQLite各通过恢复163、维护52、工厂17、时钟8及实际并发27项，另通过既有账号工厂140／配置42项。每个并发专项包含72个实际工作进程及两次SIGKILL，不把两个后端的数量相互借用。

当前SDK可移植路径的PHP7.2自建无TCP MySQL专项已退出0，同样通过267项新检查及72进程／两次SIGKILL，实例正常停止清理；PHP8.5 MySQL属于前述同字节候选快照，未另计为本次根路径执行。两版全新Composer消费者从实际安装包调用recovery()完成当前邮箱证明、密码替换、原字段保留、旧会话及重放拒绝。发行归档结构检查通过，共350文件；529个文档相对链接存在。

最终时钟修复与回调后的预算复核均已写入SDK；初始程序反例、测试原因码预期错误及修正后的选取报告保留。以上是账号恢复专项，不是整库完整门禁或实际SMTP／HTTP／浏览器验收。该核心仍要求当前邮箱证明，旧邮箱丢失／因子替换的恢复编排、独立备份恢复运维、实际发送预算及原生流程继续，完整R2.7和R1—R6保持未完成。未提交、推送、发布、部署或测试生产库。

## R2.7 密码恢复候选与边界修复（2026-10-17）

`/tmp/sosecurity-recovery-pkkyjcdp/candidate-acceptance.json` 选取54组通过命令及108次语法，产品五个源文件在原检查及后续检查间逐字节相同。九版每版恢复163、维护52、工厂17、时钟／最终预算8项，另有旧配置42及旧工厂140项；两版自建无TCP MySQL每版240项。初始新时钟测试按内部原因期望account.expired，通用SQL预检回调实际按既有契约映射为sql.authority，原失败日志与报告保留；修正预期后只复验失败／未到达项，未更改运行时放行条件。不能把初始失败报告改称全部通过。

旧候选的两个实际探针分别接受了哈希后进入SQL前的时钟回退、提交权限回调拖过原请求预算，均实际改密并产生两条通知。对应 `clock-gap-before.json`／`budget-gap-before.json` 与 `before-clock-gap/` 留存源码；修复后的两份after.json均拒绝，原密码保持、挑战仍pending、只有原一条通知。修复关联SQL预检与外部观察时间，并把最终预算检查移到提交权限／审批之后，后续再复核当前事实。

修复后的PHP7.2／8.5两后端各72个真实并发工作进程及两次SIGKILL，共288进程／8次终止通过：同一申请不重复发送、同一邮箱证明只替换一次密码、同一真实恢复码仅消费一次且MFA保留；提交前进程死亡保留原密码，提交后死亡保留唯一消费与通知，重放不重做。仅使用自有临时数据库、共享FileStore和合成账号；首版并发证据另存，不替代修复后源码。

五个产品源文件、八份可移植测试文件及说明已写入SDK；180类候选中原178类公开成员签名保持，只向Security追加recovery()。当前根目录组合、实际安装消费者和发行包检查继续；无SMTP、原生HTTP／浏览器、完整SDK门禁、生产数据库或完整R2.7验收结论。

## R2.7 正式预算／工厂的SDK整合终态（2026-10-17）

最终记录为 `/tmp/sosecurity-account-budgets-xyp8ex9s/acceptance.json`：当前SDK的61组检查、90次语法及Shell／差异检查全部退出0，389个源码／测试／资源／门禁文件哈希保持且与当前内容一致。PHP7.2—8.5九版各通过新增预算172、真实SQLite组合134、工厂140项，以及原配置42项和178类公开API；两版还通过原核心、配置预设、Outbox／幂等／Webhook工厂和原注册／双地址／最终预算检查。217个源码的PHPStan level5／PHP7.2目标通过。

整合后的PHP7.2／8.5自建无TCP MySQL控制器已退出0，两版各通过真实组合134及工厂140项，实例正常停止清理；它只运行本阶段两项专项，不计作重新执行全部账号MySQL测试或并发矩阵。两版新Composer消费者从实际安装包使用正式共享FileStore预算及SDK工厂完成注册、真实密码／操作授权、双地址变更和旧会话拒绝；两份发行归档各347文件，包含新增预算类，排除开发及私有配置。523个文档相对链接存在。

既有177类的全部公开成员签名保持，仅新增RequestBudgets及四个原类公开方法。没有降低错误处理、跳过失败或把无SMTP的通知读取当作投递验收；未重新执行整库完整门禁、原生HTTP／浏览器、生产数据库、发布或部署。强恢复、恢复运维、租约SMTP／逐通知发送预算及完整R2.7继续。

## R2.7 正式请求预算与工厂候选纳入SDK（2026-10-17）

`/tmp/sosecurity-account-budgets-xyp8ex9s/validation/report.json` 的42组及63次语法检查全部通过，242个被测文件哈希保持。PHP7.2—8.5九版各通过请求预算172项、真实SQLite流程组合134项、工厂140项和原配置42项；PHP7.2／8.5另各通过既有注册199、双地址214、注册最终预算44项，确认六参数PHP用户回调兼容。候选七个源文件的PHPStan level5／PHP7.2目标通过；独立无TCP MySQL控制器退出0，两版各通过组合134及工厂140项，实际实例已停止清理。

候选新增RequestBudgets，修改Registration／AddressChange内部预算相关编号传递、Notifications结构校验，以及Security／Config／Inspector显式接入。预算覆盖站点／来源／目标／账号全局或作用域维度、逐调用相关性、配置漂移／重放／超时／时钟／后端拒绝及隐私；工厂检查当前依赖、不执行SQL、回调、Session或写入，实际密码／TOTP／一次授权完成双地址变更。未知自定义后端的持久性未由类型检查证明，诊断保留人工边界。

七个源文件和三份可移植测试已写入当前SDK，公开候选增至178类；逐项比较原177类全部已有公开成员签名保持，只追加四个公开方法。源码整合后的专项、安装包消费者与发行包验证继续，尚不计完整SDK门禁、实际邮件或完整R2.7完成。

## R2.7 SDK 核心两后端阶段终态（2026-10-17）

账号核心整合目录 `/tmp/sosecurity-account-core-integration-fpzor5o0/` 的 `mysql-budget.json` 已退出 0，267 个被测文件在执行期间保持不变。PHP7.2／8.5 自建无 TCP MySQL 各通过 961 项常规检查，随后各完成九场景、168 个并发工作进程及两次 SIGKILL；对应并发报告为 `/tmp/sosecurity-account-race-results-r01ez99g/report.json` 与 `/tmp/sosecurity-account-race-results-9szmip_3/report.json`。测试只使用自有本地测试实例，控制器已退出，未操作业务数据库。

同一预算修复后的 SQLite 已有九版 110 组与 252 次语法检查终态，八版每版 1127 项，无 Intl 的 PHP7.4 为 1123 项；两版规范并发共 336 个进程与四次 SIGKILL，通过的独立安装消费者实际完成注册／双地址变更及旧会话拒绝，两份发行包各 346 个文件。这些是选取的账号核心组合检查，未重跑完整 SDK 门禁，完整 R2.7 尚未完成。

历史维护候选 `/tmp/sosecurity-change-maintenance-x9k839rv/maintenance-mysql-validation/report.json` 也已终态，72 组命令全部退出 0，37 文件快照保持。它早于锁顺序及最终注册预算修复，单独保留，不能替代当前 SDK 的修复验收。下一阶段在 `/tmp/sosecurity-account-budgets-xyp8ex9s/` 验证正式请求预算和显式工厂／只读诊断；此候选尚未写入 SDK。

## R2.7 双地址真实并发及维护防恢复校验（2026-10-17）

已执行并通过：原双地址核心的 `/tmp/sosecurity-change-concurrency-vbyi7to2/acceptance.json` 汇总两版PHP各8个真实场景，共288个并发工作进程及4次SIGKILL，37文件清单一致并保持，208个共享SDK依赖保持。使用共享FileStore会话／授权／预算及独立PDO，覆盖两份证明、单授权消费、完成／取消两种确定顺序及竞争、两账号目标唯一性和提交前后终止。授权存储的已消费项在SQL回滚后不退款，实际重新认证与新授权后方可继续；仅SQLite与本地私有状态，不计MySQL竞争或实际邮件。

后续维护候选 `/tmp/sosecurity-change-maintenance-x9k839rv/` 增加有界清理及根／记录／信封／活跃内层收件标签轮换。首轮PHP7.2新维护95项和静态分析通过；首次静态发现的异常出口返回类型标注已补全，没有降低类型或忽略错误。旧地址候选的恢复测试按预期失败；旧注册实际探针报告删除4条但4条仍在，原源码、日志保留。新检查点及选中正文复核使管理回调恢复旧账本／篡改正文时拒绝并回滚。

新维护源码的并发复验随后取得终态：`/tmp/sosecurity-change-maintenance-race-jq0o_pt5/acceptance.json` 两版各9场景，336个并发工作进程及4次SIGKILL通过；39个被测源码／框架文件与208个共享SDK依赖保持。新增24进程同时清理只移除一次5条私有记录，保留宿主账号／密码及原3条队列记录；原八个场景在新源码重新执行，未借用旧结果。

该新源码的九版SQLite／无TCP MySQL检查仍在运行；不将前述核心快照或新SQLite并发算成MySQL竞争已通过。全部仍为隔离候选，未合入SDK；恢复运维、强恢复、公共工厂、租约投递／SMTP、原生HTTP／浏览器及消费者仍待交付。

## R2.7 双地址确认、强认证与条件变更核心（2026-10-17）

新候选 `/tmp/sosecurity-account-change-x8e_n3v6/` 新增AddressChange、IdentityRepository和ChangeDelivery，与原30文件权限候选分开。使用实际密码／TOTP认证、SessionRegistry及Grants：旧、新地址证明分别持久确认，最终还需新的明确操作授权；同PDO条件更新地址及凭据版本，保留密码／MFA，旧会话拒绝，不自动登录。通知意图同库提交，实际邮件未发送。

已执行并通过：`change-validation/report.json` 的73组命令及252次语法检查全部退出0，12个账号源文件／PDO示例静态分析通过，35文件快照保持。九版PHP的SQLite关联专项各976项，当前缺Intl的PHP7.4为972项；双地址专项每版均为214项。覆盖取消／重发／冷却／原截止时间、分别尝试上限、错误用途、旧／交叉证明、容量、唯一性冲突、密码哈希变化而版本未推进、当前权限改变、提交前回滚／提交后未知、历史安全通知与16MiB异常字段在8MiB PHP限制下拒绝。208个共享SDK／测试依赖也与原快照一致。

源码、单版初始日志、首次静态错误与修正记录及SQLite终态保存在 `/tmp/sosecurity-account-change-x8e_n3v6-reviewed/`。新九版私有无TCP MySQL矩阵在 `change-mysql-validation/` 继续；PHP7.2新双地址专项210项已通过，SQLite专用4项异常存储类检查不计入MySQL。不提前把在途矩阵计通过，也不把上一阶段每版600项的旧源码结果计入本轮。

此阶段未合入SDK，没有双地址真实并发／SIGKILL、该流程维护／轮换／恢复、原生HTTP／CSRF／缓存／浏览器、实际SMTP或独立消费者验收。操作授权存储与业务SQL分离，失败后不自动退款；后续强恢复和完整R2.7交付要求保持。

## R2.7 权限用途隔离与通知返回前复核（2026-10-17）

实现仍在 `/tmp/sosecurity-account-r27-hbk3mqa7/` 隔离候选，未合入 SDK：公开注册、管理和通知读取使用独立回调；管理／通知回调缺失默认拒绝。当前通知在权限回调后、提交前和完成时复核账号、挑战、当前指针、通知封存内容及期限，不能让回调中禁用账号或改变版本后仍返回旧敏感数据。初始化保持两个独立管理事务，拒绝队列初始化不会继续创建账号账本。

已执行并通过：`authority-validation/report.json` 的64组、207次语法及源文件／PDO示例静态检查全部退出0；30文件清单保持，208个共享SDK／测试依赖哈希保持。PHP7.2—8.5九版SQLite关联检查各762项，当前缺Intl的PHP7.4为758项，包含每版174项新增权限检查；不将依赖缺失当作国际域名成功流程。`authority-race-validation/report.json` 六组全部退出0：两版共288个真实并发进程、4次SIGKILL，覆盖申请、确认／取消、清理及提交前后终止，均只使用自建本地临时数据库和私有预算存储。

旧实现反例已执行并按预期失败：`authority-before/` 的公开宽松回调能初始化私有存储；`authority-notification-before/` 的第一版用途拆分仍缺少回调后的当前账号复核。对应旧源码、失败日志和当前源码／SQLite／并发报告保存在 `/tmp/sosecurity-account-r27-hbk3mqa7-authority-reviewed/`。新的 `authority-mysql-validation/report.json` 已终态：54组命令全部退出0，九版各600项，同一30文件快照保持；自建无TCP实例已停止并清理，报告补入独立复核副本。上阶段45组MySQL仍属于旧维护快照，未改计为新源码。

完整R2.7仍需双地址变更、强恢复、真实身份与预算接入、租约投递／本地SMTP、恢复运维、工厂／诊断、原生HTTP／CSRF／缓存／浏览器及消费者。回调分离与返回前复核不验证实际Outbox租约，不承诺发送过程中权限持续有效；实际邮件／生产／远端CI未执行。

## 因子恢复工作进程权威轮换隔离候选（2026-10-18）

`/tmp/sosecurity-factor-rollover-gvsn16hq/acceptance.json` 确认最终471组通过，未接入SDK。`rollover-matrix/report.json` 九版450组，每版1908项父进程断言、4项真实旧读者子进程断言及13次源码／PDO示例语法；`mysql-rollover.log` PHP7.2／8.5、FileStore／独立MySqlStore20组，每版448项父进程断言及4项旧读者断言；`rollover-static-final.log` 静态通过。全部任务已终态，私有MySQL控制程序正常退出并完成关闭／临时目录清理，最终289个相关PHP文件SHA256与运行前保持。

显式轮换以相同账号／目录epoch的新私有权威为目标，要求外部可信旧根和独立当前强审批；旧权威永久关闭，新权威共享锁保持到完成检查。准确HMAC封存回执、根绑定变更、审计及实际Outbox意图同PDO提交，保留工作流正文、原期限和宿主账号／目录。真实操作员密码／TOTP／近期重新认证／一次性Grants组合拒绝错误来源、目标及可信根；COMMIT回执丢失后通过准确回执明确重试，不重复审计，新根没有匹配回执时拒绝。

新增13组轮换进程每组78项，每组8个进程同时争抢同一转换，累计104个争抢进程；每组4次实际SIGKILL，累计52次，覆盖关闭后、根变更后及SQL COMMIT前后。连同矩阵中的原排空／回收回归组，共228个业务工作进程、106次SIGKILL、9次SIGSTOP／SIGCONT，另22个实际旧读者子进程；fsync辅助进程另计。准备中／已证明流程可继续，取消／退役状态保持；旧SDK实际Ledger类在轮换后拒绝格式2。

`capacity-before/failure.log` 和两份原源码保留最低`maximum_entries=2`策略回收、轮换后无法重用的真实反例；回执改存独立签名账本后，九版及MySQL均可完整重用两条工作流容量。回执账本固定上限1000条，满额拒绝，不自动删除，显式维护／轮换仍待完成。

65条含NUL／非UTF-8正文的完整校验在PHP7.2的8MiB进程中使用104次SQL查询。`negative/quadratic-final.log` 将实现退化成逐条完整回读后测得1599次查询，退出255；`negative/metadata-only-final.log` 去掉回调后的正文校验后，同尺寸正文改写未被拒绝，专项按预期退出255。两个失败反例不计作正常通过，证明元数据根和逐条重扫均不能替代有界完整校验。

仅使用本地测试数据库和合成身份；没有正式邮件、原生HTTP／CSRF／缓存／浏览器、生产或完整SDK验收。SQL回执不构成独立备份防回滚权威，仍依赖正确的外部可信根及不会随业务备份回滚的文件权威；独立恢复、回执维护、完整MFA及全部SDK／使用方门禁继续。详见[因子恢复设计](account-factor-recovery-design.md)。

## 因子恢复入口栅栏与有界容量回收隔离候选（2026-10-18）

`/tmp/sosecurity-factor-purge-_hsk7c1q/acceptance.json` 确认最终417组通过，候选未接入SDK。`purge-matrix/report.json` 九版396组，包括每版1681项父进程断言、实际旧读者子进程2项及13次候选源码／PDO示例语法检查；另有PHP7.2／8.5私有无TCP MySQL、FileStore／独立MySqlStore组合20组，每版450项父进程断言及4项旧读者子进程断言，见 `mysql-purge.log`；`purge-static-final.log` 静态通过。包括格式1账本、注册、双地址及邮箱恢复的共享账本回归检查，不等同完整SDK门禁。

恢复初始化、准备、证明、审批请求、确认、取消及清理七个入口在启用栅栏时持有共享锁，新的恢复根格式2绑定具体锁权威，实际主SDK旧Ledger读者拒绝。保留期后的 `drainAndPurge()` 在独占锁内、写关闭标记前再次授权；物理准确代际不存在后，同PDO提交回收通知意图及工作流／当前游标删除。较新游标、当前因子、不同代际和退役目录保持。遗留超期流程先独立授权取消；关闭状态不自动重新启用。

最终验证包含88个业务工作进程、70次实际SIGKILL、9次SIGSTOP／SIGCONT及另13个真实旧读者子进程；fsync辅助进程另计。覆盖暂停阻止排空、迟到准备被拒绝、关闭标记／物理删除／SQL COMMIT前后中断、幂等重试、部分完成和账号同版本实际密码改写回滚。`negative/no-entry-fence-final.log` 是去掉恢复入口栅栏后按预期退出255的反例，不能计作正常通过。

`invalid-label-before.log` 及 `input-review/LocalEpochFence-before.php` 保存非法UTF-8上下文导致TypeError的修复前证据；显式校验后的九版各25项确认非法编码／控制字符／超长标签在建文件前按配置异常拒绝，255字节中文标签可用。首轮MySQL旧读者测试遗漏原生预处理设置，失败记录保留于 `mysql-purge-before-native-reader.log`，没有把提前退出计为格式拒绝证据；修正后四组实际旧读者均通过。早期测试脚本的认证方法／返回值预期已修正，最终矩阵使用当前脚本。

全部任务终态，最终282个相关PHP文件与运行前SHA256保持；临时MySQL实例 `/tmp/sosecurity-mysql-as0q7o2u` 已退出并清理。仅使用本地测试数据库及合成账号；没有生产、正式邮件、原生HTTP／浏览器或完整SDK验收。单机本地栅栏仍须完成后继工作进程权威轮换、全部MFA修改入口与SDK工厂接入，不能以释放SQL条目代替完整生命周期交付；后续设计见候选 `next-worker-rollover.md`。

## 因子管理本地排空栅栏隔离候选（2026-10-18）

`/tmp/sosecurity-factor-fence-w3g20rc2/acceptance.json` 确认86组定向检查通过，未接入SDK。九版 `fence-matrix/report.json` 共81组：每版状态／持久化67项、真实进程43项、实际恢复组合14项和6次语法；两版私有无TCP MySQL、FileStore／独立MySqlStore组合四组各14项；候选源码／PDO示例静态通过。272程序文件哈希保持，全部任务已终态，私有实例已清理。

36个工作进程、9次SIGSTOP／SIGCONT、18次SIGKILL证明：暂停的共享持有者不能被租约或超时判为已排空；终止后可取得独占锁，关闭状态先持久化，再清理准确代际；关闭后的迟到TOTP准备被拒绝，清理中断可以重试。去锁反例明确退出255，见 `negative/no-lock.log`。PHP7.2—8.0测试通过同一打开inode的继承文件描述符执行实际fsync，PHP8.1起使用原生fsync。仅验证单机本地锁权威；强制入口接入、SQL容量回收、后继epoch及独立恢复继续，不能据此宣称完整R2.7完成。详细约束见[因子恢复设计](account-factor-recovery-design.md)。

## Outbox 防御性修复常规测试收尾（2026-10-17）

2026-10-18 当前源码定向复验：PHP7.2.34／8.5.9 的 `outbox-body-budget.php` 在8MiB限制下各626项、`outbox-input-bounds.php` 同限制下各50项、`outbox-hard-limit.php` 在32MiB限制下各8项，全部通过，每版合计684项。SQL字段投影按实际字节计数，正文先校验BLOB类型及长度；覆盖16MiB异常字段安全拒绝、NUL二进制往返、精确1MiB与多一字节输入、拒绝前无SQL／权限回调及失败后独立连接快照不变。本次保留现有修复实现，仅更新复验证据；以下较早记录保留各自执行时的断言数。

同轮 `python3 tests/mysql_check.py --outbox php72 php85` 已执行并退出0，18组检查全部通过，两版各1416项断言。实例禁用TCP，仅使用自建本地测试库；已停止进程并清理 `/tmp/sosecurity-mysql-12chsbbn`。日志保存在 `/tmp/sosecurity-outbox-local-recheck-20261018.log`。未执行生产数据库测试或完整SDK门禁。

2026-10-18 按本次字段读取／NUL／超限拒绝要求再次复验，现有修复实现保持不变：PHP7.2.34／8.5.9 的 SQLite 专项各666项通过，私有无TCP MySQL 关联专项各1416项通过，控制脚本退出0；本轮实例 `/tmp/sosecurity-mysql-7pfdfrag` 已停止且目录清理完成。未运行生产数据库或完整SDK门禁。

2026-10-18 针对当前代码再次执行本地复验：PHP7.2.34／8.5.9 的 `tests/outbox-body-budget.php` 在8MiB内存限制下各608项、`tests/outbox-input-bounds.php` 同限制下各50项、`tests/outbox-hard-limit.php` 在32MiB限制下各8项，全部通过。覆盖16MiB异常字段、NUL字节长度、实际存储类型、拒绝后独立连接快照不变、合法二进制正文及精确1MiB硬上限。

`python3 tests/mysql_check.py --outbox /tmp/sosecurity-sodium-runtime-akybbkwr/php72-isolated /usr/bin/php85` 已执行并退出0，两版各1416项通过，含结构依赖、核心、安全、对账、真实进程并发、输入边界、硬上限及索引检查。该运行自行创建禁用TCP的临时MySQL实例；结束后已停止实例并清理 `/tmp/sosecurity-mysql-wy6go5aa`。本次未修改修复实现，补充当前复验证据；未执行生产数据库或完整SDK门禁。

已执行并通过：`/tmp/sosecurity-outbox-final-ggn0evky/report.json` 的 39 组命令全部退出 0，413 个源码／测试／资源／门禁文件哈希保持。PHP7.2／7.3／7.4／8.0／8.1／8.2／8.3／8.4／8.5 九版 SQLite 每版通过字段／正文 428 项、输入边界 50 项和硬上限 8 项，共 486 项；新增测试的九版语法、Shell 和 Python 语法检查通过。PHP7.2／8.5 自建无 TCP MySQL 每版通过 1416 项，包含结构依赖、核心、安全、对账、真实进程并发、输入上限及索引历史；私有实例已正常停止并清理。

`tests/outbox-hard-limit.php` 将此前临时脚本的验收纳入仓库、`bin/check.sh` 及 MySQL 专项和默认流程：首尾含 NUL 的精确 1048576 字节正文原样往返；1048577 字节在 SQL／权限回调前拒绝，根记录与消息数量保持。该正向大正文测试使用 32MiB PHP 限制；16MiB 异常字段的安全拒绝继续独立使用 8MiB。既有输入检查还验证超策略拒绝不会提交或中止宿主事务。

本轮仅补齐测试及门禁接入，204 个 SDK 源文件与先前字段修复专项快照一致，比较记录为同目录 `sdk-comparison.json`。完整项目门禁未因本次测试接入重新执行；此处只报告实际执行的专项。数据库测试仅使用自行创建的本地测试库，未读取业务连接配置或操作生产数据库。

## R4.3 本地完整阶段验收（2026-10-17）

最终采用 `/tmp/sosecurity-key-export-a6rb_geg/r43-final-acceptance.json`：完整九版本终态及 37 项补充检查的选取日志均通过，使用相同 473 程序文件快照。补充项包括九版默认／独立权限源原生 TLS 各 318 项、独立终态协议每版 17 项、历史已验签数据在无 sodium 的运行时处理、九版全新消费者／归档／自有微型文件系统磁盘耗尽、SDK 与五个原生辅助文件静态分析，以及 PHP7.2／8.5 两类真实 TLS 移动 Chromium。

初次 `r43-supplement/report.json` 为失败，四项浏览器在加载 Playwright 前退出，原因是新编排未带上已有模块路径。四份原日志保留；仅设置 `SOSECURITY_PLAYWRIGHT_MODULE=/var/www/node/sodialog/node_modules/playwright`（实际版本1.58.2）后，`r43-browser-followup/report.json` 同源码四项全部通过，处理管理各622项及幂等各23项，未修改页面、SDK或断言。其他33项采用原始通过日志，不通过重跑整个集合掩盖失败。

327 文件本地复核归档的 SHA-256 为 `5c4c852e3d00bff76d04cd8b8b15aadca752dbd0e05ce9e06546d10009e71bec`，路径在 `r43-supplement/archives/`；`package-byte-audit.json` 确认全部 SDK 源文件存在，包内261个纳入程序快照的文件逐字节匹配，不包含 tests／vendor／demo。归档保存的是当时的源码和文档快照，后续维护记录可能继续更新；这不是发布、标签、Packagist或部署证据。

阶段按[逐项清单](r43-acceptance.md)验收。数据库、Redis、网络与CA均为本地自有测试环境，实际生产身份权威源、业务恢复／迁移互斥、生产灾备、远端CI和独立审查仍须宿主或后续阶段验证。R1、完整R2.7、R4.4—R4.6、R5及R6不因此关闭。

## 整合修复后完整九版本门禁终态（2026-10-17）

`/tmp/sosecurity-key-export-a6rb_geg/full-final/report.json` 的三组全部退出 0，PHP7.2／7.3／7.4／8.0／8.1／8.2／8.3／8.4／8.5 每版都有独立 `PASS full isolated matrix` 终态；473 个源码／测试／资源／门禁文件哈希保持。该快照包括字段／NUL 防御、私有安全表外键拒绝、Cipher／HmacKeys／AuditLogger 导出防护和精确到期测试，尚无隔离的 R2.7 新类。原 `bin/check.sh` 在私有 SQLite、自建无 TCP MySQL、Redis、本地 HTTP／TLS 上执行，并强制 Redis／HTTP／Reset／MySQL／Upload／POSIX／HTML／Crypto／Authority 标志；未降低条件或修改业务有效期来取得通过。

此前三组 MySQL 启动路径失败，以及另一快照的 PHP7.2 1 秒 TTL 断言失败仍按历史记录保留，不能改计通过。当前九版本结果只证明该快照的完整常规门禁；R4.3 额外的双模式原生投递／协议互验、浏览器、消费者／发行归档、磁盘耗尽与静态检查还须取得同快照补充终态，生产／远端 CI／独立安全审查仍未验收。

## R1.1 输入与业务逻辑条款责任映射（2026-10-17）

从固定 ASVS5.0.0 Git 对象读取 V2 原始文档，7100 字节及 Git blob 与既有固定目录一致，SHA-256 为 `70ad0f68df22ddd825c2837e74999fa026851e75a3128372307685e2bb526969`。逐项核对源码与现有证据后，[控制矩阵](security-control-matrix.md)新增 13 条映射；原始条款编号与矩阵一一对应、无遗漏或重复，七域共 108 条。范围包括业务组合校验、事务和资源条件更新，也明确多主体审批／人类时序判断尚无相应业务验收。这里只验证责任映射完整性，不能计作 108 项安全测试或 ASVS 等级认证。

## R2.7 注册／确认隔离候选（2026-10-17）

`/tmp/sosecurity-account-r27-hbk3mqa7/registration-validation/report.json`：19 组命令全部退出 0，九版 SQLite 各 199 项注册／81 项账本、九个账号源文件及实际 PDO 账号示例静态分析、135 次语法通过，19 个源码／测试／DDL 文件哈希保持。PHP7.2／8.5 的 `registration-race-*/report.json` 分别记录 24 进程同地址申请、24 进程同证明确认：一个初始无密码账号、一条验证通知，最终一次激活和一条安全通知，尝试上限 5；各自 18 文件清单保持。测试只使用私有 SQLite 和真实 SDK 文件预算，每个 PHP 进程限制 8MiB。

验证包括所有者确认时选择密码、错误／过期／重放／其他作用域、有限重发不延长期限、当前凭据／地址／角色／MFA变化、密码检查时实际无 SQL 事务、预算先于 SQL 的拒绝、账号更新／通知失败的同库回滚、坏字段及条件更新竞争。通知读取当前有权限检查，尚未实现租约验证或邮件投递；无 SMTP、HTTP／CSRF、浏览器、独立消费者或生产验收，候选未合入。

首轮流程在长期指针更新处失败，修复后仍保留挑战／通知的创建期上限；当前指针更新的保留上限单独绑定最后合法更新时间。另一个原候选的实际提交跨期探针返回成功，`completion-before-probe.json` 记录证明已过期而账号 active、通知两条且重放 false；现用例分别核对提交前回滚和提交后 `account.completion_unknown` 保留持久结果。两份旧源码／失败日志目录分别为 `-registration-first-source/` 和 `-registration-completion-before/`，不将原失败改计通过。

容量修复前的 `registration-mysql-validation/report.json` 已终态，九版无 TCP 私有 MySQL 各 199 项注册／59 项账本通过，共 18 组命令退出 0、19 文件清单保持，自建服务已停止并清理。两版最终并发报告为 `registration-race-final-72/`、`registration-race-final-85/`；`registration-kill-72/`、`registration-kill-85/` 的四个真实 SIGKILL 用例通过：提交前终止仅保留已扣尝试、账号及通知回滚，重启可以完成；提交后终止保留激活及两个通知，重启旧证明不能再次激活。对应 22 文件及报告副本在 `-registration-reviewed-v1/`。完整需求与剩余实现见[生命周期契约](account-lifecycle-design.md)；主 SDK 的完整门禁仍使用原 473 文件快照，另行取终态。

容量探针另外确认已有指针时多预留一条，导致 5 条容量尚有 2 个空位也拒绝换新。随后只修改一个预留表达式，`capacity-diff.json` 记录新旧文件摘要；当前 `capacity-validation/report.json` 的九版 SQLite 各 11 项、静态与 144 次语法，`capacity-mysql-validation/report.json` 的两版 MySQL 各 11 项通过，两个 20 文件清单保持。初版九版 199 项仍按旧快照记录，未混作容量修复后整合门禁。

## R2.7 内部事务账本隔离候选（2026-10-17）

`/tmp/sosecurity-account-r27-hbk3mqa7/` 后续增加账号快照、宿主适配契约和内部事务账本，并提供显式 SQLite／MySQL DDL；全部仍未合入 SDK。账号申请契约明确不在所有权证明前安装申请者选择的密码。完整状态机、宿主适配实现、请求预算、清理／轮换／恢复、SMTP 和原生流程继续，见[设计与剩余范围](account-lifecycle-design.md)。

已执行并通过：`ledger-validation/report.json` 的九版 SQLite 各 76 项、七个账号源文件的 PHPStan 和 81 次语法检查，`ledger-mysql-validation/report.json` 的九版私有无 TCP MySQL 各 53 项；两份 11 文件清单哈希各自保持。数据库均由测试自行建立，不读取业务连接配置，每个 PHP 测试使用 8MiB 内存限制。覆盖 SQL 元数据字节／类型限额、16MiB SQLite 异常字段、MySQL 大二进制正文、合法空／NUL／非 UTF-8 正文、CAS、容量、历史篡改和自有／宿主事务回滚。没有注册／邮箱变更／恢复／发送或浏览器验收结果。

首轮 MySQL 测试错误地要求超限参数抛出存储异常，实际为配置异常，九版均退出 255；修正该断言后重跑通过，未改动账本实现。原失败目录 `ledger-mysql-first-failure/` 保留；阶段复核副本 `/tmp/sosecurity-account-r27-hbk3mqa7-ledger-review/` 保存 12 个源码／测试／DDL 文件及两轮报告、日志，复制后哈希一致。主 SDK 完整门禁使用的 473 文件清单在本阶段仍保持。

## 通用密钥／审计导出防护与精确到期测试实际复验（2026-10-17）

`/tmp/sosecurity-key-export-a6rb_geg/` 已实现 Cipher／HmacKeys／AuditLogger 的隔离修复候选：私有密钥值改由静态闭包保存，标准 var_export 不展开原始字节；审计密钥和回调对象同样封装，日志字段／假名计算、签名与信封格式、轮换和公开方法签名保持。取钥前拒绝不符合新内部类型的状态，不将重建的原始字符串当作可调用目标执行。

候选 `report.json` 的 28 组命令全部退出 0，7 个候选 PHP 文件哈希保持。九版各 77 项导出／签名／轮换／不可变性及非法可调用状态检查、各 48 项独立 C API 密码学互验、各 166 类完整隔离源码树 API 契约检查通过；无 sodium 的真实 PHP7.2 另有 4 项 HMAC 签名／导出验证。三类 PHPStan 检查通过。PHP8.5 首次测试因已无效的 ReflectionProperty::setAccessible 调用发出弃用而失败，测试改为只在 PHP8.1 之前调用，未抑制错误。

原冻结矩阵已终态：PHP8.0—8.5 六版完整通过；PHP7.2 在已记录的 1 秒 TTL TLS 断言失败，PHP7.3／7.4 未执行到，471 源文件保持，不计九版通过。随后已将三类修复、两份回归和精确时钟测试写入工作树，`merge-report.json` 记录七个改动文件及其他原源码保持，类文件与候选相同；实际 PHP8.5 的 77 项、无 sodium 的 HMAC 4 项和 166 类 API 首验通过。`/tmp/sosecurity-key-export-a6rb_geg/postmerge-report.json` 实际工作树 50 组命令全部退出 0、473 源文件哈希保持：九版各 77 项导出与核心回归、各 48 项独立 C API 密码学、166 类 API，以及无 sodium 的 HMAC、两版完整 HTTP／TLS 各 437 项、消费者安装／归档／语法、SDK 与五辅助文件静态检查、两种 Outbox TLS 各 318 项。当前整合源码随后在该目录 `full-final/` 完成九版门禁，最终采用日志见本页首节；其他敏感值对象仍须 R1.2 逐一复核，不以三类修复代替全 SDK 导出审查。

隔离的 `idempotency_http_controlled.py` 保持 TTL=1、容量=1 和原拒绝断言；只有该边界用例使用私有受控 Clock 引导，明确核对首次创建时间、1 秒寿命和到期秒。`http-clock-report.json` 的 22 组全部退出 0、两份测试源码哈希保持：九版各 HTTP／TLS 精确边界检查通过，PHP7.2／8.5 的完整 HTTP／TLS 场景各 437 项通过。没有修改 SDK、生产配置、SQL 总预算或放宽有效期。测试入口随后已按可移植路径写回工作树；原失败完整矩阵不能因此改计通过。

## R2.7 基础隔离候选与新增导出缺口（2026-10-17）

本段记录后续账本编码之前的基础快照。四个账号地址／加密通知基础类仅在 `/tmp/sosecurity-account-r27-hbk3mqa7/`，尚未合入工作树。当时 `report.json` 的 13 组命令符合各自预期退出状态（包括强制能力拒绝的 255），8 个候选 PHP 文件哈希保持；八版各 140 项、缺少 Intl 的 PHP7.4 预设为 136 项，均使用 8MiB 限制及自建私有 SQLite。18 组独立 JSON／libsodium C API 互验、72 次语法及四类 PHPStan 检查通过；这些不是完整注册／邮箱变更／恢复／发信验收，见[设计与剩余交付](account-lifecycle-design.md)。

首版基础绿灯之后，两版实际 var_export 探针确认地址、通知令牌和嵌套密钥展开；历史代码和 `export-before.json` 在同名前缀的 `-export-gap/` 目录保留。新导出回归执行旧候选按预期退出 255，最终闭包封装候选通过九版检查；不以旧基础测试通过掩盖缺口。无 sodium 的 PHP7.2 只有 77 项非加密检查，加密明确未执行，强制能力时拒绝；禁用两个验证函数的 PHP8.5 拒绝检查通过。

另对当时 SDK 的 Cipher／HmacKeys 直接 var_export 进行了本地测试数据探针，`-export-gap/core-export-before.json` 两项均确认私有密钥会展开。该缺口随后已按上节修复并完成实际工作树专项，其他敏感对象仍须复核；__debugInfo 对 print_r／var_dump 的保护不能代替 var_export 保护，尚未声称全 SDK 导出安全。

完整矩阵 `fixed-full-matrix-short/` 的 PHP7.2 组在 1 秒 TTL 容量 TLS 用例首次请求预期 201、实际 409 处失败；原日志未保存 error 字段，不能事后断言同一次响应的具体原因。该轮最终 PHP8.0—8.5 六版通过，PHP7.3／7.4 未执行到；不能计九版通过。独立私有 SQLite 的真实业务 SQL 延迟可复现提交后 `idempotency.expired`，业务及唯一记录各保留一条，原键不重执行业务；初次额外探针误断言必须回滚为零，已按现有提交后到期契约修正并保留原失败。这不是超限输入拒绝或 SQL 失败回滚的同一语义。

为容量／到期断言准备了隔离测试运行框架候选：仍用 1 秒策略，私有时钟冻结首次执行，再精确前进到到期秒；不改 SDK 或生产入口，也不放宽断言。首次仅自动前置脚本未作用于内建服务器路由，创建时间断言失败；随后路由私有引导又曾选错时钟文件，已纠正。随后九版 HTTP／TLS 精确边界及两版完整场景全部通过，测试入口之后已合入，详见上节；原冻结矩阵的失败记录保留。

## 共享私有 SQL 表外键防护合入与实际入口复验（2026-10-17）

已将四个共享／Webhook 独立校验源文件、正式依赖测试及门禁写入工作树。类文件与隔离候选逐字节相同，`dependency-merge-report.json` 记录七个文件哈希及其他原源码保持；规范 DDL、公开 API 和状态格式不变，新增严格拒绝私有表的入站／出站外键。MySqlStore 构造与每次自有事务均检查，关闭外键执行也不能绕过；业务之间的独立外键仍可用，既有非规范关系须明确迁移。

### 已执行并通过

- `dependency-formal-report.json`：九版 SQLite 各 338 项、PHP7.2／8.5 私有 MySQL 各 360 项正式依赖回归，候选哈希保持。覆盖七张私有表、双向外键、执行开关、组件／宿主事务回滚、SQLite main／TEMP 遮蔽及真实业务子行保留；移除测试关系后正常清理恢复。
- `dependency-regression-report.json`：九版各 14 组既有 SQL 模块及真实子进程检查，共 126 组全部退出 0，492 个当时纳入清单的文件哈希保持。`dependency-regression-mysql-report.json`：PHP7.2／8.5 的既有 MySQL 模块、24 进程、真实 SIGKILL 和事务所有权检查通过；该关联检查预载的四个类与合入文件相同，不冒充完整工作树矩阵。
- `dependency-postmerge-report.json`：实际工作树 30 组命令全部退出 0，471 个源码／测试／资源／门禁文件哈希保持。包括九版 SQLite 各 338 项、九版 166 类公开 API、两版各 380 文件语法、全新 Composer 消费者和 327 文件发行归档，以及 SDK／五个原生辅助文件静态分析。新 `--sql-dependencies` 实际入口在私有无 TCP MySQL 上通过 PHP8.5 的 360 项，未使用候选预载。
- 工作树实际 TLS：PHP8.5 默认／独立权限源 Outbox 各 318 项、PHP7.2 Webhook 处理 589 项及 PHP8.5 幂等 433 项通过；使用独立数据库、进程私有 CA／网络，不改变宿主信任或执行外部业务投递。

### 反例与验证边界

原实现的真实级联反例保存在 `sdk-foreign-key-before.json`，业务子行从 1 变 0；原工作树执行新正式 SQLite 回归按预期退出 255，见 `dependency-formal-baseline.log`。修复后的正式回归在删除前拒绝，保留业务子行／根和外键开关；不是仅以源码存在或正常 DDL 绿灯代替拒绝验证。

最初预载运行框架缺少接口与资源映射，以及直接临时路径被 API 校验器排除的问题均单独保留。完整隔离源码树／类映射后九版 API／候选语法共 54 组通过，随后实际工作树 API 也通过；没有改写公开契约来消除失败。

修复前 PHP7.2 完整门禁及其余八版完整矩阵均退出 0，原 470 文件哈希保持，见 `preflight-report.json`／`remaining-report.json`。修复后的完整九版矩阵首轮 `fixed-full-matrix/` 三组均在 MySQL 启动前置阶段退出 1，尚未进入 SDK；原 471 源文件保持。受控保留日志复现同类目录设置，`startup-failure-analysis.json`／`startup-proof/server.log` 记录套接字路径 125 字节，MySQL 明确拒绝超过 107 字节；自建失败数据库已确认停止、保留日志后清理。仅把自有临时运行目录移到较短的 `/tmp` 路径，源码、九版运行时、必需标志和断言均保持；重新执行的三组见 `fixed-full-matrix-short/`，尚未取得全部终态，不计为通过。两种源码与针对性复验分别记录，完整 R4.3／R1—R6 继续。

全部数据库仅为本地临时库。MySQL 查询只覆盖当前账号可见的依赖，部署者仍需完整 DDL 审核与迁移互斥；没有生产、远端 CI、公开发布／部署或独立审查结论。R2.7 [账号生命周期契约](account-lifecycle-design.md)仅为设计稿，编码与流程验收待完成。

## Outbox 字段读取、NUL 与超限拒绝专项复验（2026-10-17）

本次仅复核现有工作树中的字段／正文防御性修复，保留其他在途修改，没有扩大为完整 R4.3 或 R1—R6 验收。

共享 SQL 外键防护及密钥／审计修复合入之后，使用当前整合源码再次执行同一专项：`/tmp/sosecurity-outbox-current-otm2b3z7/report.json` 的 28 组命令全部退出 0，473 个源码／测试／资源／门禁文件哈希保持，并与在途完整门禁的源码清单一致。九版 SQLite 各 428 项字段／正文、50 项输入边界及 7 项精确硬上限通过；PHP7.2／8.5 私有无 TCP MySQL 各 50＋7 项通过。异常读取专项使用 8MiB，精确 1MiB 合法正文往返单独使用 32MiB；1048577 字节在 SQL／权限回调前拒绝。自建 MySQL 已停止并清理，未读取或修改现有业务库。完整九版门禁仍另行记录，不将此专项计作全部通过。

已执行并通过：`/tmp/sosecurity-outbox-bounds-review-t_hjl2zy/report.json` 的 28 组命令全部退出 0，492 个源码／测试／资源／门禁文件哈希在验证期间保持一致。

- PHP7.2—8.5 九版各通过 `tests/outbox-body-budget.php` 的 428 项及 `tests/outbox-input-bounds.php` 的 50 项检查，均使用私有临时 SQLite 数据库、`memory_limit=8M`。覆盖逐字段 SQL 投影上限、SQLite 存储类型、16MiB BLOB／NUL 前缀或中间含 NUL 的 TEXT，异常不会作为截断后的合法数据继续使用。
- 合法空正文、首尾／中间 NUL、非 UTF-8 字节及按字节计数的多字节文本保持原样；旧版 PDO SQLite 的空 BLOB 表示只在 SQL 已证明真实类型和零长度后规范化。超策略输入在 SQL 和权限回调之前拒绝，队列／根保持，已开启的宿主事务仍能由宿主明确提交。
- 补充独立脚本 `hard-limit.php`：九版各 7 项，实际入队／领取／确认首尾含 NUL 的精确 1048576 字节正文，验证摘要与字节数一致；1048577 字节在构造时拒绝，不触发查询或权限回调，不增加队列记录。该正向大正文往返单独使用 `memory_limit=32M`，不混作 8MiB 异常读取检查。
- 使用仓库测试预设环境的私有 MySQL 启动器，在独立临时目录初始化、禁用 TCP、不读取宿主凭据，并在结束后停止和清理。PHP7.2／8.5 各通过输入边界 50 项及精确硬上限 7 项；没有连接现有业务数据库。

本次专项没有失败或跳过的命令。未执行生产数据库、远端 CI、发布或部署；共享结构外键缺口仍按下节单独跟踪，本次字段边界通过不关闭该问题。大字段预算限制 PHP 返回数据，不能据此声称数据库引擎内存或总 RSS 同样受限。

## R4.3 完整门禁与共享结构缺口复核，进行中（2026-10-17）

- 本轮补齐 [R4.3 验收清单](r43-acceptance.md)，工作流改用私有 MySQL 全矩阵，显式要求 SQLite3／独立权限源，并追加双模式原生 TLS、终态协议互验及五个辅助文件静态检查。已解析 CI YAML 核对九版矩阵与必需标志；没有运行远端 CI。
- `/tmp/sosecurity-r43-stage-e2bx2uxl/preflight-report.json` 记录 PHP7.2 完整 `bin/check.sh` 在自建禁用 TCP 的 MySQL、私有 SQLite／Redis 上通过，470 个 SDK／示例／测试／资源／门禁文件哈希保持。其余八版分两组完成，日志为 `full-73-81.log`、`full-82-85.log`，`remaining-report.json` 两组均退出 0 且原 470 文件哈希保持；该完整九版结果属于合入外键修复前的源码。
- `extras-report.json` 的 38 组追加检查全部通过，原快照哈希保持：九版默认／独立权限源 TLS 各 318 项、独立终态协议互验各 17 项、独立消费者／发行归档、真实微型临时文件系统 ENOSPC，以及无 sodium／无在线提供器密钥的真实已验签历史处理。Composer 配置与锁定依赖审计、SDK／五个辅助文件静态检查通过；保留的本地审阅包包含新验收文档，不表示公开发布。
- `browser-report.json` 的四组 PHP7.2／8.5 真实 TLS Chromium 检查通过，覆盖处理管理的密码／TOTP、CSRF、失败重试与退出，以及幂等提交／重放／业务唯一约束、无凭据持久保存。截图已查看，恶意样式消息编号以文字显示、凭据字段遮蔽，390px 无页面横向溢出。均使用独立测试账号与数据库。

合入前结构复查确认共享缺口：通用 SDK 的队列表被业务表通过级联外键引用时，消息维护会同时删除业务行。PHP7.2／8.5 本地真实 SQLite 对照均从 1 条业务子行变为 0 条，见 `sdk-foreign-key-before.json`。此前的原生审计外键防护不能证明通用 SDK 已防护，完整正常结构门禁即使通过也不能关闭该问题。

合并前候选记录：当时共享校验候选仍在该目录的 `dependency-candidate/`，尚未替换工作树中的 SDK。最初九版 SQLite 各 9 项／两版私有 MySQL 各 11 项的原型检查之后，已补齐覆盖七张私有表的正式回归候选；Webhook 接收／处理原来使用独立校验，候选也分别补齐。`dependency-formal-report.json` 十组命令全部退出 0 且候选哈希保持，九版 SQLite 各 338 项、PHP7.2／8.5 私有 MySQL 各 360 项，覆盖双向外键、关闭执行、组件／宿主事务回滚、真实业务子行保留、复用存储对象和 SQLite 结构查询遮蔽。原工作树执行同一 SQLite 回归按预期退出 255，不能通过缺少拒绝的旧实现，见 `dependency-formal-baseline.log`。

四个候选源文件的 PHPStan 检查通过。直接预载临时路径会被 API 校验器的工作树路径过滤排除，初次 API 检查因而失败；改用完整隔离源码树及显式 Composer 类映射后，PHP7.2／8.5 的 166 类公开接口契约通过，没有修改候选契约文件。较早原型运行框架缺少接口加载和资源映射的问题也已修正，均不混作产品修复结果。随后九版既有模块／子进程共 126 组及原版本完整九版矩阵均通过；候选已按相同字节合入，当前实际入口复验见本页最新记录。

原版本矩阵及隔离候选使用不同的源文件快照验证，不能混作修复后完整矩阵。继续共享结构整改和剩余门禁，不关闭 R4.3 或完整 R1—R6。全部数据库均为本地临时库，未操作生产或发布／部署。

## Outbox 独立权限源、业务备份恢复与组合授权（2026-10-17）

### 已执行并通过

- `/tmp/sosecurity-outbox-authority-i6iihwo0/final-composite/report.json`：最终 66 组命令全部终态 0，469 个源码／测试／资源文件执行期间及完成后哈希一致。PHP7.2—8.5 九版各 1119 项 SQLite 关联检查：原生适配 66、独立权限源 152、接收恢复 342、签名对账 279、归档 219、审计结构 61；均在独立 8MiB PHP 内存进程使用自有临时库。
- 独立权限源覆盖实际旧业务文件恢复后的账号禁用／版本／角色、路由和拥有者撤销，队列及接收根不采用本地旧权限；已知最后转换在当前撤权时拒绝重放，明确重新授权后恢复一次。实际只读连接拒绝写入，权限源锁等待有界；文件缺失／替换、配置变化、别名、重复身份和 16MiB NUL 元数据均有拒绝检查。删除业务库权限行后，实际签名终态、发送审计和管理 CLI 继续使用当前独立来源。
- 每版另有三个真实权限写进程，分别构造发送双角色、接收双角色、处理角色与对象关联的交替状态。每次提交都缺少一项必需权限，每类连续 1000 次决定全部拒绝；确认写进程确实前进且正常退出，完整授权恢复后允许。不是用模拟对象或始终拒绝来证明并发安全。
- PHP7.2／8.5 的默认模式、独立权限源模式实际 TLS 各 318 项通过，包含真实生产／工作／HTTP 接收、当前撤权、独立检查点、24 并发请求与工作进程 SIGKILL。新模式先删除业务库权限行，确保实际请求没有改查旧表。九版独立协议互验各 17 项、两版新 Composer 消费者、325 文件发行归档、166 类 API 契约和 379 文件语法，以及 src／五个原生辅助文件的 PHPStan 检查通过。
- 实际启用前的旧辅助源码逐文件校验后执行：两版各 6 项证明旧配置可读，新权限源字段被旧代码明确拒绝，根／检查点与业务条数不变；来源见 `legacy-config-source.json`。缺少 ext-sqlite3 时，两版各通过 2 项能力拒绝和原生适配 66 项，生命周期明确未执行；强制要求扩展则预期退出 255。PHP7.2 缺少 sodium 时独立权限源基础通过 127 项，签名集成明确未执行；强制密码学依赖则预期退出 255。补充终态为 `supplemental-composite-report.json`，预期依赖拒绝不计入签名生命周期通过。

### 初次发现、失败及修复

初期实际反例确认：原业务库禁用拥有者后拒绝请求，但恢复旧业务文件会带回启用状态并接受新业务。可选独立权限源使权限恢复顺序与业务备份分离；省略配置时保持原模式，不能据此声称原业务权限表已经具备防回滚能力。

第一轮 `final/report.json` 的 66 组检查和 468 文件快照通过后，额外并发检查发现双角色分别读取会拼接不同权限版本。留存的真实初版源码在同一新增测试中，PHP7.2／8.5 各 1000 次判断分别错误允许 17／14 次并按预期失败，见 `composite-old72.log`、`composite-old85.log` 和 `composite-regression-report.json`。最终将所需角色、版本及对象关联合并为一条查询；第一轮绿灯不作为该并发问题已解决的证据。

新增关联并发测试又暴露 SQLite3 空结果被继续读取时可能重置并在新状态重新执行，最小真实例子可得到首次无行、更新后再次读取出现行；最终只在首次已有行时检查重复结果。PHP7.2 的 PDO 只读标志／URI 探测不支持本机该构建，选择标准 SQLite3 OPEN_READONLY 并明确可选扩展依赖，未更改系统运行时。初次签名集成测试误把既有导入状态数组当作布尔，按现有接口契约修正断言；没有更改该接口返回值。

本轮只验证本地权限测试源与原生接入，没有接入真实身份发行方或操作生产数据库。SDK 源码／核心 DDL 未变，本轮未重复 MySQL 核心矩阵；上一阶段私有 MySQL 证据按其快照保留。权限源自身时效／恢复和跨库并发窗口由宿主承担，全部来源共同回退仍需外部权威基线。完整 R4.3 阶段门禁及其他 R1—R6 要求继续，未发布、部署或完成独立安全审查。

## Outbox 读取边界、审计归档与结构防护最终复验（2026-10-17）

### 已执行并通过

- `/tmp/sosecurity-outbox-archive-final-ta7jkx7k/report.json`：138 组命令全部终态 0，465 个源码／测试／资源文件验证期间哈希未变；完成后再次逐文件核对一致。九版 PHP7.2—8.5 各 2461 项私有 SQLite 关联检查，均在独立 `memory_limit=8M` 进程运行，包含字段／正文边界 428、输入边界 50、归档 219、归档元数据预算 11、审计结构依赖 61 和索引分页 7 项。
- PHP7.2／8.5 禁用 TCP 的独立本地 MySQL 各 1048 项通过；九版独立 Ed25519 协议互验各 17 项、两版本地实际 TLS 各 318 项、全新 Composer 消费者、322 文件发行归档、166 类 API 契约和 376 文件语法检查通过。PHPStan 检查 src 及四个原生辅助文件通过；不是整库完整门禁或生产验收。
- 同库归档保留已接受的完整原证据和公钥快照，队列清理后再迁移，两个成员集合与审计根同 PDO 提交。验证容量释放、在线／归档重封存、旧密钥退役、故障回滚和 COMMIT 前后真实 SIGKILL。十万条归档容量测试明确使用未认证的合成元数据，未封存或采用为合法历史；一万条队列测试使用已封存合成记录，不代表真实远端业务。
- 额外使用上一阶段留存且逐一核验哈希的实际旧辅助源码，PHP7.2／8.5 各 10 项证明旧审计根可读，升级后旧解析器拒绝格式 2 且不改写根或归档记录。无 sodium 的 PHP7.2 普通原生适配通过 66 项，终态功能通过 3 项明确拒绝检查并标记生命周期未执行，归档标记未执行；要求 sodium 时按预期退出 255。补充结果保存在 `supplemental-report.json`，预期能力拒绝不计入主矩阵的成功生命周期覆盖。

### 已确认反例、修复与边界

首批归档矩阵 `/tmp/sosecurity-outbox-archive-results-0e4swns0/` 的 56 组检查通过后，额外本地外键反例发现：归档删除在线审计行会将引用它的业务子记录从 1 条级联删除为 0 条。修复后 PHP7.2／8.5 对同一结构均在删除前拒绝，业务子记录仍为 1 条，审计根不变、外键执行开关保持；前后对照为该目录的 `foreign-key-counterexample.json`。当前九版结构测试进一步覆盖入站／出站外键、关闭执行时仍拒绝、大小写、main 查询与同名对象遮蔽，并允许无关业务外键。该修复属于原生审计表结构防护，不宣称通用 SDK 所有 SQL 依赖均已审计。

实际查询计划另确认按有界投影的同名别名排序会反复创建临时排序树；改为明确限定的原表主键后，当前归档及 SDK 历史分页不再临时排序，字段读取上限保持。当前执行计划测试同时证明旧排序方式会创建临时排序树。

全部数据库仅为本地临时私有测试库；8MiB 是 PHP 分配限制，不是数据库引擎或总 RSS 上限。未操作生产数据库、发布、部署、远端 CI 或独立安全审查。权威旧备份恢复对接、完整 R4.3 及其余 R1—R6 要求继续，不能以本次专项通过关闭完整规划。

## 原生 Outbox 签名终态、持久取消与审计闭环（2026-10-17）

### 已执行并通过

- `/tmp/sosecurity-outbox-terminal-results-tt895a8x/report.json`：38 组检查全部终态 0，459 个源码／测试／资源文件验证期间哈希未变。九版 PHP7.2—8.5 各 279 项原生对账、342 项接收恢复、66 项原生适配；每版合计 687 项，均在 8MiB PHP 内存限制下使用自己创建的私有 SQLite 文件。
- 对账专项使用实际 Ed25519 密钥、已接收业务账本和持久取消两条链路。验证站点／作用域／生产者／事件／正文／投递／挑战／epoch／目的端绑定、错误及过期签名、当前角色／版本／禁用和历史归属、原始证据幂等／冲突、线上公钥移除后的已封存历史查询、清理保留审计及缺失审计拒绝。16MiB NUL/TEXT 审计字段在受限内存下拒绝，SQL 字段投影和正文读取上限继续保持。
- 实际 CLI 完成导出、未知事件不能签发、显式取消、证据导入及状态查询；非私有输入文件拒绝。新增示例增量 DDL 在已有业务表上实际执行后，保留原订单／接收根，并完成签名对账。
- SQL 语句及 COMMIT 前／后故障证明审计和队列同时回滚或持久提交。接收取消在 prepared、业务未提交、业务已提交和检查点已提交四阶段，发送审计与处置在 COMMIT 前／后两阶段，均对确认仍存活且 PID 匹配的自有子进程实际 SIGKILL、回收并重连核查；旧备份受控恢复保留取消栅栏，部分删除取消记录拒绝自动确认。
- `tests/outbox_resolution.py` 九版各 17 项独立 Python／Node22.14.0（OpenSSL3.0.15）对照：独立重算业务事件／投递编号、原指纹、正文和业务根摘要，Node 验证 PHP/libsodium 签名、错误域拒绝，再独立签名并由 PHP 验证。该互验是协议与密码学原语对照，不是独立安全审查。
- PHP7.2／8.5 实际 TLS 各 318 项、新 Composer 消费者、319 文件归档、166 类公开 API 契约及 371 文件语法检查通过。消费者使用已安装的原生辅助文件实际签发／验证已接收证据并初始化审计；完整收发、私有 DoH／IP pin／进程 CA、确认丢失及工作进程 SIGKILL 分别由 TLS 测试覆盖。PHPStan 对 src 和三个原生辅助文件通过。
- 另用上一阶段实际保存并通过哈希核验的旧 `outbox-business.php`／`outbox-recovery.php`：两版各 8 项证明旧代码生成的格式 1 接收历史可被新代码读取并签名处置，各 7 项证明旧代码拒绝含取消的格式 2 根且不改写业务根／检查点。旧解析器源码哈希及过程保存在 `legacy-source.json`、`legacy-compatible-results.json` 和 `legacy-results.json`，不是构造一个假想旧解析器。

### 初期诊断与边界

原生动态权限函数的初次静态分析将重复读取视为纯函数，按实际数据库读取副作用标注后通过，没有关闭规则。独立验证环境探测发现 Python cryptography 未安装、系统 OpenSSL1.1.1 的 pkeyutl 不支持 rawin，首轮命令失败；最终使用本地 Node 自带 OpenSSL 完成双向验证，没有更改系统 OpenSSL 或安装运行时依赖。

38 组快照完成后，最后发现可选 sodium 的测试入口需与既有框架保持一致，因此仅修改 `tests/outbox-resolution.php` 的能力分支。PHP7.2 无 sodium 时通过 3 项明确拒绝断言并将签名生命周期标记“未执行”，普通原生适配仍通过 66 项；`SOSECURITY_REQUIRE_CRYPTO=1` 时明确失败。含 sodium 的九版各 279 项重新执行通过，其他 458 个源码／测试／资源文件哈希与主快照一致，补丁及复验见 `capability-overlay-source.json`／`capability-overlay-report.json`；不能把主快照说成测试入口最后一次修改后的同一快照。

本轮仅为本地候选阶段证据。没有操作生产数据库、发布／部署、执行远端 CI 或独立安全审查；没有把本地测试权限表视作真实发行方。全部数据库及外部锚点共同回退仍需宿主权威恢复基线；权限表恢复须从当前权威来源重新核对。审计受控归档、权威旧备份恢复对接、完整 R4.3 门禁和其他 R1—R6 要求继续，不能因本轮 38 组通过就关闭完整规划。

## Outbox超期对账核心与封存格式2（2026-10-17）

### 实现与兼容边界

- 向现有SqlOutbox追加reconcile、向Status追加resolution，逐项比较原166类其他既有成员签名保持。原始Message、终态received／cancelled及证据摘要绑定，每次显式传入当前决策guard，另需当前管理权限；只有超过恢复期且正文已退休的dead意图可加入宿主审计事务转换为独立resolved状态。true仍待宿主COMMIT，sent_at保持0，旧领取失效，后续聚合解除阻塞；保留期后清理逐条检查current／commit权限并保留宿主审计，原事件过期及顺序高水位保持，见[对账核心](outbox-reconciliation.md)。
- 首次处置将对应记录／命名空间封存format推进为2，无DDL变更；旧进程须先停止，不能回退代码或手改format。保留的旧版State解析器SHA为d8b3b7d6464af6c78207d3e44e90adcd56d20d5bb2a68710fccaf5adb4fc2979，两版独立旧解析进程实际拒绝新格式，根版本／修订／摘要保持；这是旧解析器的运行证据，不冒称旧应用完整部署验证。
- 本阶段核心测试使用合成审计决定和可控时钟，真实PDO、独立观察连接、实际事务／锁及子进程；没有据此宣称远端签名证据、接收取消栅栏或原生对账命令闭环已完成。MySQL审计测试表为InnoDB，SQLite为私有持久文件；库仍由宿主提供真实证据验证、当前权限与实际审计保留策略。

### 已执行的数据库与接口阶段

- 432个PHP／Python／JSON／SQL／Shell文件固定快照完成九版SQLite每版Outbox1577项、私有无TCP MySQL每版1042项；新增对账核心分别274／268项，新并发各31项，包含24个真实进程竞争同一／冲突决定及宿主提交前后SIGKILL。SQLite专项另在8MiB PHP进程验证回调篡改为16MiB NUL前缀TEXT后安全拒绝，未将SQLite特有存储类测试计入MySQL覆盖。
- 同九版各42项配置／诊断、166类API及367文件语法通过；两版全新消费者真实调用已安装reconcile／resolution，验证审计与处置提交／回滚及清理后审计保留，316文件归档包含新指南。PHPStan以PHP7.2目标、level5检查src通过。默认缺少管理权限时不调用决策guard，诊断新增人工核实项不执行SQL／回调。

### 首轮失败与修正

- 前置权限拒绝最初在通用事务回调中抛出，被包装为sql.authority；改为在前置回调返回严格布尔，再在事务层返回后生成outbox.denied，current／commit继续直接拒绝，保留外层事务归属和局部回滚。两版原失败日志分别为php72-first／php85-first，修正后完成新增拒绝矩阵。
- 并发测试最初直接用JSON传入含非UTF-8的二进制正文而无法启动；仅测试运行框架改用规范Base64，子进程恢复原始NUL／非UTF-8字节，再执行真实SDK。MySQL新增专项选择器最初放错分支，实际进入默认完整测试；确认自有进程后中止、等待私有实例清理，修正选择器后完成两版专项，随后进入九版正式矩阵。中止的mysql-first日志不计通过。
- 数据库阶段结束后的原生TLS首次在PHP7.2错误证书后的正常重试出现transport.timeout并进入dead，未标记sent。阶段日志已记录TLS／DoH完成及HTTP请求转发，但接收端尚未返回；不能据此把该次超时归因于握手阻塞或对账核心。原日志native-tls.log、126条命令终态及432文件前后SHA保存在`/tmp/sosecurity-outbox-reconciliation-results-qy7k_8u3/audit.json`；数据库／接口／安装等125条成功，TLS一条失败，分开计数。
- 原生发送新增显式transport_budget_ms配置，100—10000毫秒整数，省略兼容原1000毫秒；当前状态查询后按最新租期减1秒再截断。后续部署测试明确配置3000毫秒／6秒租期，同时对预先确认已提交的事件切换到1000毫秒并延迟响应1.1秒，验证严格超时不确认，随后恢复部署配置，保留原编号去重。未自动增加预算、忽略超时或放宽成功确认条件。

### 最终分阶段复验与范围

- 首轮126条命令的125项成功和TLS一项失败完整保留。随后只修改原生业务适配、适配单元测试和TLS测试三份文件，全部库src、SQL结构、API清单及其他PHP专项SHA保持；final-source.json保存覆盖后的432文件指纹及三份修改源码。
- 后续24条命令终态均为0：九版各66项原生适配／342项接收恢复，完整九版真实TLS各318项、两版全新消费者／316文件归档，以及src与完整原生帮助文件的PHPStan检查通过。初次单独扫描业务适配时未包含恢复帮助函数而报告符号缺失；补齐实际扫描目标后通过，没有加入忽略。TLS同时验证显式3000毫秒部署配置和严格1000毫秒的已提交迟到确认拒绝，不以延长所有测试预算替代原边界。
- 最终源码的分阶段Outbox证据合计SQLite每版1585项（以66项替换首轮58项适配），MySQL每版1042项；配置／诊断各42、API166及初始快照367文件语法单列。后续两份PHP改动均由九版实际运行编译，其他语法目标未变。两版安装后的对账API、旧解析器拒绝、实际TLS及本地数据范围分别核对，未将两轮结果合称一次全绿矩阵。
- 最终记录为`/tmp/sosecurity-outbox-reconciliation-results-qy7k_8u3/final-audit.json`，24条终态0、无失败组，执行前后SHA一致，预算修改范围精确为三份原生文件。全部数据库为自己创建的本地临时库，网络仅隔离命名空间、测试CA与固定测试数据；没有下游、生产、公开发布或远端CI操作。
- 原生签名证据、持久取消栅栏、审计封存／归档及实际对账命令仍未完成，合成SQL决定不构成远端业务验收。封存格式2需停旧进程，旧备份恢复另需业务审计、当前权限来源和外部代际；完整R4.3、R1其余适用项、R2.7、其余R4—R6保持继续。

## Outbox接收检查点、代际及受控恢复（2026-10-17）

### 实现与拒绝边界

- 原生接收端新增业务根、独立持久检查点和CLI初始化／状态／恢复／代际旋转。写前先提交prepared意图，处理事务同时提交业务唯一账本、投影及下一根，最后完成检查点；普通请求遇到prepared、与检查点不一致的业务旧备份、受保护业务表部分恢复、缺失历史／密钥或代际不匹配均拒绝确认。独立检查点不随业务库回退，配置epoch保存在两库之外，操作顺序见[接收恢复](outbox-recovery.md)。
- 恢复只允许上一根到下一根的最后一个已封存转换，保留原始正文、事件及投递编号；不根据旧库重新生成事件，不把不确定状态改为成功，不自动采用非空未封存旧候选库。更早备份和全部信任锚同时回退仍须宿主权威恢复／对账，不能由HMAC独自证明最新状态。
- 代际旋转要求外部保留的原root_hash，当前管理角色／版本复核，事件重放另需当前工作角色、发布方路由与业务拥有者。复核配置、私有文件身份和密钥材料隔离，防止旧PDO连接在业务／检查点／锁文件替换后继续确认；接收管理CLI的HTTP访问404，导入无副作用。库src及166类公开API保持不变。

### 已执行并通过

- 九版PHP7.2／7.3／7.4／8.0／8.1／8.2／8.3／8.4／8.5本地SQLite每版501项，均在8MiB PHP进程执行：恢复342、原生适配58、输入50、字段／正文限额51。恢复含实际业务／检查点文件备份与恢复、四个确认活跃并带阶段标记的子进程SIGKILL、初始化／代际COMMIT前后异常、当前权限／路由／拥有者、部分表恢复、缺失历史／密钥、旧配置、文件替换、硬链接、宿主事务、锁及耐久性故障，另以SQL生成16MiB异常字段验证读取前拒绝。全部子进程确认终止并回收。
- 同九版各166类API、364文件语法通过；PHPStan以PHP7.2目标、level5检查src及新接收适配通过。两版全新Composer消费者真实安装并执行新接收初始化、原事件去重、代际切换与幂等恢复，315文件归档包含新帮助函数、管理CLI、检查点结构和恢复指南，排除测试／开发／私有配置。
- 测试入口修正后，完整九版实际TLS每版314项均通过，含保持原1秒发送预算、24个TLS请求、两个PHP接收进程、原有响应丢失／工作进程SIGKILL，以及新增停滞握手不阻塞、实际业务库回退503、接收CLI恢复／幂等、稳定投递编号及受控代际旋转。最终命令终态0，九个运行时均有独立通过行；没有只取首版或中间输出作为完整结果。

### 首轮失败与修正

- 初次PHPStan把重复的当前数据库权限读取当作纯函数；根据实际SQL依赖声明principal为impure，保留提交前后权限复核，不删除检查或加入忽略。最终静态检查通过。
- 首轮九版TLS矩阵在PHP7.4的迟到确认后普通重试得到transport.timeout，第二次有限尝试结束为dead，测试期望立即sent而失败；未误报成功。PHP7.2／7.3此前通过，原日志及终态保存在`/tmp/sosecurity-outbox-recovery-results-g7s4m3x4/native-tls.log`和audit.json；该轮整体不计通过。
- 独立真实套接字对照确认测试入口在accept主线程握手时，一个不发送TLS字节的TCP连接可阻塞后续合法请求；改为各连接线程握手后同场景HTTP200，结果`/tmp/sosecurity-outbox-tls-ingress-counterexample.json`。测试入口据此改为每连接线程握手并限制等待，永久用例在停滞连接仍打开时核对另一合法HTTPS请求得到405；补充有界TLS／DoH／HTTP阶段时间诊断。产品仍保留1秒网络总预算。这是已证实的测试入口缺陷，不据此宣称已确定首轮那次瞬间超时的唯一根因。

### 当前快照与验证范围

- 首轮429个PHP／Python／JSON／SQL／Shell运行与测试文件前后SHA一致；本地、API／语法、消费者／归档及静态分析共59条命令终态0，TLS命令终态1，分别记录在audit.json。随后仅修改测试入口`tests/outbox_native.py`，PHP实现、SQL结构、PHP专项和发行包运行代码保持同一SHA；完整九版TLS复验终态0、执行前后SHA一致，来源及结果见同目录final-audit.json、final-source.json及native-tls-threaded.log。最终仅追加文档说明，未改写首轮失败或把两个阶段合称一次全绿矩阵。
- 全部数据库是自己创建的本地私有临时库；TLS仅在隔离网络命名空间使用测试CA和固定测试域名／公开形状地址，不连接外部业务服务。当前接收恢复仅为单机SQLite候选；MySQL原生恢复、Windows、真实断电、生产灾备和独立审查未执行。业务检查点不封存宿主权限表；只有权限／路由回退而业务根相同时，需宿主当前权威来源及外部身份版本／代际防护，不将当前表值复核写成权限历史防回滚验收。不把本轮专项描述为整库完整门禁或完整R4.3验收，超期dead消息的业务对账／处置及其余R1—R6继续。

## Outbox原生生产／发送／接收去重（2026-10-17）

### 实现与首轮实际证据

- 新增惰性业务适配、CLI生产／发送／管理和HTTPS接收入口。发送业务在同一PDO事务内提交订单、稳定原始事件、Outbox意图与幂等结果；接收先持久验签来源，再用现有事务处理组件提交独立业务唯一账本及投影，确认JSON必须匹配稳定投递编号与原始正文摘要。详见[原生接入](outbox-native.md)。
- 私有配置绑定OS服务账号、当前数据库角色／版本、固定实际Web根与HTTPS目的端；不从命令参数或请求头认定操作者，不自动创建账号、目录、结构或根。共享预算在SQL回调之外消耗，签名／封存／幂等密钥材料相互独立。原生资料采用8KiB固定正文结构，所有实际字段长度按字节核验。
- PHP7.2／8.5首轮真实TLS各239项通过：受限客户端的实际DoH／IP绑定／证书、24个并发TLS请求跨两个独立PHP接收进程、重复／冲突／历史重建、当前权限和密钥变化、禁用拥有者后的显式重试、响应丢失、已提交接收确认被暂停时工作进程真实SIGKILL、租期恢复、错误证书／重定向／畸形200不确认。私有网络命名空间中无外网路由，测试CA仅通过单进程配置注入。
- 当前PHP7.2适配57项在8MiB PHP限制下通过，覆盖惰性导入、显式私有配置、真实SQL生产／接收、原始头保护回调拒绝、独立唯一账本在安全历史重建后去重、换投递编号拒绝、当前业务字段、角色／版本／密钥撤销，以及16MiB含NUL角色记录在取回前拒绝。新五份示例PHPStan按PHP7.2目标、level5通过。

### 首轮失败与修正

- 首次TLS测试运行框架在24请求阶段从子线程访问主线程SQLite连接而失败；改为主线程预读不可变投递数据，再让HTTP线程只发送真实TLS请求。接收服务仍由两个独立PHP进程各自连接业务数据库，没有以单线程或模拟对象替代并发。随后两版239项均终态0，日志 `/tmp/sosecurity-outbox-native-initial.log` 与second.log；更早跨线程错误保留于本轮工具输出。
- 首次消费者测试复用了既有幂等测试的同名设置数组，误将pdo等字段作为原生角色迭代而退出255；改用独立Outbox测试预设变量后，实际安装包生产／接收／历史恢复检查通过。原失败与修复后日志分别为 `/tmp/sosecurity-outbox-native-install-initial.log`、second.log。产品角色限制保持，未放宽为接受任意角色。
- PHPStan首轮指出密钥快照在已经确认当前键存在之后，空集合分支不可能触发；移除冗余条件，保留当前键存在、最多8键以及HmacKeys本身的非空／材料校验，没有关闭规则或加入忽略基线。
- 首次445文件矩阵的本地九版检查和两版消费者／归档均通过，但TLS在PHP8.1的SIGKILL后恢复投递返回2，矩阵终态1，源码前后SHA一致。原报告为 `/tmp/sosecurity-outbox-native-results/audit.json`；当时只持久化unconfirmed，没有细分瞬间原因，不能认定已定位到超时或宣称原问题根因已修复。
- 随后增加固定失败分类与只包含状态／次数／固定错误码的测试诊断，原1秒网络预算和原断言均保留；诊断最初误把CLI文件的正常空404响应当JSON解析，已将非JSON诊断按空元数据记录，未放宽实际发送的确认格式。PHP8.1连续三次真实TLS各255项通过，`/tmp/sosecurity-outbox-native-classified-second.log`，不以简单重跑覆盖原始失败；新增确定性接收已提交但响应超时、私网DNS拒绝及原编号管理重试后，当前九版实际TLS各274项均通过，其他最终门禁继续补齐。

### 当前快照通过结果与范围

- 最终445文件固定快照覆盖src／examples／tests／resources／bin、Composer及CI定义，九版PHP7.2—8.5实际隔离TLS每版274项通过：原239项场景外，增加保持1秒原预算的确定性晚确认超时与同编号恢复，以及实际DoH返回私网地址时在发送前拒绝、记录策略分类、受控重试后同编号完成。各版8MiB适配57项、Outbox核心／工厂／输入／字段限额、既有幂等与Webhook工厂、配置和既有核心回归也通过，各版166类API与359文件语法通过。
- PHP7.2／8.5全新消费者实际使用安装后的五份原生示例、两套业务DDL及当前SDK完成生产、重复请求、真实签名接收、清除安全接收／处理历史后独立业务账本防重及确认；311文件归档包含新示例、结构和指南，排除开发／测试／私有配置文件。新五份示例PHPStan按PHP7.2目标、level5通过；测试运行框架与CI YAML语法通过，远端CI未执行。
- `/tmp/sosecurity-outbox-native-classified-results/audit.json` 记录全部11项终态0及执行前后SHA一致，命令、日志和445文件来源快照同目录保留。相对首次445文件失败快照，产品仅增加固定错误分类与策略拒绝处理，测试仅增加安全诊断和确定性场景；原始失败报告不覆盖，不称同一轮全矩阵通过。
- 本轮原生业务结构是SQLite示例；核心SQLite／MySQL库源码和API清单与前轮405文件基线逐一SHA核对不变，旧两后端证据另列，不声称本轮运行了MySQL原生投递。没有生产／外部真实提供器、公开部署或新浏览器流程验收。
- 超期业务对账／处置、完整有效备份一起回退的恢复演练和完整R4.3仍需完成；独立唯一账本不能与安全接收历史一起丢弃，也不能仅以一次本地去重成功承诺跨系统恰好一次。

## Outbox并发／崩溃恢复及显式工厂（2026-10-17）

### 已执行并通过

- 新增24进程真实PDO专项：独立业务与消息同事务提交、同事件重复／内容冲突、不同聚合并行领取、工作端绑定、重复确认、同聚合最早消息阻塞、容量不足回滚宿主业务、并发失败只安排一次退避，以及清理后保留递增顺序和旧事件到期拒绝。每批用私有启动屏障同时放行24个子进程；不是顺序调用或模拟对象替代。
- 真实SIGKILL发生在宿主COMMIT前后、领取提交前与持有已提交领取时、确认COMMIT前后；暂停期间由另一PDO连接观察业务和消息可见性。提交前终止不残留业务／意图，提交后恢复保留稳定投递编号；租期通过可控测试时钟推进后重新领取，旧凭据不能确认／安排失败；确认响应丢失后可重复确认，已sent正文保持清除。测试没有调用网络或接收方业务，不能据此承诺跨系统恰好一次。
- 测试运行框架只管理自己创建且确认仍在运行的子进程，输入／输出、启动与完成等待均有界；检查点位于私有目录，子进程最长等待30秒，父进程退出失败路径也终止并回收自己的子进程。没有根据PID文件或未知进程名执行终止。
- 新增Config.outbox()与Security.outbox()，默认不启用，服务显式注入。诊断区分缺失／错误服务、未配置管理权限与仍需人工核实的结构／身份／目的端／接收去重／恢复／容量／传输要求；构造与诊断不发SQL、不调用权限、不启动Session、不发头、不初始化数据库。166类其他既有契约逐项保持。
- 九版PHP7.2／7.3／7.4／8.0／8.1／8.2／8.3／8.4／8.5的真实SQLite每版Outbox832项通过：核心175、安全370、工厂72、并发148、输入16、字段／正文限额51。同九版真实私有MySQL每版709项通过：核心175、安全370、并发148、输入16。各版配置、既有核心、幂等核心／安全／工厂／正文限额，以及Webhook接收／处理／工厂／正文限额关联回归也全部通过；不是只运行新增工厂或只观察到中间PASS。
- 同九版166类API与353文件语法通过。兼容性对照逐一核对166类，只有Security与Config新增outbox()，其他既有公开成员保持；三份产品文件除工厂／配置／诊断增量外与上轮SHA一致，Outbox七份核心源码保持不变。`compatibility.json` 保留原API、当前API及受影响产品源码的SHA和对照结果，签名相等本身不作为行为安全证明。
- PHP7.2／8.5全新Composer消费者实际安装Outbox结构、宿主回滚／提交、重复入队、二进制NUL／非UTF-8正文领取和重复确认均通过；303文件归档包含Outbox七份源码、两后端DDL与指南，排除测试／开发／私有配置路径。PHPStan以PHP7.2目标、level5检查src通过，Shell与Python测试运行框架语法通过。

### 当前快照与验证边界

- 最终405文件固定快照覆盖src／tests／resources／bin，九版SQLite、同九版私有MySQL及两版消费者／归档共11项终态全部0。`/tmp/sosecurity-outbox-integration-results/audit.json` 确认执行前后源码SHA一致，命令、完整日志、来源快照与兼容对照保留在同目录；后续仅补记文档，不把上一阶段401文件或更早基线当作当前源码验收。
- 本轮全部数据库为本机私有测试库，MySQL使用独立无TCP实例；没有生产或下游数据库操作。尚未完成原生发送／接收方去重、超期业务对账处置和完整R4.3，也不是整库最终门禁或独立安全审查。

## Outbox字段读取与NUL防御性修复（2026-10-17）

### 逐字段投影与空 BLOB 兼容补强

- 根记录与消息元数据的每个字段分别检查 SQL 投影本身：精确字节上限保留原值，NUL 后隐藏的超量字节及错误存储类型返回拒绝标记；另验证领取、状态、候选和维护均拒绝异常历史。`tests/outbox-body-budget.php` 增至 428 项，16MiB 异常正文／元数据在 8MiB PHP 内存限制下拒绝，状态、领取次数及根记录不变。
- 正文读取再次核对策略字节上限；只有 SQL 已证明实际存储类型为零字节 BLOB，才将旧版 PDO SQLite 返回的 NULL 规范化为空字符串。TEXT、缺失记录及其他 NULL 不适用；合法空正文、首尾 NUL、非 UTF-8 和中文逐字节往返。
- 已执行并通过：PHP7.2—8.5 九版各 428 项字段／正文边界和 50 项输入边界；PHP7.2／8.5 私有、禁用 TCP 的本地 MySQL 关联专项各 1048 项，包含输入边界 50 项。超限入队不执行 SQL 或权限回调，不修改根记录，调用方仍可提交自己的业务事务。当前日志保存在 `/tmp/sosecurity-outbox-archive-final-ta7jkx7k/`；完整关联矩阵终态以该目录的 `report.json` 为准。
- 上述内存限制针对 PHP 取回数据的分配，不代表数据库引擎、页缓存或整个进程 RSS 也限制为 8MiB；本轮只使用本地临时测试库，未操作生产数据库。

### 本次输入边界补强与复验

- `tests/outbox-input-bounds.php`从16项增加至50项：空正文、单个／首尾NUL、非UTF-8和中文正文逐字节领取并确认；4字节策略下，5字节含NUL／中文正文在SQL查询和权限回调前拒绝。独立连接确认消息数量不增加，根记录版本／数量／历史摘要不变，宿主未提交的业务仍不可见且随后可以明确提交。
- 异常持久正文被拒绝后，另检查消息仍为pending、领取次数为0、根记录版本不变，拒绝不制造领取或推进历史。
- 已执行并通过：PHP7.2／7.3／7.4／8.0／8.1／8.2／8.3／8.4／8.5真实私有SQLite每版681项，含Outbox核心175、安全370、输入50、字段／正文51，以及幂等结果20、Webhook正文15；全部在独立8MiB PHP进程中运行。新增测试九版语法检查、PHP7.2／8.5各166类API契约，以及PHP7.2目标的Outbox／共享SQL结构PHPStan检查通过。
- 已执行并通过：PHP7.2／8.5独立、关闭TCP的本地MySQL实例每版743项，含核心175、安全370、24进程并发148及8MiB输入边界50项。异常SQLite类型的16MiB用例仍仅计入SQLite覆盖。
- 本次执行记录为`/tmp/sosecurity-outbox-bounds-review-cl1yhvsd/audit.json`，全部命令终态0，执行前后源码／测试／SQL资源哈希一致。测试仅使用本地临时库和合成数据；本次补强测试及说明，不将已有接收恢复开发或完整R4.3计为完成。

### 修改与实际拒绝边界

- Outbox根记录、单条消息及分批完整性扫描使用SQL端有界字段投影：字符串按实际字节长度限制，整数拒绝异常存储类型、负数或超出PHP整数范围的值。超限返回无效字段并抛出存储校验异常，不先完整读取、不截断后继续使用；分批最多64条的原边界保留。
- SQLite正文必须实际存为BLOB，不能仅信任列声明。TEXT字符长度会在NUL处停止，不能代替二进制长度；正文先验证实际类型、长度和已认证的策略限额，再查询正文并检查摘要。MySQL正文继续按实际二进制长度核对。合法空BLOB、二进制NUL和非UTF-8正文保持支持，标识中的控制字符仍拒绝。
- 同类存储类型检查同步应用到幂等结果、Webhook持久接收与处理读取。正文硬上限1MiB、Outbox策略限额以及标识长度均在入库之前检查；测试验证精确上限可用，超限不增加消息记录，异常持久正文不会产生领取记录或更改原pending状态。

### 已执行并通过

- 九版PHP7.2／7.3／7.4／8.0／8.1／8.2／8.3／8.4／8.5均通过真实私有SQLite专项：Outbox核心175项、安全370项、输入边界16项、字段／正文限额51项；关联幂等核心135项、安全190项、结果限额20项；Webhook接收201项、处理287项、正文限额15项，每版共1460项。输入／正文限额专项使用独立8MiB PHP内存进程，异常字段由SQL生成，包含16MiB BLOB、NUL前缀／中段TEXT、空TEXT、超大元数据及异常整数存储。
- 同九版真实私有MySQL每版Outbox核心175项、安全370项、输入边界16项，共561项通过；输入专项在8MiB限制下验证2MiB二进制持久正文拒绝、精确4字节正文可用及5字节含NUL正文超策略拒绝。16MiB异常存储类型专项只在SQLite执行，不把它描述为MySQL覆盖。
- 四组实际前后对照：Outbox正文／消息元数据、幂等结果、Webhook处理正文。修改前副本在8MiB限制下均因取回超大字段发生内存耗尽并退出255；当前根目录源码均以存储校验异常拒绝、退出0。幂等与Webhook旧副本SHA与上一阶段源码快照逐一核对；Outbox旧副本来自本轮修改前留存。对照使用父进程持有的独立临时目录，即使PHP致命退出也清理本轮数据库。报告为 `/tmp/sosecurity-outbox-defensive-results/counterexamples.json`，逐项保留前后日志与SHA，不把预期的旧版失败算作当前通过。
- 九版各349文件语法与166类候选API检查通过；原有161类签名逐一对比保持不变。PHPStan按PHP7.2目标、level5检查src通过，Shell与MySQL测试运行框架的Python语法检查通过。上述矩阵在401文件固定源码／测试／资源快照中执行，`/tmp/sosecurity-outbox-defensive-results/audit.json` 记录全部10项终态0及前后SHA一致；日志、命令与来源快照保留在同目录。这是本轮关联专项，不是整库完整门禁。
- 通用清单补充实际存储类型、NUL／字节长度、元数据读取限制、精确限额及数据库引擎资源边界，已同步仓库内Skill引用；未改写其他已安装副本。

### 验证边界

- 全部数据库为本机临时私有测试库；MySQL以不开放TCP的独立实例运行，只使用合成账号与数据，不读取宿主业务库凭据。8MiB验证限制PHP取回数据的分配，不代表数据库引擎内存、页缓存或总进程RSS也限定为8MiB。
- 本轮没有执行生产、下游、外部真实消息投递或整库完整门禁；原生发送／接收去重、并发进程恢复及完整R4.3仍待完成。下方为早期阶段各自快照的历史证据，不能代替本轮当前源码验证。

## R4.3宿主事务加入基础，本地专项补齐、完整Outbox继续（2026-10-17）

### 已执行并通过

- 新增内部 `SqlTransaction::enlist()` 与 `SqlTransactionGuard::assertActive()`，构造不执行SQL；明确加入宿主已有显式事务，固定局部回滚点与独立事务见证点，成功只代表待提交写入，不触发外层提交或回滚。公开候选仍为161类，无新增公开成员签名。
- 九版PHP7.2／7.3／7.4／8.0／8.1／8.2／8.3／8.4／8.5的新事务专项每版SQLite335／MySQL356项通过；每版336文件语法、161类API及既有幂等SQLite409／MySQL356项的分阶段证据已补齐。测试用独立真实连接观察宿主提交／回滚、局部失败与原有写入、旧PDO手工事务／旧标志、MySQL隐式模式拒绝、真实锁等待、时钟倒退、共享期限、事务替换、保存点／连接清理失败和嵌套调用。
- 与真实 `Idempotency\SqlExecutor` 组合，首次提交同时保留业务与消息意图，重放不再入队；业务异常和提交前撤权同时回滚两者；真实提交成功但故障注入丢失确认后，独立连接恢复为重放，不重做业务。测试intent表只验证事务基础，不是Outbox结构。
- PHPStan以PHP7.2目标、level5扫描src通过；PHP7.2／8.5全新Composer消费者及293文件归档通过。PHP7.2／8.2原生HTTP／TLS各433项也通过。产品代码在修复后的452文件基线中保持不变；后续只调整两份测试预设文件，并在当前452文件新快照中完成九版安全回归及原未执行命令。组合审计 `/tmp/sosecurity-sql-enlistment-combined-audit.json` 逐项核对覆盖与当前SHA，首次及第二轮失败报告均保留，不是单次全矩阵通过或当前整库完整门禁。
- 通用清单补充加入宿主事务时先证明存在、保持固定局部回滚边界与失败后中止完整业务单元的要求，已同步仓库Skill引用；没有修改其他已安装技能副本。

### 已执行但失败及修复

- 修复后第二轮九版新增事务加入专项均通过，但旧安全回归的PHP8.1 SQLite及PHP8.3 MySQL在250ms策略的初始化提交后触发真实期限拒绝，尚未进入目标故障注入。原日志和第二轮终态1均保留。产品源码、250ms被测预算、350ms延迟与原断言未改；只将三个场景的测试预设准备独立为有界初始化，再为私有空测试根封存目标策略，禁止用于非空状态或生产迁移。两个测试文件调整后，九版／两后端各190项安全专项及原未执行命令均通过，`/tmp/sosecurity-sql-enlistment-timing-stage-exit.json` 终态0；新快照产品源码与前一轮一致，仅测试预设不同，不以简单重复同一失败消除问题。
- 新专项首次九版矩阵在PHP8.2 SQLite真实锁等待后失败：失败语句的活动游标使 `RELEASE SAVEPOINT` 返回“SQL statements in progress”，触发了组件禁止复用，随后正常重试被拒绝。与当前源码SHA匹配的隔离副本稳定复现；仅增加失败路径 `closeCursor()` 后同一335项测试通过，原始日志及对照 `/tmp/sosecurity-enlistment-cursor-counterexample.json` 保留。根目录已应用同等修复；首次矩阵终态1且源码未变，保留原报告 `/tmp/sosecurity-sql-enlistment-stage-exit.json`。根目录修复后的九版／两后端事务专项均已通过；当前产品源码与该阶段一致，后续仅调整两份测试预设文件，不以隔离副本替代根目录验收。
- 验证工具最初把新MySQL专项分支放在完整矩阵分支内，导致单独模式运行既有回归而没有执行新专项；已修正并单独运行九版新专项。最初两版既有SQL／处理／接收／共享状态回归终态0，但含未启用Redis及PHP7.2无sodium的明确未执行项，不计入新专项或整库完整门禁证据。

### 未执行与剩余范围

- Outbox消息结构、实际入队API、持久领取／发送确认、重试／人工恢复和稳定投递编号下的接收方去重尚未交付，R4.3及完整R1—R6目标继续。
- 本次是内部SQL基础与组合专项，没有新增原生HTTP入口；不是当前源码的整库九版完整门禁、生产／下游、外部真实投递或独立审查结论。SQLite／MySQL的引擎自动回滚、宿主吞掉错误后仍自行提交或错误回调已经提交的副作用，不能一概描述为已安全撤销。

## R4.3通用幂等原生接入，本地专项完成、出站消息继续（2026-10-17）

### 已执行并通过

- [原生页面／POST接口](../examples/idempotency.php)、[业务适配](../examples/idempotency-business.php)、[私有CLI](../examples/idempotency-admin.php)、页面JS及显式宿主DDL已实现。真实ApiKeys／FileStore凭据绑定当前SQL账号版本，Authorizer复核角色／归属，Cookie不参与身份；签发、初始化、维护和撤销只通过私有CLI，不自动创建账号、目录、密钥、结构或命名空间。安装包中的适配也实际完成两键关联同一订单，不仅检查函数能导入。
- PHP7.2／7.3／7.4／8.0／8.1／8.2／8.3／8.4／8.5九版，每版335个PHP文件语法、161类API、SQLite409项（核心135／安全190／工厂48／受限内存5／并发31）、真实HTTP433／TLS433及全新非符号链接Composer消费者通过。逐命令日志`/tmp/sosecurity-idempotency-native-NN.log`及exit.json；MySQL同九版各356项（135／190／31），`/tmp/sosecurity-idempotency-native-mysql.log`和mysql-exit.json均终态0。
- 总报告`/tmp/sosecurity-idempotency-native-stage-exit.json`与审计`/tmp/sosecurity-idempotency-native-final-audit.json`确认451个源码／测试／示例／门禁／资源及Composer／静态配置文件在整轮保持不变；SHA-256清单`/tmp/sosecurity-idempotency-native-source.json`在该阶段结束时与源码一致；后续事务基础及测试预设变化另见本页最新记录。新元数据字段fingerprint来自已验证存储记录，冲突请求先检查旧执行的当前权限，再由核心拒绝不同参数；原有公开成员签名未变化。
- 原生测试覆盖首次／同键重放／内容冲突、不同键下的业务参考唯一性、可重放业务409、当前版本／角色／启用／令牌撤销、Cookie与Bearer分离、跨主体隔离、当前归属变更、同事务SQL故障与提交前撤权回滚、封存轮换及过期墓碑／容量；响应不含Token、SQL或内部异常。删除安全历史并获授权显式重建后，独立业务账本仍只保留一份订单。
- 真实客户端丢弃HTTP确认后，用独立SQL连接看到业务提交，再SIGKILL本轮自己的PHP服务器；重启后原键返回原结果，订单与执行记录仍各一次。它是丢失确认／进程重启验收，不宣称精确发生在写响应前；SQL核心另有提交前后明确检查点的真实SIGKILL九版两后端测试。
- 重复／大小写变体的Authorization、Idempotency-Key、Content-Type、Content-Length及Host通过真实网络请求在信息丢失前拒绝；直接绕过接入或伪造服务端属性／转发头也拒绝。TLS测试运行框架实际校验隔离私有CA证书，不能当作生产代理各跳或真实旧站验收。
- 入口预算先于正文解析、凭据验证、数据库和封存密钥加载；通过公开RateLimiter接口耗尽预算，再让数据库／密钥离线，仍返回429且不新建数据库。无效Bearer不加载数据库，授权请求遇到丢失数据库返回503。私有CLI维护不依赖已删除账号表；移至Web根内的状态、缺失结构和错误配置均拒绝。
- PHP7.2／8.5真实TLS移动Chromium通过提交、同键重放、换键后的业务唯一性、文本安全输出、无Cookie／localStorage／sessionStorage凭据持久化和无布局溢出；每版运行框架另23项。最终截图`/tmp/sosecurity-idempotency-native-NN-mobile.png`均已查看，日志browser.log保留。浏览器忽略信任仅用于隔离私有CA，普通TLS测试仍校验证书；没有部署系统根证书。
- 无sodium的实际php72运行时另通过原生HTTP433项，表明本流程没有隐式依赖可选MFA加密扩展；不能据此声称已有MFA页面可在缺少sodium时正常完成。PHPStan以PHP7.2目标／level5同时扫描src与三个新PHP示例通过，最初冗余类型判断已移除，没有降低级别、添加忽略或覆盖类型。

### 已执行但失败及修复

- 首轮HTTP在CLI文件的HTTP404响应统一头断言失败，已补齐no-store/private、nosniff及明确文本类型后复验通过；不把这一断言失败描述为核心事务失败。
- 旧载荷解析器会在JSON重复成员后只看覆盖后的结果，`amount:0`后再给`amount:500`被接受；隔离原实现及修复结果分别保留于`/tmp/sosecurity-idempotency-json-before.json`、after.json。固定两标量结构现在同时核对原始成员分隔，拒绝普通／Unicode别名／隐藏嵌套值的重复，同时保留合法字段顺序和Unicode编码差异。相关正常／拒绝路径纳入九版HTTP／TLS，不外推其他既有JSON入口已完成整改。
- 出站消息箱准备阶段的MySQL连接探测最初错误预期autocommit=0空闲状态不能保留保存点，探索脚本因此失败，`/tmp/sosecurity-outbox-active-probe-exit.json`及log保留。后续两版六种模式的独立连接验证确认已有DML一直未向观察者提交且可由宿主回滚；但autocommit=0空闲状态也可保留保存点，PDO仍报告false，不能把保存点或PDO标志单独当作既有事务证明。`/tmp/sosecurity-outbox-active-probe-v2.log`及exit.json为准备证据，当前拥有事务的组件仍明确拒绝autocommit=0，没有据此修改其保护。

### 未执行与剩余范围

- 出站消息箱追加／领取／发送／确认／接收方去重尚未实现，准备探测不是该能力的验收；完整R4.3、R1其余复核、R2.7及其他R4—R6继续。常驻Apache、生产与下游、远端CI、公开发布和独立审查未执行，本轮专项不代替整库九版最终门禁。
- 新原生接入的独立管理工具及场景说明见[接入指南](idempotency-native.md)。通用规范与仓库Skill引用同步补充解码前重复成员／编码别名，不更新其他已安装副本。

## R4.3通用SQL幂等核心，本地专项完成、完整阶段继续（2026-10-17）

### 已执行并通过

- 新增同PDO事务的业务／结果提交、当前权限重放、方法／目标／正文／宿主绑定指纹、永久键墓碑、封存轮换和有界维护；支持空／二进制响应。显式工厂和只读诊断不执行SQL或权限回调，未配置管理服务时不能初始化／维护。宿主认证、请求保护和业务唯一约束仍须接入。
- PHP7.2／7.3／7.4／8.0／8.1／8.2／8.3／8.4／8.5九版最终SQLite每版129核心、190事务／安全、48工厂、5受限内存及31并发恢复断言，共403；每版161类API与全新非符号链接Composer消费者通过。消费者实际执行发行包DDL、工厂、业务写入、同键结果重放和只调用一次业务，不只检查类可导入。日志`/tmp/sosecurity-idempotency-final-NN.log`和各exit.json。
- 同九版真实私有MySQL、无TCP／无宿主凭据，每版129核心、190安全及31并发断言，共350；包含双连接固定旧快照、手动／原生宿主事务保留、回调提交／替换与抛错、回滚故障、提交确认丢失、提交后到期／拒绝／抛错及原总预算不延长。日志`/tmp/sosecurity-idempotency-final-mysql.log`、mysql-exit.json及总报告`/tmp/sosecurity-idempotency-final-stage-exit.json`，均终态0。
- 两后端各版24进程确认同键只执行业务一次且原始结果一致、参数冲突不执行业务、容量不超用、跨作用域隔离；真实SIGKILL分别发生在业务写入后、COMMIT前及确认提交后，恢复后原键安全执行或重放，不改键重做。它们不是外部网络副作用的恰好一次验收。
- 该阶段443个源码／测试／示例／门禁／资源及Composer／静态配置文件在最终矩阵期间未变，SHA-256清单`/tmp/sosecurity-idempotency-final-source.json`与总报告相符。首轮旧快照的通过不能替代新增回归检查；当前仍没有将此专项当作整库九版全量门禁。
- 156个原有公开类的所有既有成员签名保持，追加5个公开类及Config.idempotency()／Security.idempotency()；兼容对照`/tmp/sosecurity-idempotency-api-compatibility.json`。PHP7.2对331个PHP文件语法检查、PHPStan level5／PHP7.2目标和286文件发行包检查通过；采用真实根目录单一源码路径，无错误忽略或类型断言绕过。
- 额外在PHP7.2／8.5通过真实API建立513条历史，跨512行批次边界，再篡改第二批的执行ID，新增业务被拒绝；各517断言。脚本`/tmp/sosecurity-idempotency-history-batch.php`为本轮隔离补充验证，未列作仓库CI测试或九版全覆盖证据。正文16MiB篡改在PHP memory_limit=8M下先拒绝读取；元数据集合按最多512行分批核验，完整工作量随有界历史条数增长。

### 已执行但失败及修复

- 首轮443文件固定快照的九版SQLite／API／旧配置／既有核心／新消费者全部终态0，但MySQL首次24进程仅12次重放，未满足23次，原始总报告`/tmp/sosecurity-idempotency-stage-exit.json`及mysql.log保持exit=1。双连接进一步确定旧REPEATABLE READ快照会使已提交根计数与记录读取不一致，反例`/tmp/sosecurity-idempotency-before-current-reads.log`；现在所有安全状态核验统一为当前读取，最终九版两后端通过，没有放宽并发断言。
- 旧PDO SQLite手动BEGIN时inTransaction()为false，新增实际数据库探测，探测仅回滚自己成功开启的空事务。恢复仅依赖PDO标志的实现时，宿主事务保护用例按预期非零失败；`/tmp/sosecurity-idempotency-before-sqlite-ownership-exit.json`及对应log保留。实际独立连接核验宿主写入始终待提交，只有宿主明确COMMIT后可见。空BLOB在PHP7.2返回null的问题通过实际SQL长度和行存在性区分，不把NULL／缺失当作空响应。
- 早期仅计数根记录可以被“改变旧键但保留总条数”绕过，真实业务金额由5重复变成10；提交后权限检查观察到到期但未持久化，也会在服务重建和时钟回退后返回旧结果。使用与首轮SHA-256完全匹配的三个原始实现文件独立复现，记录`/tmp/sosecurity-idempotency-history-counterexample.json`及其私有目录内原始日志。修复后金额保持5、业务一次，旧结果不再返回，相关用例纳入最终九版两后端。
- 未发布根格式升级为2，封存有序键／执行ID集合摘要；提交后失败的观察补记复用原总预算，不重做业务。旧开发原型不自动迁移或清空，生产在线迁移未执行；完整有效旧备份仍依赖外部epoch、可信时间及业务唯一账本，见[SQL幂等指南](idempotency.md)。

### 未执行与剩余范围

- 新通用接口的原生HTTP／TLS／浏览器与常驻演示、出站消息箱及接收方去重、完整R4.3与整库最终验收继续；既有Webhook原生界面的历史证据不覆盖新接口。生产、下游项目、远端CI、公开发布及独立审查没有在本批执行。
- 通用清单补充幂等当前授权／参数／到期恢复、集合完整性和大字段读取预算，仓库内Skill引用同步；已安装副本没有更新。R1其他适用条款、R2.7及其余R4—R6继续，精确状态见[实施跟踪](security-refinement.md)。

## R1.1固定标准与密码学用途盘点，部分完成（2026-10-17）

- 固定ASVS5.0.0 Git对象后，文件／授权／API／日志与错误／密码学／安全通信六域分别13／13／16／17／24／12条，共95条已逐项映射组件证据、宿主责任及缺口。逐域校验源条款ID集合、矩阵行唯一性及文档记录的原始SHA-256均一致，审计记录`/tmp/sosecurity-asvs-domains-audit.json`。这是需求和适用性映射，不是95项安全验收通过，其他领域继续。
- 新增[密码学用途清单](cryptography.md)，按实际源码盘点加密／MAC／摘要／随机凭据和外部协议用途；明确TOTP默认HMAC-SHA1的兼容例外、HIBP查询用途、算法／格式迁移和运行时内存边界。未扫描生产资产、未更改既有因子算法，也没有独立密码学审查结论。

## MySQL手工事务保护补充，本地基线复验完成（2026-10-17）

- 379文件固定基线最终九版完整／既有磁盘耗尽／新消费者共27项门禁逐一通过，源码在测试期间及回填前全部匹配`/tmp/sosecurity-r43-full-source.json`。最终采用`/tmp/sosecurity-r43-full-final-audit.json`列出的每个log和result路径；八版采用原始verified.log与无verified后缀的exit.json，PHP8.2采用serial.log／serial-exit.json。运行日志无FAIL／NOT RUN、PHP警告／弃用、回溯或致命错误；不把已有文件系统ENOSPC测试描述为SQL设备耗尽实测。
- 初始PHP8.2在既有`tests/password_calibration.py`的外部总耗时小于3秒断言失败，校准命令本身退出0；日志`/tmp/sosecurity-r43-php82-full-verified.log`及exit=1保留。发生时有隔离静态分析高并行负载；原矩阵其余八版最终全部通过，随后同一379文件基线的PHP8.2完整／磁盘耗尽／消费者单独复验均退出0。未改产品超时策略或测试断言，原汇总中的该次失败也不覆盖成成功。
- 后续汇总脚本最初误用verified-exit.json文件名，发生在PHP8.2三个命令已经退出0之后；核对真实退出文件并完成只读审计，没有因此重新运行产品门禁。最初汇总错误保留在`/tmp/sosecurity-r43-full-followthrough.log`。之后回填新接入形成388文件，新增功能证据按独立快照记录。

- 独立连接确认PHP7.2／MySQL用SQL开始事务时PDO标志为false；原接收／处理入口可在随后BEGIN时提交调用方未提交写入。处理用例`/tmp/sosecurity-r43-ownership-mysql-before-fix.log`及接收用例`/tmp/sosecurity-r43-intake-ownership-mysql-before-fix.log`已失败复现；此前完整通过记录不覆盖此新增场景，R4.2重新标为待复验。
- 私有MySQL探针确认两版空闲连接SAVEPOINT后RELEASE返回1305，实际手工事务内RELEASE成功且原DML仍可回滚；PHP7.2标志false、PHP8.5为true。采用不提交／不回滚／不修改自动提交或隔离级别的保存点探测，在启动新事务前保护真实调用方事务，并拒绝autocommit=0连接。
- 同类启动逻辑存在于MySqlStore事务／清理及显式install，已纳入同一共享内部保护。PHP7.2／8.5共32个真实MySQL用例通过：接收／处理／共享存储／清理／安装、SQL显式事务与autocommit=0、共享存储原生PDO的异常／静默／警告模式；每个用例比较调用方与独立连接可见性；接收／共享存储／清理／安装另覆盖回滚后的空闲正常执行（处理保护用例不进入业务映射）。采用`/tmp/sosecurity-r43-ownership-all-mysql-final.log`，SQLite两版对应保护也通过。379文件修复基线已完成上述九版门禁，之后功能变更仍按新快照验证。
- 错误模式复验最初沿用故障注入PDO，其exec会把false强制转成RuntimeException，与原生静默／警告模式不同；改为原生PDO验证这些模式，预期1305按返回值检查而不输出警告，保留`/tmp/sosecurity-r43-ownership-mysql-test-wrapper-failure.log`。

## R1.2审计对象调试与序列化保护，本地专项完成（2026-10-17）

- 原AuditLogger直接print_r／var_dump会显示私有审计假名密钥，使用可序列化回调时serialize也会携带密钥；合成材料复现保存于`/tmp/sosecurity-r1-audit-debug-before.json`。新的同一回归检查对原类预期退出1，`/tmp/sosecurity-r1-audit-counterexample.log`及exit.json保留；不是当前修复构建失败。
- 补充受支持调试输出脱敏与__sleep拒绝序列化，覆盖密钥和回调捕获材料；验证原有事件白名单、日志注入拒绝及主体HMAC不变。隔离修复九版tests/run.php全部通过，PHP7.2为193项、其余版本195项，API均156类且既有所有成员签名保持，仅新增两个魔术方法。日志`/tmp/sosecurity-r1-audit-NN.log`、`/tmp/sosecurity-r1-audit-exit.json`及API复核记录。
- 在388文件Webhook新接入专项最终审计之后，仅回填AuditLogger、核心回归测试及候选API三个文件；其他388文件来源逐一保持。该叠加修复记录在`/tmp/sosecurity-r1-audit-merge.json`，当时源码快照`/tmp/sosecurity-r43-post-audit-source.json`；不能把之前388文件专项的源码完全匹配结论延伸成后续源码未经变化。新修复有独立九版证据，当前整库九版全量仍待后续阶段。
- 通用清单和仓库内技能引用补充直接组件／回调捕获材料及服务对象持久化检查；未修改其他安装的技能。迁移要求见migration.md，不处理历史转储或在用密钥，任意反射／进程内存不由调试接口保证保密。
- 回填后的根目录PHPStan level5／PHP7.2目标、156类API及PHP8.5核心195项通过；PHP7.2／8.5两个全新独立消费者从非符号链接的已安装包实际验证调试保护和序列化拒绝，`/tmp/sosecurity-r1-audit-consumers.json`。最终274文件发行包、427个本地文件链接目标（未检查锚点）、Skill引用同步和diff空白检查通过；该阶段388文件仍匹配post-audit源码快照，汇总`/tmp/sosecurity-r43-current-stage-audit.json`。

## R4.3工厂、原生工作端与管理恢复，阶段实施中（2026-10-17）

### 已执行并通过

- 隔离副本九版配置／预设／协议／接收SQL／处理SQL与工厂专项全部终态0：工厂各120、配置42、预设46、协议239、SQLite接收201及处理287项；`/tmp/sosecurity-r43-factory-exit.json`与各版本日志。实际回填前后核对388个源码文件，采用`/tmp/sosecurity-r43-integration-source.json`及`/tmp/sosecurity-r43-integration-merge.json`；只替换本批19个源码／示例／测试／门禁／API／SQL文件及对应文档，其他原受测源码保持，备份路径记录在merge.json。
- PHP7.2／8.5最终真实隔离TLS／CLI各622项及移动Chromium通过：原始签名投递、同库业务投影／稳定事件账本、重复拒绝、接收／处理历史丢失后的幂等、同事件冲突内容、已知回调回滚后的自动重试、人工重试、CSRF／近期强认证／撤权、分页及空页游标、HTTP访问CLI拒绝和不自动建表。最终页面使用可读状态卡片及折叠诊断数据，两版截图已检查；日志`/tmp/sosecurity-r43-native-ui-NN.log`、截图`/tmp/sosecurity-r43-processing-NN-mobile.png`。Python验证私有CA，浏览器忽略信任仅用于该隔离证书。
- 真实Ed25519消息先在带sodium运行时验签接收，后在无sodium的PHP7.2中越过原签名时间窗口、无提供器密钥输入仍按独立封存和当前业务关联只处理一次；同一无sodium运行时另执行原生CLI处理真实Standard消息，业务投影只增加一次。`/tmp/sosecurity-r43-ed-history-without-sodium-final.log`；不是让接收端跳过Ed25519验签。
- 两版新消费者实际通过仅工作端配置取得工厂、同PDO事务处理及重复拒绝；156个既有类的所有成员签名保持，新增Security.webhookProcessor及ProcessingPolicy.options。PHPStan level5／PHP7.2目标、单一副本源码路径及512MiB工具内存通过，未加错误忽略或修改源类型绕过；最初双源码配置与128MiB工具内存问题分别纠正。新消费者最终包含工作端导入检查的版本由下面新九版专项继续复验。

### 新接入专项及未完成

- `/tmp/sosecurity-r43-integration-stage.py`在379文件完整基线最终审计后执行新388文件九版专项，最终九版全部终态0。各版语法315文件／156类API、配置42／预设46／协议239／工厂120／SQLite接收201／处理287及调用方事务7项、旧接收HTTP／TLS各628、新处理HTTP／TLS／CLI各589、新消费者均通过；每份日志及退出结果由`/tmp/sosecurity-r43-integration-final-audit.json`核对，测试期间388文件未变，回填根目录也逐一匹配。最初因前置汇总路径错误而未启动测试的等待进程已经终态，保留initial-audit-wait.log，随后依据实际最终审计启动；没有覆盖已执行失败结果。
- 这批是新接入的专项门禁，不是388文件整库九版全量验收。通用接口幂等、出站消息契约、完整R4.3阶段及全部R1—R6继续；无生产、下游接入、远端CI或独立审查结论。

## R4.3 SQL处理核心，实施中（2026-10-17）

### 已执行并通过

- 隔离原型PHP7.2／8.5两后端专项通过：SQLite各229、MySQL各226断言，以及两后端各24项24进程领取／事务完成／重放和实际SIGKILL提交前后恢复。日志`/tmp/sosecurity-r43-processing-mysql-prototype-final.log`与`/tmp/sosecurity-r43-processing-concurrency-prototype.log`；这些不包含之后根目录的引用隔离新增检查。
- 根目录PHP8.5最新SQLite252断言、156类API、308文件语法及PHPStan level5／PHP7.2目标通过。新增回调引用参数测试确认不能改写组件PDO／端点／原始正文／封存来源上下文；隔离旧实现对新用例必败，`/tmp/sosecurity-r43-before-reference-isolation.log`。
- 根目录第一阶段九版处理专项全部终态0：各252 SQLite／249 MySQL断言，两后端各24项24进程／SIGKILL恢复通过；22个源码／测试／SQL文件与启动快照完全一致。采用`/tmp/sosecurity-r43-core-stage-exit.json`、`/tmp/sosecurity-r43-core-stage.log`、`/tmp/sosecurity-r43-phpNN-core-stage.log`、`/tmp/sosecurity-r43-mysql-core-stage.log`及`/tmp/sosecurity-r43-core-stage-source.json`。这些不包含之后补充的映射元数据与事务终止检测。
- PHP7.2／8.5新消费者已实际执行包内处理DDL、首次领取、同PDO业务与成功状态、重复执行拒绝；269文件归档、156类API兼容对照及381项本地Markdown链接通过。

- 新增契约PHP7.2／8.5两后端通过：各287 SQLite／284 MySQL与两后端24进程／SIGKILL恢复；MySQL采用`/tmp/sosecurity-r43-contract-mysql-stage.log`，两版全新消费者`/tmp/sosecurity-r43-phpNN-consumer-contract.log`实际接收仅签名头有ID的消息并事务处理。原生PDO标志不作为后来事务所有权证明，独立连接确认已提交1笔／调用方内可见2笔、宿主回滚后保留1笔。新增随机保存点检测登记回调提交／回滚／替换事务，非法提交可能已持久化，不冒充业务已回滚。
- 新契约九版专项已启动，采用`/tmp/sosecurity-r43-contract-stage.py`及`/tmp/sosecurity-r43-contract-stage.log`；首轮22文件快照只证明之前版本，不覆盖新契约代码。

### 已执行但失败，随后调整并复验

- 新事务用例最初用PDO API在手工提交后重开事务，PHP7.2／MySQL未形成预期第二笔写入，日志`/tmp/sosecurity-r43-contract-mysql-initial-pdo-state.log`。改用显式SQL开启，并用独立连接验证真实可见性，避免用PDO状态标志替代事务所有权证据。
- 原型handler异常正确转换为DependencyException，初始用例错误期待StorageException，已按真实错误分类修正；原始秘密不传递为previous异常。
- SQLite宿主手工BEGIN在PHP7.2与8.5的PDO::inTransaction表现不同，用例按真实驱动状态区分配置拒绝／新BEGIN失败，并验证两种情况均保留调用方未提交写入。
- 静态分析曾把读取实时期限的held方法当作纯函数，按其真实时钟依赖添加impure声明，保留所有SQL／回调后的重新核验，不删除检查或抑制错误。

### 未完成与边界

- 以上为SQL核心阶段当时证据；其后工厂／诊断、原生工作端／管理及新消费者已按上节完成九版专项。通用接口幂等／出站消息契约与完整阶段门禁继续。处理事务不能包含外部副作用，不作生产或独立审查结论。

## R4.2 Webhook接收层，本地验收（2026-10-17）

### 已执行并通过

- 最终九版完整检查／既有磁盘耗尽检查／新消费者共27项终态0；每份full／disk／consumer日志及exit.json逐一核对，无FAIL／NOT RUN、PHP运行时警告／回溯。采用`/tmp/sosecurity-r42-phpNN-{full,disk,consumer}-verified.log`、对应exit.json，以及`/tmp/sosecurity-r42-final-audit.json`。PHP8.5最终采用下述串行复验，不将最初失败日志当作通过。
- 每版Webhook各239协议／900独立请求、201 SQLite／191 MySQL专项、两后端各25项24进程／SIGKILL恢复、原生HTTP／TLS各628断言通过；42配置／46预设、152类API检查通过。新增接收层没有把既有文件／上传／下载的磁盘耗尽测试写成SQL设备耗尽实测。
- PHP7.2／8.5真实TLS移动Chromium最终复验通过；Python验证私有CA，浏览器仅忽略该隔离自签证书信任；测试接入层在原始头被SAPI丢失之前拒绝重复头，后端直达和客户端伪造检查声明均拒绝。所需生产接入能力另行验收。
- 366个源码／测试／示例／门禁／SQL／API文件在完整矩阵前保存到`/tmp/sosecurity-r42-final-source.json`，最终审计确认全部不变。R4.3先在隔离副本实施，不能将之后新增处理层计入本阶段的完整通过证据。
- 原有144类所有既有公开成员签名保持不变；PHPStan level5／PHP7.2目标、260文件发行包、Composer严格校验、锁定HTML Purifier依赖审计无公告／废弃包、367项本地Markdown链接及仓库Skill引用同步检查通过。

### 已执行但失败，随后复验

- 最初三版本同时运行完整矩阵期间，PHP8.5在既有FileStore租约续期竞争中触发生产默认1秒锁等待预算，完整进程退出255。保留`/tmp/sosecurity-r42-php85-full-initial-lock-timeout.log`及对应json；未修改生产超时或放宽断言。其余八版全部终态通过后，PHP8.5同一366文件源码单独执行完整／磁盘耗尽／新消费者均0，串行日志`/tmp/sosecurity-r42-php85-serial.log`与`/tmp/sosecurity-r42-php85-serial-exit.json`。该结果证明受控负载复验通过，不声称从此消除负载相关锁超时。
- MySQL历史快照、PHP7.2重复头信息丢失、工厂调试秘密以及原语测试工具兼容问题的修复／复验记录保留在以下阶段记录中。

### 未执行与边界

- 真实提供器凭据／公网投递、生产代理及业务、下游接入、远端CI与独立审查未验收。接收成功不等于业务执行；R4.3幂等处理、重试与恢复继续实施，完整路线其余阶段继续。

## R4.2 SQL持久接收与原生接入，实施中（2026-10-17）

### 已执行并通过

- 新增接收层九版专项均退出0：各239协议／900独立请求、201 SQLite、25 SQLite并发、42配置、46预设及152类API检查。采用`/tmp/sosecurity-r42-phpNN-inbox-stage.log`，汇总`/tmp/sosecurity-r42-inbox-stage-exit.json`和`/tmp/sosecurity-r42-inbox-stage.log`。
- 同一真实私有无TCP MySQL服务下，九版各191接收／25并发断言通过，采用`/tmp/sosecurity-r42-inbox-mysql-stage.log`。两后端均含24进程首次／重复／冲突／跨站点／非法来源、新进程持久去重及真实SIGKILL提交前后恢复。
- 原生接入PHP7.2 HTTP／PHP8.5 TLS最终预检各628断言通过；私有CA由Python验证，包含原始正文、重复／冲突、当前密钥撤销与封存失败、业务停用／版本、实际锁等待、1000条容量、CSRF／密码／TOTP与角色变更。对应`/tmp/sosecurity-r42-php{72,85}-webhook-native-final.log`。容量占用预载为惰性测试行，不冒充验证过的提供器消息。
- PHP7.2／8.5真实TLS移动Chromium最终复验通过，含390像素布局、密码／TOTP、接收元数据、已签名HTML样式事件ID的转义、Cookie不能替代发布器签名、弱认证管理员拒绝及退出；`/tmp/sosecurity-r42-phpNN-webhook-browser-final.log`。
- 源码覆盖独立HMAC封存、实际BLOB比较、原始来源密钥／签名时间、当前业务关联复核、宿主事务保护、数据库结构／持久性检查、晚返回／清理失败和失败连接拒绝复用。构造与只读诊断不执行回调或SQL。
- PHP7.2全新Composer消费者通过Webhook工厂验签、显式安装包内SQLite结构、首次／重复持久接收；采用`/tmp/sosecurity-r42-php72-consumer-stage.log`。阶段发行包259文件、PHP8.5语法297文件通过；这些为原生页面新增前的阶段记录。

### 已执行但失败，随后修复并复验

- 真实MySQL 24进程投递曾因REPEATABLE READ旧快照误报接收记录不存在；接收行与最终正文查询改用锁定读取。双连接固定交错复现及修复后通过，隔离旧实现必败日志`/tmp/sosecurity-r42-inbox-before-current-read.log`；没有改动根目录回退修复。
- PHP7.2真实重复头请求曾被CLI SAPI覆盖后接受（`/tmp/sosecurity-r42-php72-webhook-native-preflight.log`）；确认不可在信息丢失后恢复。原生入口改为缺少可信接入检查属性时拒绝，并由真实HTTP／TLS接入层在转发前拒绝重复头；直接后端与客户端伪造属性拒绝，628专项及最终浏览器通过。PHP8.5对部分重复头返回403而非最初测试预期400；用例按拒绝且不分配接收状态核验，未放宽接受条件。
- 通用Security工厂的调试展开曾可显示回调捕获的合成秘密；新增脱敏debugInfo，print_r／var_dump／JSON检查通过。

### 未执行与边界

- 完整门禁首批PHP7.2／7.3／7.4的完整检查／磁盘耗尽／最终新消费者共9项均终态0；逐份日志无FAIL／NOT RUN、回溯及PHP运行时警告，原生HTTP／TLS各628断言通过。其余七版继续，不能以首批结果代表九版全部完成。
- 新增完整九版检查、磁盘耗尽与最终新消费者门禁仍在运行，进程`/tmp/sosecurity-r42-matrix.py`、汇总日志`/tmp/sosecurity-r42-matrix.log`；终态与全部日志未检查前不标记完成。原生最终静态检查通过，260文件归档通过，最终文档链接及发行材料继续。接收结果不代表业务执行；真实提供器、公网投递、生产与独立审查均未验收。

## R4.2 Webhook验签核心，实施中（2026-10-17）

### 已执行并通过

- 当前根目录九个PHP版本各239核心断言／900独立Python原始帧请求及149类API检查通过；原有144类完整契约逐类比较保持一致。采用日志`/tmp/sosecurity-r42-phpNN-protocol-root.log`。GitHub维护方公开向量与RFC8032原语验证，四种固定协议分别覆盖原始正文、密钥撤销／轮换、时间边界、输入／头预算、未签名元数据、当前来源故障以及真实慢回调到期拒绝。
- Python标准库构造HMAC，OpenSSL EVP C API构造Ed25519，PHP sodium验证；二进制／中文／64KiB、时间数值／Base64别名、重复时间字段、路径／方法与正文变更分别核对。所有密钥、账号、域名和消息均为测试预设。
- PHP8.5语法288文件、PHPStan level5／PHP7.2目标、252文件发行包检查通过。当前协议组件无共享账本、数据库、Session、Cookie、网络或业务副作用。
- 原生php72缺少sodium时，HMAC三种配置的636个独立请求通过，Ed25519测试明确未执行；设置强制密码学检查后同一缺失依赖明确失败。该结果单独记录，不混入具备sodium的九版900请求通过日志，也不把Ed25519请求改用HMAC。

### 已执行但失败，随后修复并复验

- 最初独立脚本使用OpenSSL pkeyutl -rawin，本机1.1.1命令行不支持；已改用该版本支持的单次EVP C API。系统find_library优先找到更早的libcrypto.so.10，脚本按所需API选择受支持的1.1.1／3.x库，不改变系统库或安装第三方密码包。

### 未执行与边界

- 持久接收、共享去重／重放策略、可信业务关联、工厂／诊断、原生HTTP／TLS、并发SQL接收、本阶段完整九版检查与新消费者继续实现。仅验签不意味着已接收或业务已提交；GitHub投递ID／事件类型与签名时间限制详见[方案](webhooks.md)。
- 当前不作真实提供器、生产、下游、远端CI或独立审查结论。R4.1及更早完整检查是各自阶段证据，不作为新增Webhook的完整验收。

## R4.1 账号级API凭据，本地验收（2026-10-17）

### 已执行并通过

- 九版最新专项3753凭据断言／280下载断言／263流式断言／1456独立Range对照通过；独立Python凭据签名／格式720检查（24个PHP签发与312个Python请求）、144类API及原有139类公开签名兼容对照通过。包含操作者退出／降权／切换、提供器畸形返回及策略引用隔离。采用日志`/tmp/sosecurity-r41-phpNN-core-final.log`；九版完整检查／真实磁盘耗尽／新消费者均正常退出0，通过日志逐份检查无FAIL／NOT RUN、回溯或运行时警告。采用`/tmp/sosecurity-r41-phpNN-{full,disk,consumer}-verified.log`，各full／consumer另有exit.json及汇总`/tmp/sosecurity-r41-matrix.log`。
- 当前凭据格式的文件／Redis／MySQL各24进程容量／代际轮换／替换／撤销竞争通过，阶段日志`/tmp/sosecurity-r41-shared-stage.log`。每个账号单根原子账本，首次并发签发恰好8项、同代际轮换／替换恰好1个成功，旧秘密拒绝；不能推断跨资源事务。
- 九版原生HTTP各592检查与真实TLS各600检查通过：真实bcrypt密码／TOTP、CSRF／Session轮换、一次展示秘密、服务账号委派、只接受Bearer的SQL读写、范围／所有权／租户、代际／撤销／密钥轮换、超限正文／私有路径／固定Host、依赖故障和真实两秒到期。
- PHP7.2／8.5真实TLS移动Chromium均通过：密码与TOTP、一次展示后刷新消失、独立无Cookie API请求、轮换后旧秘密拒绝、服务账号读取及写范围拒绝、撤销与390像素布局。测试私有CA由Python验证，浏览器仅对该自签证书忽略信任错误；TLS桥仅为测试。
- 九版全新Composer消费者通过账号凭据签发、认证、查询、轮换／撤销与原生示例未配置时安全拒绝；PHPStan level5／PHP7.2目标通过，144类API保留原有139类公开签名；归档246文件、Markdown链接／CI YAML和锁定HTML Purifier依赖审计通过，无公告或废弃包。

### 已执行但失败，随后修复并复验

- 测试预置脚本误用不存在的Totp::at；已改为公开codeAt，并使用提前90秒的隔离测试时钟预置因子，真实HTTP按实际时间验证。
- JSON异常用例误用只读令牌，写路由在解析正文前正确返回403。改用具备写范围的令牌后，确认正文错误返回400，独立只读写请求仍为403，无SQL变更。
- 代码检查发现晚返回的权限拒绝可能早于到期清理；调整为先持久化已观察过期，并验证权限恢复与时钟倒退不能复活旧令牌。
- PHP数组槽位引用可使新凭据策略及既有下载策略被外部变量修改，均已复现并断开引用；新增配置不变性和实际超预算文件拒绝检查。该文件拒绝最初误写为SecurityException，实际在读取前正确抛出ValidationException；修正测试分类后复验。
- 首轮完整矩阵被SIGTERM中断，没有正常退出标记，保留为`/tmp/sosecurity-r41-php{72,73,74}-full-interrupted.log`，不计完整通过。改为独立进程组运行，逐阶段记录退出状态；重跑九版全部完成，27个阶段正常退出0。

### 未执行与边界

- 完整矩阵期间补充下载策略引用隔离，采用九版最新下载280断言／流式263断言／1456独立Range专项补足早期完整日志中的275项下载检查。凭据3753、720独立检查及144类API均为当前九版结果。343个源码／测试／示例／门禁文件清单保存在`/tmp/sosecurity-r41-final-source.json`，阶段结束已核对无变化；Webhook先在独立副本开发，R4.1验收完成后才并入根目录，不混算入本阶段源码。
- 常驻Apache、生产／下游、远端CI、真实客户服务账号、独立安全审查未执行。账号服务／文件账本／业务SQLite之间无全局原子事务；管理员退出不自动撤销目标机器凭据，备份恢复旧状态须配合权威版本或密钥退役。
- R1、R2.7、R4.2—R4.6、R5—R6仍保留原规划，API凭据不是OAuth服务器或JWT协议实现。

## R3.6 授权下载与私有内容快照（2026-10-17）

本段覆盖Download核心、显式工厂／诊断、真实私有文件及原生密码／SQL／签名接入。九版本完整检查、最新下载专项及新消费者已通过，R3.6本地验收完成。完整R1、R2.7、R4—R6均未完成，不将本阶段变成整个精修规划验收。

### 已执行并通过

- 九个运行时严格bin/check.sh完整检查、独立磁盘耗尽及新消费者均通过；267个PHP文件语法、139类API和既有文件／Redis／MySQL各24进程场景保持通过。最终采用PHP72／73／74／80的`/tmp/sosecurity-r36-phpNN-{full,disk,consumer}-final.log`，PHP81／82／83／84／85采用对应`-verified.log`；逐份核对没有FAIL／NOT RUN、异常回溯或运行时警告。首轮PHP80失败不计入通过，修复测试时序后完整重跑通过；其他早期阶段结果由以下冻结后的九版最新下载门禁补足新增边界。
- PHP7.2.34／7.3.33／7.4.33／8.0.30／8.1.34／8.2.32／8.3.35／8.4.23／8.5.9最新下载门禁逐版通过：275核心、263流式断言、1456独立Python任意精度Range对照、749原生HTTP、733真实TLS、139类API、11真实ENOSPC及全新Composer消费者安装。采用日志为`/tmp/sosecurity-r36-php{72,73,74,80,81,82,83,84,85}-final-download.log`；源／测试清单326文件保存在`/tmp/sosecurity-r36-final-source.json`并用于核对冻结后的变化。
- 核心使用真实私有目录／源文件／匿名快照，覆盖大小／完整摘要、同大小同mtime篡改、复制期间内容混合、校验后源文件替换、根／快照目录替换、私有嵌套路径、符号／硬链接、管道及锁等待。未经授权不读取源文件，已验证快照随后输出的字节不受源替换影响；有界回调仅用于注入故障时序，不用模拟文件系统替代实际文件读写。
- 真实SessionRegistry和Authorizer核对当前身份；核心测试身份为合成测试数据，原生HTTP另外执行真实bcrypt登录。每块读取前后检查共享会话、角色、元数据和期限，覆盖读取期间撤权／空闲到期／身份源故障、时钟无效／回退、输出异常／部分接受，以及最后一块输出回调晚返回。拒绝关闭快照，后续不能重新读取；不将读取字节数等同网络交付。
- 九版各处理16MiB实际源文件，独立PHP进程`memory_limit=8M`，256块输出摘要一致，PHP分配器统计峰值2MiB；不是进程RSS或内核页缓存占用的测量。实际16KiB隔离tmpfs耗尽使快照失败，未留下命名文件或占用的匿名内容块，原始源摘要不变。该结果证明当前管道分块处理，不证明所有宿主／代理没有额外缓冲。
- 原生页面使用私有SQLite账号／ready文件索引、独立FileStore和密钥；覆盖真实登录／CSRF／旧令牌失效、私有下载／HEAD、单Range／后缀／开放末端／溢出／416、强If-Range、弱／日期If-Range完整返回，以及条件缓存头不能产生304旁路。匿名已有／缺失对象ID及错误Range保持相同拒绝，不返回私有大小；公开签名读取不创建Cookie或混用另一个登录主体。
- 签名链接绑定Download\File派生内容资源；多次、一次GET、明确POST兑换与重放／撤销分别执行，一次性HEAD／Range拒绝且保留完整请求机会。文件名称／版本／隔离状态、所有者密码哈希／角色／禁用、密钥删除、真实源摘要／链接／权限变化均拒绝。跨账号／额外租户字段／查询别名／Host／方法，以及私有SQL／密钥／共享状态故障均不返回文件正文；状态目录位于实际Web根下时503拒绝。
- 原生预算按完整源文件向上取整KiB，单字节Range不能只按输出字节扣减；32KiB额度对16KiB源只接纳两次范围请求，第三次拒绝。四名额租约满额拒绝、缺失账本拒绝、恢复需授权显式初始化；正常／失败路径释放，崩溃恢复能力沿用已验证租约模块，不声称可强行中断暂停进程。
- HTTP另有真实延迟输出用例：服务器echo／flush交付完整正文后，写回调仍执行一秒；此时检查到一个活动租约，活着的PHP进程完成finally后恢复为零。故障注入／账本删除前及验收结束时有界等待实际清理完成，不把客户端收完Content-Length字节当作服务器清理已结束。
- TLS检查使用临时私有CA、实际TLS终止器及仅测试使用的受限回源桥；Python验证CA，Secure／HttpOnly Cookie和精确Host／HTTPS成功路径通过；直接明文回源加伪造代理头仍被拒绝。测试桥不属于生产代理自动信任能力，未修改系统CA。
- 新消费者安装真实拷贝后调用当前Session授权、快照后源替换、单Range、签名HEAD不消费／一次读取／重放拒绝，未配置原生入口仅返回download.unavailable；无自动Session、表、默认账号或公开源路径。
- 冻结后PHP7.2／8.5真实TLS Chromium复验通过：真实登录后保存私有下载、不同上下文公开分享下载、UTF-8名称／完整二进制SHA-256、撤销、明确POST下载与重放拒绝、退出后拒绝；390像素无横向溢出或页面脚本异常。两版日志为`/tmp/sosecurity-r36-php{72,85}-browser-final.log`，已查看`/tmp/sosecurity-download-mobile.png`。临时私有CA在浏览器中的例外见下文。
- PHPStan level5／PHP7.2目标、Composer严格校验、CI YAML／Python语法、236文件发行包及338处本地文档链接通过；包内有Download全部14个源码文件、原生页面与指南，无测试／开发／私有配置文件。新模块没有增加必需第三方运行时依赖。实现和测试326文件摘要在最终门禁后复核未变化；仅继续整理文档及CHANGELOG。

### 已执行但失败，随后修复并复验

- 读取后只检查绝对期限，未覆盖读取期间的空闲期限或权限变化；已改为返回字节前重核当前授权和元数据。末块完成后输出回调晚返回仍可报告完成，已补回调返回后的期限检查，并标记未完成、不自动重试。两项均进入275核心断言，九版最新专项通过。
- 初期复制竞态测试只用4KiB文件，PHP流预读得到完整旧内容时仍是合法快照，测试错误地预期拒绝；改为64KiB实际源及1KiB读取，让中途写入导致混合内容，验证摘要拒绝。该项为测试数据修正，不描述为已确认内容绕过。
- PHP8.0首轮全库检查在HTTP末尾预期零租约却观察到一个。响应到达与服务器finally间存在时序，立即移动状态目录还可能打断尚未完成的释放；新增前述延迟输出用例和活进程／共享状态有界等待后，九版最新749 HTTP／733 TLS通过。首轮失败日志保留，不作为最终通过证据。
- 原生页面早期将签发管理权限拒绝误映射503，已归类为403；私有下载也前移当前会话验证，避免存在／缺失对象在匿名Cookie及错误Range上的区别。新增实际HTTP负面断言，不仅修正文档。

### 未执行与边界

- 本阶段未配置常驻Apache或生产的私有账号／文件索引、源／快照目录和并发账本；未执行生产、Windows／网络文件系统、实际反向代理、远端CI、公开发布或独立安全审查。
- Python已验证私有CA；Chromium测试只为该临时证书允许证书错误，不代表生产证书链验收。浏览器文件摘要／文件名与移动布局为独立实际操作，不能以HTTP断言代替。
- 信任部署目录、权威索引和同UID进程；宿主仍须维护扫描结果、磁盘硬配额、全入口授权、所有Web映射／存储ACL和基础设施超时。内核阻塞I/O或宿主回调只能返回后检查期限，无法承诺强制抢占。
- 签名一次消费和预算不会因后续失败退款，已交给输出层或已下载的数据不能追回；跨SQL／共享状态没有全局原子撤权或业务恰好一次保证。完整扫描／隔离生命周期继续R4.4，归档继续R6.4。

## R3.5 签名链接、共享撤销与明确兑换（2026-10-17）

本段覆盖Link核心、严格URL／HMAC、工厂／诊断、共享账本和独立原生页面。R3.5本地验收完成，完整R1、R3.6—R6仍在继续；签名链接不等同于已实现文件下载、部署或独立审查。

### 已执行并通过

- PHP7.2.34／7.3.33／7.4.33／8.0.30／8.1.34／8.2.32／8.3.35／8.4.23／8.5.9最终严格bin/check.sh完整检查及独立Composer消费者安装全部通过。逐版核对各663签名链接核心／104独立签名向量／542原生HTTP、129类API、248个PHP文件语法，以及三种真实后端并发场景；采用日志无FAIL／NOT RUN、运行时警告或异常回溯。
- 核心覆盖固定规范来源、用途／资源租户／编号／版本／属性、路径／全查询／方法绑定，可分享及非空上下文绑定、密钥轮换／删除、期限边界、不续期、查询／单条及全部撤销、作用域与容量。UTF-8路径段、精确RFC3986查询、重复项／额外参数／重排／编码别名、非规范信封及标量类型预算均验证；不使用PHP折叠后的查询数组重建验签输入。
- 事务回调重复执行产生相同状态／期限／结果，随机数、时钟、密钥运算及请求保护均在回调外。64条最大账本实际通过Codec，缺失／损坏／策略漂移／时钟回退／依赖故障拒绝。账本与已认证信封进一步核对issued／expires／one_time／key_id；一次性标记反转不能变成可重放授权。慢I/O到期、返回后无效时钟及回退均不返回授权，精确清理后旧凭据不能复活，也不删同ID但不同摘要的替代记录。
- 各版本104独立Python对照断言，独立计算Resource／Target JSON指纹、UTF-8／查询编码、绑定摘要及HMAC-SHA256／Base64url，PHP签发结果逐字节一致；Python签发并在隔离测试账本登记后由PHP验证，覆盖重复与单次、GET／POST／HEAD、IPv6、最大期限和非规范填充位。采用固定公开测试密钥，不声称与其他框架或通用签名协议直接互操作。
- 各版本真实File／Redis／MySQL，每场景24个PHP进程：一次性链接只一次成功，重放全部拒绝；可重复链接24次均成功，撤销后24次全部拒绝；容量8只允许8项新签发，到期边界24次验证全部拒绝。HEAD先行拒绝不消耗一次性GET。测试只用私有目录／Unix套接字及无TCP数据库，未访问生产后端。
- 各版本542原生HTTP断言，使用真实bcrypt登录／Session更新／CSRF、私有SQLite权威账号／资源和独立密钥文件。签发后另一未登录浏览器可按Bearer授权读正文且不创建登录Cookie；错误CSRF／权限／Host／方法、重复／额外／别名查询、资源版本／归属、所有者密码哈希／角色／禁用变化，以及密钥删除均拒绝正文。读取发生在验签之后，并用SQL再次约束资源／原始账号版本和密码哈希。If-None-Match／If-Modified-Since不能绕过验证或返回缓存304。
- 原生GET一次性链接在首个有效GET后失效，HEAD不消费；POST目标的GET仅提供通用兑换表单，不验证或透露正文，重复打开不消费；实际POST须本浏览器CSRF和有效签名，只成功一次。另用两秒真实期限验证到期，无测试时钟绕过。密钥文件超限／非规范Base64／不私有、密钥／SQL／共享状态下线均503通用错误，没有明文异常／路径或密码；默认HTTPS配置在实际明文HTTP上拒绝请求。
- 各版本另行通过tests/link_owner_http.py的106项双账号HTTP断言：两名真实登录编辑者不能跨对象签发／列出／撤销／全部撤销，已知链接ID也不能扩大管理权限；明确分享的Bearer链接可由另一已登录账号读取，其Cookie身份不会混入分享授权。该脚本另加入CI九版兼容任务并要求PDO SQLite前置条件；CI YAML解析通过，本轮未触发远端CI。
- 隔离PHP7.2／8.5各通过390像素Chromium真实表单：登录签发、不同浏览器公开读取、正文HTML标签按文本显示、撤销后拒绝、GET兑换页不消费、明确POST兑换和重放拒绝、退出，无页面脚本异常或横向溢出。已查看 `/tmp/sosecurity-link-mobile.png`；截图及URL均为自建测试数据，不是生产链接。
- 九版本新消费者重新安装包，执行HEAD不消费／一次性验证／重放拒绝及撤销；未配置原生入口从消费者自动加载后仅返回link.unavailable。PHPStan level5／PHP7.2目标、Composer严格校验、220文件发行包通过；包内有Link全部7个源码文件、原生页面及指南，排除测试、开发和私有配置。315处本地文档链接及git diff --check通过；新增能力无必需第三方运行时依赖。

### 已执行但失败，随后修复并复验

- 初次最小运行调用了Uri不存在的query()访问器，运行失败；改为比较Uri::path()与原始path即可同时拒绝查询及路径别名，没有扩充不必要的URI接口。最终九版核心／语法和原生流程通过。
- 初次独立向量的模式篡改生成器连续替换两次，把一个负例变回合法原链接，导致预期拒绝的断言失败。改为按原模式单向替换，保留正例与单次／重复结果检查；最终九版各104项通过。本项为测试数据生成修复，不描述为验签绕过。

最终采用日志：`/tmp/sosecurity-r35-php{72,73,74,80,81,82,83,84,85}-full-verified.log`、`-consumer-verified.log`及独立双账号`-owner.log`。早期core.log记录631项阶段核心，最终采用663项；首轮518项HTTP之后增加密钥输入和HTTPS拒绝边界，最终采用542项。临时本机记录不随发行包分发。

### 未执行与边界

- 原生示例成功路径使用显式许可的隔离本机HTTP；已验证默认HTTPS拒绝明文，但本批没有配置原生HTTPS成功路径或真实反向代理。已有其他模块TLS测试不能代替本页面的HTTPS验收；继续纳入R1／R5／R6相应部署验证。常驻Apache未配置此示例私有账号／文档库或密钥，未作实际站点接入结论。
- 未接入真实账号／生产库，未执行生产驱逐／持久性／时钟／旧备份恢复、Windows、本批远端CI、公开发布或独立审查。密钥快照轮换须传播到全部工作进程；策略变更需显式迁移。字段与资源版本的权威性仍由宿主维护。
- 分享URL是明确Bearer能力，管理仍需当前权限；账号退出不自动收回所有分享。撤销只影响后续验证，不能收回已读内容或中断已开始响应；一次性消费只保证账本内单次授权，不保证业务事务恰好一次。原生页面是有界签名流程示例，私有文件路径／符号链接、内容摘要／流读取及Range下载继续R3.6。

## R3.4 高风险操作授权与真实认证接入（2026-10-17）

本段覆盖操作授权核心、工厂／诊断、SQLite／MySQL事务示例及独立原生页面。本地验收完成，完整R1—R6仍继续；未将生产部署或高级协议计入通过。

### 已执行并通过

- PHP7.2.34／7.3.33／7.4.33／8.0.30／8.1.34／8.2.32／8.3.35／8.4.23／8.5.9最终严格bin/check.sh和独立Composer消费者全部通过。逐版核对完整日志：各392操作核心、88 SQLite、88 MySQL、871原生HTTP，124类API及236个PHP文件语法通过，采用日志无FAIL／NOT RUN、运行时警告或异常回溯。
- 核心验证精确动作／资源版本／参数／字段绑定、准备后的同会话秘密轮换、默认方式／强度／年龄、三阶段单次转换、跨会话及篡改拒绝、撤销／禁用／角色／凭据变化、请求保护、前后身份和权限复核、提交后依赖／时间变化清理、有界参数／容量和可重试纯事务回调。核心及竞争测试使用明确标注的模拟认证证明，真实密码和TOTP另由原生HTTP／浏览器证明。
- 各版本真实File／Redis／MySQL后端，每场景24个PHP进程：同一confirmation仅一次成功转为grant，同一grant仅一次返回Permit；再次竞争全部拒绝，容量8只接受8项准备，精确到期边界24次消费全部拒绝。成功凭据仅通过测试私有0700目录中的0600文件交给父进程，不打印秘密，也不在事务回调做文件I/O。
- 各版本SQLite和MySQL原生预处理验证唯一执行ID、租户／归属／资源版本／权威账号版本及期限。恢复共享grant和旧资源版本仍被SQL唯一receipt阻止；冲突、真实三秒慢SQL过期均回滚业务与receipt，已消费grant不能退还。新增真实PasswordIdentityProvider／AuthenticationFlow密码重新认证，证明原始版本与有效身份的映射、保存哈希条件及错误PasswordRecord拒绝；故意陈旧的身份适配也不能越过SQL原始版本／哈希条件。
- 各版本871项原生HTTP断言使用独立SQLite账号源、真实bcrypt／TOTP／恢复码、原生Cookie和CSRF：先准备／展示，再重新认证／明确确认，确认阶段不改业务，执行才提交唯一receipt及文档版本。密码与恢复码不能满足默认强操作策略；显式密码配置单独验证。旧review_id、不同浏览器会话、客户端替换title／额外字段、资源版本／归属变化、角色撤销／禁用、密码哈希变更但原始版本未增加、源下线均拒绝或使会话失效，业务数据保持。nonce／grant／会话秘密和密码哈希不出现在页面JSON。
- 隔离PHP7.2／8.5各通过密码、TOTP两种390像素Chromium原生表单流程：标题／对象／版本明确展示，HTML标签作为文本显示，旧标签页不能确认新提案，重新认证保持注册会话ID、确认与执行分离、执行后退出，无脚本异常或横向溢出。Python同时核对真实SQL标题和唯一receipt。已查看 `/tmp/sosecurity-operation-totp-mobile.png`；相应密码截图为 `/tmp/sosecurity-operation-password-mobile.png`。
- 九版本消费者重新通过Composer安装复制包，执行真实密码提供器的有效身份映射、准备／新证明／确认／单次消费，导入SQL辅助示例；未配置的原生入口通过安装包自动加载后仅返回通用operation.unavailable。PHPStan level5／PHP7.2目标、Composer严格校验、211文件发行包通过，包内包含操作授权全部8个源码文件、原生页面、SQL示例及指南，排除测试／开发数据。298处本地文档链接及git diff --check通过；新增能力无必需第三方运行时依赖。

### 已执行但失败，随后修复并复验

- 初次真实HTTP执行合法授权返回409：PasswordIdentityProvider使用原始账号版本与保存哈希合成的有效版本，而旧SQL示例直接比较原始数据库version。增加PasswordRecord::identity()复用既有身份计算；示例先核对有效账号指纹，再联合比较原始version与保存password_hash。九版本最终SQL／HTTP及消费者均通过，原有哈希变更撤权能力保留。
- 初次浏览器测试在POST准备后直接reload，浏览器重发POST而生成了新提案，导致测试期望的旧工作流ID不一致。测试改为明确GET查看当前提案；跨标签页场景仍保留真实旧表单提交，最终两种运行时和两种认证策略均通过。本项是测试导航修正，不描述为已修复浏览器自身行为。

最终采用日志：`/tmp/sosecurity-r34-php{72,73,74,80,81,82,83,84,85}-full-verified.log` 与 `-consumer-verified.log`。此前focused及首轮824项HTTP是开发阶段证据；最终采用当前代码的392／88／88／871结果。这些本机临时证据不随发行包分发。

### 未执行与边界

- 未在常驻Apache配置该原生页面的私有业务库或MFA密钥；未接入真实账号、生产操作、通知或外部支付。未执行本批Windows、远端CI、公开发布、生产恢复或独立安全审查。常驻PHP-FPM7.2的sodium缺失不因隔离CLI成功而被视为解决。
- 共享消费与SQL提交不属于同一事务；失败后需要重新确认，不承诺退款、跨资源恰好一次或收回已发生的外部副作用。SQL示例要求权威账号版本、短事务和每次失败回滚，检查不是COMMIT钩子，返回后长暂停再提交不受期限保护；角色／因子要求等变化仍须推进原始业务版本。
- 浏览器明确确认不是可信硬件显示或抗钓鱼交易签名；WebAuthn方法标签不代表协议已实现。完整R1、R3.5—R6及其最终验证继续保留。

## R3.4 核心与SQL初步阶段，历史记录（2026-10-17）

### 已执行并通过

- PHP7.2.34／7.3.33／7.4.33／8.0.30／8.1.34／8.2.32／8.3.35／8.4.23／8.5.9定向检查：各392操作核心、68 SQLite、68 MySQL及39配置断言；源码语法、124类候选及公开／内部分类通过。采用日志无FAIL／NOT RUN或运行时警告，PHPStan level5／PHP7.2目标通过。
- 核心覆盖准备后新秘密轮换、默认认证方式／强度／年龄、不同会话不可借用、三阶段单次转换、参数／资源版本变化失效、退出／禁用／角色／身份变化、请求保护、前后权限复核、提交后依赖变化／超时清理、有界参数及容量、状态／策略指纹和明文隐藏。事务回调重复执行得到相同状态和结果；认证证明在本阶段由测试适配模拟，未冒称真实TOTP／WebAuthn协议验证。
- SQLite和MySQL原生预处理实际执行唯一receipt、租户／资源／归属／账号版本与期限条件。测试同时恢复缓存授权和旧文档版本，唯一执行ID仍拒绝重放；账号／资源冲突及三秒慢SQL触发器过期均回滚文档和receipt，已消费grant不能退款。
- 初次依赖故障测试发现身份服务运行时异常原样传播，现已转换为固定的operation.authentication_unavailable并不串联敏感异常；请求保护异常同样单独脱敏，最终定向检查通过。

定向日志：`/tmp/sosecurity-r34-php{72,73,74,80,81,82,83,84,85}-focused.log`。临时MySQL为独立无TCP测试实例，未访问生产数据。

### 本阶段当时未执行，已由上节补齐本地验收

本节完成时，真实认证与明确确认HTTP／浏览器、File／Redis／MySQL共享并发、独立消费者和完整九版检查尚未执行；现已由上节当前代码的最终记录补齐。生产接入仍未执行；本段历史定向证据不能代替上节验收或R1—R6整体交付。

## R3.3 并发租约、期限与旧任务隔离（2026-10-17）

本段覆盖[并发租约](leases.md)、显式初始化的永久序号账本、工厂／诊断、独占SQL示例及访客演示。最终代码的九版本严格完整检查和独立消费者安装全部通过，采用日志无FAIL／NOT RUN或运行时警告。R3.3本地验收完成，整体R1—R6继续。

### 已执行并通过

- PHP7.2.34／7.3.33／7.4.33／8.0.30／8.1.34／8.2.32／8.3.35／8.4.23／8.5.9各418租约专项断言：1—64名额、单owner不重复占位、固定总生命周期、期限内续期／过期拒绝、资源／作用域／owner／秘密绑定、旧释放不影响替代持有者、永久序号与新epoch、排空／预期epoch清理、损坏／指纹／时钟／缺失账本拒绝和无明文凭据存储。
- 获取／续期／验证的存储前后延迟、提交后时钟回退均拒绝放行；事务回调重复执行得到一致状态、期限和凭据，不在回调读取时钟或生成随机数。64持有者实际经MemoryStore的有界Codec编码；自然过期后新租约保持递增序号。
- 九版本真实File／Redis／MySQL，各24进程并发：5个名额仅接受5名不同持有者，同一凭据24次有效续期保持单条租约，24次释放仅一次成功，替代持有者建立后旧凭据24次释放／续期均拒绝。强制SIGKILL真实PHP持有进程，未运行析构／finally；名额在期限内仍占用，推进专用测试时钟到边界后恢复，隔离序号继续递增，旧释放无效。
- 最终九版本真实SQLite及MySQL各23项SQL检查全部通过；MySQL采用原生预处理。固定epoch／严格更大序号取得业务权限，写入检查租户／资源／序号／摘要／版本／数据库期限；暂停前已验证的旧快照、已退休权限、旧账本备份及新账本epoch均不能覆盖当前业务数据。数据库真实期限及三秒慢触发器导致过期时拒绝并由宿主回滚，原输出保持不变。
- 九版本最终独立Composer消费者重新安装并执行新租约API和SQL示例导入，通过显式初始化／名额／释放后旧凭据拒绝检查。九版本各125原生演示HTTP断言通过：Cookie／CSRF、未初始化拒绝、持有者隔离、容量／续期／到期／序号、旧释放、受控删除及故障；秘密不出现在页面或JSON。
- 隔离PHP7.2／8.5及实际Apache/PHP-FPM7.2，390像素Chromium均通过真实表单／AJAX：初始化／获取／步骤、到期恢复、旧释放409而新租约保持有效、访客隔离、无页面脚本错误与横向溢出。实际Apache另通过125项HTTP。已查看 `/tmp/sosecurity-lease-mobile.png`。这些网页仅使用访客Session，共享能力由独立三后端测试证明。
- PHPStan level5／PHP7.2目标、118类／接口候选及公开／内部分类、Composer严格校验、200文件发行包、相关指南177处本地链接通过。无新增必需第三方依赖；工厂构造和示例导入不启动Session、不创建业务表或发送响应头。

### 已执行但失败，随后修复并复验

- 增加慢SQL触发器后，初次SQLite检查证明原示例未按预期抛错：语句起始期限条件不能覆盖执行期间的全部延迟。已增加claim／write／renew返回前的新SQL时间及工作节点时间复核，九版本SQLite／MySQL最终23项均通过。检查不是COMMIT时钩子，宿主必须回滚并保持短事务。
- 另一次状态机复现证明：先判定过期，再把测试时钟回拨，未持久化观察时间的查询可重新接受旧凭据。已让verify／inspect／重复initialize保存观察时间并清理过期持有者；晚返回的失效凭据再做精确清理，不误删并发替代持有者，相关回退／恢复测试并入最终九版各418项。
- 初次MySQL慢触发器测试因临时实例启用二进制日志、测试账号无SUPER而失败。只将本地一次性无TCP实例的启动参数设置为 `--skip-log-bin`，未扩大应用账号权限或修改生产配置；后三版完整检查已在该环境重跑通过，九个版本均以最终代码和调整后的测试实例完成完整复验。初始失败日志保留，不作为验收采用日志。

最终采用日志：`/tmp/sosecurity-r33-php{72,73,74,80,81,82,83,84,85}-full-verified.log` 和对应 `-consumer-verified.log`，均在最后观察时间及晚返回清理修复后完整执行，包含全部SQL与并发场景。较早的full、full-final及SQL补充日志保留为开发过程证据，不冒充最终验收；这些本机临时记录不随发行包分发。

### 未执行与边界

- 未接入生产任务、共享业务入口或使用方数据库；未验证生产时间同步、驱逐／持久性、旧备份／副本切换及总资源容量，未执行本批Windows、远端CI、公开发布或独立安全审查。
- 租约描述期限内的持有权，不能停止已暂停进程或替任意外部副作用提供恰好一次语义。SQL示例仅支持SQLite／MySQL的独占条件写入，宿主拥有事务、授权、时钟与恢复；检查返回后长时间暂停再提交不受期限钩子保护。多名额信号量不等同于同资源独占锁。

## R3.2 加权预算、三算法与组合范围验收（2026-10-17）

本段覆盖[请求预算组件](request-budgets.md)、工厂／诊断、独立报表示例及访客网页；完整R1—R6规划继续，预算不承担并发租约职责。全部运行时采用最终代码的成功日志。

### 已执行并通过

- PHP7.2.34／7.3.33／7.4.33／8.0.30／8.1.34／8.2.32／8.3.35／8.4.23／8.5.9九版本严格 `bin/check.sh` 完整检查及独立Composer消费者安装通过；采用日志无FAIL／NOT RUN或运行时警告。既有MFA205、认证199、持久登录499、授权77／42 SQLite／71 HTTP保持通过。
- 九版本各759预算专项断言：整数分数信用、加权补充／突发、首次接受锚定的固定窗口、精确秒级滑动历史与同秒合并、最早重试、历史容量拒绝、成本永不适配、预览不改状态／TTL、指纹变化／损坏／时钟回退拒绝、显式重置和共享工厂边界。
- 原子组全量检查后一次扣减；拒绝保留全部子项余额，成员顺序调整保持同账本。顺序组合的IP／账号／租户共享规则、后项拒绝保留前项、不访问未检查项、全部成本／绑定预检及后项存储故障拒绝已验证。重复执行事务回调生成一致状态、期限与结果，回调无时钟或外部副作用。
- 存储前／后推进测试时钟，单项／原子组／顺序组合均拒绝已过期配额；另测后项I/O导致前项过期、提交后时钟回退，不返回业务放行。最大配置滑动历史及接近平台整数上限的时间通过Codec编码和有效状态检查，未把PHP64位运行结果称为32位系统实测。
- 九版本各10,800组独立Python对照数据：Fraction有理数令牌模型、固定窗口与已接受历史模型，对照PHP的允许／余额／retry／原因；包含随机成本、只读、重置和时间边界，不依赖PHP内部状态字段。
- 九版本真实File／Redis／MySQL，各场景24进程同时竞争：令牌桶／固定／滑动三算法在10单位、成本2时只接受5次；原子组10请求单位＋15工作单位按2／3扣减只接受5次，拒绝不多扣任一余额；顺序组合只接受5次业务但保留全部24次入口扣减。MySQL运行使用隔离无TCP实例，Redis使用私有Unix套接字；没有操作生产服务。
- 九版本各107原生HTTP断言：Cookie／CSRF、固定动作成本而非客户端cost、三算法、拒绝和异常不增加业务执行次数、原子／顺序扣减差异、切换IP仍受账号限制、访客隔离、时间与管理操作。实际Apache/PHP-FPM7.2演示同样通过107项。演示预算是访客Session，真实跨Session共享能力由上述独立后端测试证明。
- 隔离PHP7.2／8.5与实际Apache各通过390像素Chromium表单／AJAX检查：加权拒绝、原子组余额、顺序组合保留IP扣减、访客隔离、无页面脚本错误及横向溢出。已查看 `/tmp/sosecurity-budget-mobile.png`；实际共享业务站点未接入。
- PHPStan level5／PHP7.2目标、114个类／接口候选及公开／内部分类、Composer严格校验、193文件发行包与受影响指南119处本地链接通过。新增功能未添加必需第三方依赖；新增类和报表示例导入不启动Session或发送响应头。

可复查日志：`/tmp/sosecurity-r32-php{72,73,74,80,81,82,83,84,85}-{full,consumer}.log`。这些是本机临时证据，不作为随包文件或生产监控记录。

### 未执行与边界

- 未修改使用方业务入口或生产预算配置，未验证真实生产时钟、后端持久性／驱逐策略、请求覆盖和全局键容量；未执行本批Windows、远端CI、公开发布或独立安全审查。
- 滑动历史精确到秒，固定窗口仍有边界突发；retry不是未来可用额度承诺，结果不能缓存。预算不会终止已运行任务，不保证跨键／跨业务数据库事务、任务恰好一次或旧进程隔离；R3.3租约及后续阶段继续实施。

## R3.1 授权接口与对象／字段／批量验收（2026-10-17）

本段覆盖默认拒绝授权及独立原生接入；完整R1—R6继续按[需求跟踪](security-refinement.md)推进。生产业务规则和数据库一致性仍由使用方验收。

### 已执行并通过

- PHP7.2.34、7.3.33、7.4.33、8.0.30、8.1.34、8.2.32、8.3.35、8.4.23、8.5.9九版本完整 `bin/check.sh` 成功，沿用八个严格门禁，最终日志没有`FAIL`／`NOT RUN`。启动前读取检查脚本完整快照，运行期间没有修改入口。
- 九版本各77项授权专项：无策略／匿名／未知动作默认拒绝、作用域与身份版本、角色／归属／严格属性约束、组合全部通过及字段交集、投影不返回其他字段、100项批次及重复／非法资源拒绝、元数据引用与预算、权威源／策略／审计故障、构造／导入无Session或响应头副作用。
- 九版本各42项真实SQLite检查：租户限定、归属和越权字段、混合批次及数据校验失败无写入、未授权错误版本仍通用拒绝、授权后读取允许列、条件更新和宿主完整回滚。真实SQL触发器在首项写入后改变次项目版本，触发冲突且回滚首项；视图中的数据库函数证明普通／未授权请求未读取机密列，授权私有列才执行该函数。
- 九版本各71项原生HTTP：真实密码／共享会话／Cookie与CSRF、跨租户参数不能改变查询范围、其他归属对象／字段拒绝、整批拒绝及触发器冲突回滚、角色变更使旧会话失效、身份源故障和禁用账号不继续读写；全部响应no-store。
- PHP7.2／8.5原生Chromium表单完成登录、字段拒绝、带版本更新、其他归属对象拒绝，错误后表单仍可继续操作；390px无横向溢出，未显示机密列。已查看截图 `/tmp/sosecurity-authorization-mobile.png`。
- 九版本新Composer消费者独立安装、PSR-4、RolePolicy／Authorizer与字段拒绝、SQL适配文件导入通过；原有MFA205／认证199／持久登录499专项及真实三后端检查保持通过。
- PHPStan level5／PHP7.2目标、108类候选及公开／内部分类、Composer严格校验和183文件发行包检查通过；新增文件不包含测试数据、私有文档库或开发依赖。

### 已执行但失败及修正

- 开发初次身份查询计数测试包含了此前未知动作的查询，已隔离计数范围；实际身份变更回调仍独立验证授权后复核会拒绝旧身份，没有删掉安全断言。
- 新机密列读取证明用到SQLite自定义函数，PHP8.5对旧PDO方法报告弃用；测试改用该版本驱动专用 `PDO::connect()`／`Pdo\Sqlite::createFunction()`，旧版继续其原生方法。保留严格错误处理，没有屏蔽弃用，最终九版本42项全部通过。

### 复现与边界

- 完整日志 `/tmp/sosecurity-r31-php{72,73,74,80,81,82,83,84,85}-full.log`；独立消费者同前缀 `-consumer.log`。
- 单项：`<runtime> tests/authorization.php`、`<runtime> tests/authorization-sql.php`、`python3 tests/authorization_http.py <runtime>`。浏览器加 `--browser` 并设置现有 `SOSECURITY_PLAYWRIGHT_MODULE`。
- 常驻Apache未配置原生示例的私有文档库，不声称其文档授权路径已验收。未修改使用方权限规则／业务库，未证明生产数据库隔离、跨权威源原子撤权、远端CI、公开发布或独立安全审查。
- 新增组件不替代宿主认证、API scope、CSRF、载荷校验或事务。字段为精确顶层白名单，复杂嵌套DTO、分布式权限版本及回调时限见[授权指南](authorization.md)。

## R2.6 密码精修验收（2026-10-17）

本段覆盖密码策略、拒绝表、可选泄露检查和成本校准；完整精修仍按[需求跟踪](security-refinement.md)继续。九版本完整检查及最终补充验证均已完成，受影响版本只采用修正后成功的日志。

### 已执行并通过

- 九版本 `bin/check.sh` 完整检查及最终密码／重置／校准／消费者补充检查通过，采用日志没有`FAIL`／`NOT RUN`；PHP7.2构建的Argon2id不适用并已验证拒绝，未伪装支持。既有认证199、MFA205、持久登录499项及三种真实后端24进程保持通过，演示HTTP扩为126项。
- 九版本密码专项：PHP7.2.34为82项，并明确验证Argon2id不可用时拒绝；其余PHP7.3.33／7.4.33／8.0.30／8.1.34／8.2.32／8.3.35／8.4.23／8.5.9各89项。覆盖按算法匹配字节／Unicode预算、本地全串匹配和快照校验、默认／显式服务注入、HIBP范围与零填充、完整畸形响应拒绝、异常不串联秘密、保存哈希成本预检和Argon2成本不降级。
- 九版本SQL重置边界各21项：短／弱／已泄露或泄露服务故障不消费令牌、不改SQL，随后同一有效令牌仍可成功；并发版本、宿主事务和提交后清理失败语义保持通过。
- 隔离POSIX子进程校准：PHP7.2各35项，其余各42项，包含探测／总预算终止、无真实密码参数／输出、不写配置、错误参数／不可用算法、禁用进程控制及导入无执行。实际样本时延不作为跨机器固定结果。
- 最终九版本原生TLS／DoH测试：固定HIBP目标、Add-Padding、计数0、HTTP错误／重定向／超时／响应体和头预算、坏CA；静默OS DNS仍可通过有界DoH和精确IP连接。慢DoH配置500ms总预算，外层实测验证不早于400ms且在2.5秒内返回、无OS DNS请求；不把进程启动／调度容差称为精确500ms墙钟保证。每次独立网络／挂载命名空间和测试CA，不改宿主DNS／CA。
- 最终实现通过真实公开HIBP已知测试词查询（PHP8.5），未使用用户密码、邮箱或私有服务密钥；这不代表使用方生产账号已接入。
- 九版本新Composer消费者包含默认弱密码拒绝、显式范围适配和可用时的长Argon2id策略；安装副本中的校准工具实际启动，导入无执行且未配置认证仍安全拒绝。
- 隔离PHP7.2／8.5及实际Apache `http://72.rocky.wsl/SoSecurity/` 的Chromium：真实表单弱密码拒绝、AJAX正常通过、密码不回填／不出现在结果、离线状态文字及390px布局；截图 `/tmp/sosecurity-password-mobile.png`。
- PHPStan level5／PHP7.2目标、101类API候选、原有80类参数前缀兼容性复核、173文件归档及Composer严格校验通过；PasswordPolicy有意追加末尾可选服务参数，行为变化见[密码指南](passwords.md)。

### 已执行但失败及修正

- 初版直接cURL请求在静默OS解析器下超过3秒，不能证明DNS总预算；已替换为现有有界DoH／精确IP客户端，最终九版本相同阻塞条件通过。旧失败日志保留，不计作新实现通过证据。
- 开发期间修改了运行中的Bash入口，导致PHP8.3／8.4／8.5出现解析错误；此前结果不计通过。入口已冻结并在启动前读取完整脚本快照，三个版本已完整重新执行并通过。
- 迁移传输后测试曾错误区分HTTP请求头大小写，已按协议改为不区分大小写；未放宽填充值、目标、无Cookie／Authorization或路径的断言。

### 证据与复现

- `bin/check.sh <runtime>`，沿用八个严格门禁；首轮日志 `/tmp/sosecurity-r26-php{72,73,74,80,81,82,83,84,85}-full.log`，受影响版本最终以 `-full-final.log` 为准。专项／最新重置与校准／消费者补充日志为各 `-extra.log`。
- `SOSECURITY_REQUIRE_NATIVE_HTTP=1 python3 tests/native_password.py <runtime...>`：最终 `/tmp/sosecurity-r26-native-password-current.log`；旧阻塞失败为 `-native-password-final.log`。传输缺失与显式适配九版本证据为 `-transport-capabilities.log`。
- 浏览器用现有Playwright设置 `SOSECURITY_PLAYWRIGHT_MODULE`，执行 `python3 tests/password_browser.py <runtime>`；常驻演示可传 `--url http://72.rocky.wsl/SoSecurity/`。仅创建自己的访客测试状态。

### 未执行

未导入客户真实拒绝表、未查询私人密码、未校准／修改生产哈希配置，未验证使用方并发容量、远端CI、发布或独立安全审查。基础弱密码集不称为完整泄露数据；默认DoH和显式企业／离线适配的数据责任分开，原始PHP7.2构建不声称支持Argon2id。

## R2.5 持久登录验收（2026-10-17）

本段覆盖记住登录的本地验证，R1—R6完整精修继续实施，状态见[逐项跟踪](security-refinement.md)。

### 已执行并通过

- PHP7.2.34、7.3.33、7.4.33、8.0.30、8.1.34、8.2.32、8.3.35、8.4.23、8.5.9九版本完整检查全部成功，沿用八个严格门禁，最终日志无`FAIL`／`NOT RUN`；新增TLS又分别补充执行，原有MFA各205／认证各199断言及原生认证HTTP各192均保持通过。
- 九版本专项 `tests/remember.php` 各499项断言：明确选择／近期证明、固定授权期限、恢复来源／敏感操作拒绝、旧会话秘密失效、签名代际轮换／密钥轮换、并发重试、重放全体撤销、单设备／全部退出、忘记设备、容量、损坏状态、时钟倒退、可重试回调、存储故障、v1账本迁移、工厂注入及真实加密MFA来源。
- 九版本原生HTTP `tests/remember_http.py` 密码／TOTP／恢复码各182项累积断言；真实Session／Cookie和CSRF、GET不自动恢复、并发旧响应不覆盖新Cookie、旧代际重放撤销、重新认证、忘记／退出及禁用来源均通过。
- 三种真实后端文件／Redis／MySQL分别通过24进程竞争：同令牌仅一次轮换，其他请求只重试；窗口后重放在同一主体事务撤销会话及持久授权。该场景在九版本完整检查中执行。
- 九版本各执行真实TLS `tests/remember_https.py` 25项和新的Composer消费者安装。测试使用每次独立CA验证TLS证书，检查默认Secure／HttpOnly／SameSite=Lax／无Domain的`__Host-` Cookie、持久性、轮换、恢复后近期认证拒绝及退出清除；不修改系统信任或现有Web配置。
- 九版本各执行独立Python/PHP令牌互操作27项：HMAC-SHA256、UTF-8字节长度、最大代际和严格拒绝非规范／跨作用域输入。
- PHP7.2／8.5原生示例真实Chromium：密码／TOTP／恢复码表单、只保留持久Cookie后的匿名GET／POST恢复、Cookie轮换、HttpOnly对脚本不可见、重新认证和全部退出；390px布局通过，并检查 `/tmp/sosecurity-auth-example-mobile.png`。
- PHPStan level5／PHP7.2目标、Composer严格校验、168文件归档检查通过；公开99类候选完整，原有HEAD基线80类全部签名保留。

### 复现与证据

- `bin/check.sh <runtime>` 包含专项、原生HTTP、独立向量及TLS检查，沿用八个严格环境开关。完整日志 `/tmp/sosecurity-r25-php{72,73,74,80,81,82,83,84,85}-full.log`；TLS／独立安装补充日志同前缀 `-extra.log`。
- 九版本运行时沿用下节的隔离sodium配置；系统原始 `php72` 另执行专项494项，并明确输出未执行加密MFA的5项。两种构建证据分开，不称其扩展已安装或常驻Apache已获得MFA能力。
- Chromium通过 `SOSECURITY_PLAYWRIGHT_MODULE` 指向现有Playwright，再执行 `python3 tests/auth_example_browser.py <runtime>`；截图为独立测试账号，不含持久令牌。

### 未执行

使用方生产账号／浏览器、实际集群及备份恢复、远端CI、公开发布与独立安全审查未执行。浏览器使用显式本地HTTP例外；TLS证据来自验证证书的独立HTTP客户端。完整可信设备与风险策略继续R6.3，不将基础设备标签当作硬件证明。

## R2 认证与会话撤销验收（2026-10-17）

本段补充 R2.3／R2.4；完整 R1—R6 继续实施。状态、范围及剩余要求见 [精修跟踪](security-refinement.md)。

已执行并通过：

- PHP 7.2.34、7.3.33、7.4.33、8.0.30、8.1.34、8.2.32、8.3.35、8.4.23、8.5.9 九版本运行 `bin/check.sh`，沿用下节八个严格门禁。全部成功，最终日志没有 `FAIL`／`NOT RUN`。源码语法、96 个公开类／接口候选及既有能力回归通过。
- 各版本 `tests/auth.php` 199 项专项断言：本地密码／配置身份、凭据哈希及角色变化、禁用、跨作用域、旧会话、空闲／绝对期限、重新认证、真实 TOTP／恢复码、因子版本变化、撤销代际、租约过期及旧持有者晚到、服务故障额度恢复、状态损坏与工厂配置。
- 文件／Redis／MySQL 各 24 进程：容量5只登记5个；同一旧秘密只允许一次重新认证轮换；全部退出后的旧代际登记0个；同一待 MFA 登录只产生1个完整会话。测试权威源只用于并发控制，实际密码和因素由其他专项验证。
- 独立原生 HTTP 示例最终每版本 192 项检查：真实 Cookie／Session 更新、旧 Cookie 与旧 CSRF 拒绝、密码／TOTP／恢复码、单个／全部会话撤销、旧待 MFA 登录失效、当前哈希／角色／禁用状态、近期重新认证及固定绝对期限、来源不可读／移除和明确 null 策略字段拒绝。补充权限及 null 字段后，九版本分别重跑最终 HTTP 专项。
- 访客隔离演示每版本最终 66 项 HTTP 检查，包括管理编号不能撤销其他访客记录、容量超限返回409及清理模拟未来时间后的恢复；远程身份适配契约每版本 24 项真实本地 HTTP 检查，包括当前作用域／版本／角色／禁用、畸形额外字段和服务故障。远程测试不代表生产发行方或 TLS 验收。
- 隔离 PHP7.2／PHP8.5 的 Chromium 实际运行独立认证示例：原生密码登录、TOTP、恢复码重新认证、Session ID 变化、近期认证到期、管理编号／绝对期限保留、全部退出和移动布局；独立 Node HMAC 生成测试 TOTP。诊断展示不输出 CSRF，表单隐藏字段继续正常提交。
- 隔离 PHP7.2／PHP8.5，以及实际 `http://72.rocky.wsl/SoSecurity/` 的 Chromium／HTTP 认证演示通过：表单／AJAX、原生 Session 更新、权限变更失效、访客隔离和移动布局。已检查截图 `/tmp/sosecurity-auth-mobile.png` 与 `/tmp/sosecurity-auth-example-mobile.png`；这是测试账号与独立示例，不是使用方生产登录验收。
- 九版本 Composer 新消费者调用认证、重新认证、会话撤销及 MFA API，并确认已安装原生示例从消费者自动加载器启动后，缺少显式配置时安全拒绝。源包归档检查通过，162 个文件，未引入框架或第三方强制运行时依赖。PHPStan level5／PHP7.2目标及严格 Composer 清单检查通过。与当前 HEAD 逐字段比较，原有80个公开类／接口及既有方法签名全部保留，新增16个类／接口及原类上的7个方法；这是兼容性检查，不是稳定API冻结。

本地复现及证据位置：

- 使用下节相同的隔离扩展运行器，完整日志 `/tmp/sosecurity-r23-phpNN-full.log`（NN 为72、73、74、80、81、82、83、84、85）。后续加强检查的最终日志分别为 `-http-final.log`、`-demo-final.log`，前缀相同。
- CLI／HTTP／演示／远程契约：`<runtime> tests/auth.php`、`python3 tests/auth_http.py <runtime>`、`python3 tests/auth_demo.py <runtime>`、`python3 tests/auth_remote.py <runtime>`；并发包含在 `tests/concurrency.php`，需使用隔离后端。
- 浏览器：已有 Playwright 下执行 `python3 tests/auth_example_browser.py <runtime>`、`python3 tests/auth_browser.py <runtime>`，设置 `SOSECURITY_PLAYWRIGHT_MODULE`。常驻演示可使用 `--url http://72.rocky.wsl/SoSecurity/`（仅 auth_browser.py／auth_demo.py），只创建并清理当前访客测试数据。

已执行但初次失败后修正：静态分析发现租约上限与挑战下限已隐含相同约束的冗余比较，删除重复条件后通过；未添加忽略或基线。源码复核补充占位哈希参数匹配、观察到明确失去身份时的登记撤销、配置 null 类型拒绝、私有读取错误抑制和安装目录自动加载器检查，并由对应专项复验。

边界：身份／因子／业务数据库之间没有跨资源事务承诺；版本条件写入和可靠通知由宿主实现。远程 SDK 的真实发行方、OAuth/OIDC/SAML、生产业务、公开发布、远端 CI 和独立审查没有由本批证明完成。记住登录、密码策略深化及其他 R1／R3—R6 要求继续实施。

## R1／R2 第一批精修验收（2026-10-17）

本段为本轮新增证据。完整 R1—R6 尚在实施，见 [需求跟踪](security-refinement.md)；以下结论只覆盖本次实现和相应回归范围。

已执行并通过：

| 运行时 | `bin/check.sh` 严格检查 | 最新 `tests/mfa.php` | 独立 Composer 消费者 |
| --- | --- | --- | --- |
| PHP 7.2.34 | 通过 | 205 断言 | 通过，调用新 TOTP／加密因子 API |
| PHP 7.3.33 | 通过 | 205 断言 | 通过 |
| PHP 7.4.33 | 通过 | 205 断言 | 通过 |
| PHP 8.0.30 | 通过 | 205 断言 | 通过 |
| PHP 8.1.34 | 通过 | 205 断言 | 通过 |
| PHP 8.2.32 | 通过 | 205 断言 | 通过 |
| PHP 8.3.35 | 通过 | 205 断言 | 通过 |
| PHP 8.4.23 | 通过 | 205 断言 | 通过 |
| PHP 8.5.9 | 通过 | 205 断言 | 通过 |

- 严格检查设置 `SOSECURITY_REQUIRE_CRYPTO/REDIS/MYSQL/HTTP/HTML/UPLOAD/RESET/POSIX=1`，实际对应八个完整环境变量；没有通过跳过缺少扩展的测试制造成功。包括原有功能、真实隔离 Redis/MySQL、部分写失败、原子状态、HTTP 和演示回归。
- MFA 专项包含全部 18 个 RFC 6238 独立向量、Python HMAC 独立计算的高 32 位非零／接近 64 位整数上限计数、畸形编码／输入、确认／重放、共享错误预算、恢复码轮换、因子替换／禁用／撤销、密钥重加密、损坏状态、时钟倒退、存储故障及宿主示例拒绝路径。完整矩阵后增加高位计数向量，各版本单独重跑专项至 205 断言。
- 九版本的文件、Redis、MySQL 后端分别验证 24 进程竞争：同一绑定确认、同一 TOTP 证明和同一恢复码都只有一次接受。测试只操作自己创建的隔离状态，结束清理模拟未来时间的记录。
- `tests/crypto_vectors.py` 每版本 48 项检查，独立调用 libsodium C API，双向验证 PHP 封装、二进制内容、Unicode 对象绑定和跨对象拒绝。
- `tests/mfa_demo.py` 每版本 55 项真实 HTTP 检查，Python 标准库独立计算 TOTP，验证 CSRF、访客隔离、确认、重放、恢复码、密钥轮换、因子替换、清理和故障拒绝。
- 隔离 PHP 7.2／PHP 8.5 的 Chromium 移动端实际运行 `tests/mfa_browser.py`：原生表单、AJAX、独立 Node HMAC 计算、恢复码／重放、重加密、访客隔离、状态不包含秘密、无脚本异常及无页面横向溢出。已查看截图；开发截图位于 `/tmp/sosecurity-mfa-mobile.png`，不作为永久发行文件。
- 九版本通过 84 个公开类／接口候选签名检查；新增源文件必须显式归入公开或内部清单。PHPStan level 5／目标 PHP7.2 通过，核心与可选 HTML／开发工具清单审查通过，两个独立依赖项目的 `composer audit --locked` 未发现漏洞公告。
- Composer 实际安装的消费者调用新 TOTP、Cipher、TotpFactors 和示例；普通无 sodium 的 PHP7.2 消费者单独确认明确依赖拒绝。发行归档检查通过，146 个文件，排除开发／私有文件名。

环境与复现：

- 本机部分 PHP 缺少 sodium、POSIX 或 Redis；从已配置的 Remi 官方仓库下载对应 RPM，逐个 `rpm --checksig` 确认摘要与签名后，只解包到私有临时目录并通过独立 CLI 的 `PHP_INI_SCAN_DIR` 加载。未安装到常驻 PHP 配置，也未重启共享 PHP-FPM。
- 本次临时运行器目录为 `/tmp/sosecurity-sodium-runtime-akybbkwr`：7.2/7.4/8.2/8.4 使用 `phpNN-isolated`，7.3/8.0/8.3 使用 `phpNN-sodium`，8.1/8.5 使用系统原有命令。临时目录可能被清理；其他环境按自己受信任的包管理流程配置所需扩展。
- 最终完整日志：`/tmp/sosecurity-r2-php72-isolated-full.log`、`php73-sodium-full.log`、`php74-isolated-full.log`、`php80-sodium-full.log`、`php81-full.log`、`php82-isolated-final.log`、`php83-sodium-full.log`、`php84-isolated-final.log`、`php85-full.log`（后八个均带相同 `/tmp/sosecurity-r2-` 前缀）。
- 浏览器使用已有 Playwright：`SOSECURITY_PLAYWRIGHT_MODULE=/tmp/winstar-smtp-ui/node_modules/playwright python3 tests/mfa_browser.py <runtime>`，测试启动独立本地服务器与私有目录。

完整检查使用以下门禁（`<runtime>` 替换为已配置相应扩展的运行器）：

```sh
SOSECURITY_REQUIRE_CRYPTO=1 SOSECURITY_REQUIRE_REDIS=1 \
SOSECURITY_REQUIRE_MYSQL=1 SOSECURITY_REQUIRE_HTTP=1 \
SOSECURITY_REQUIRE_HTML=1 SOSECURITY_REQUIRE_UPLOAD=1 \
SOSECURITY_REQUIRE_RESET=1 SOSECURITY_REQUIRE_POSIX=1 \
bin/check.sh <runtime>
```

已执行但初次失败、修正后通过：

- 严格环境门禁发现部分运行时缺少 POSIX／Redis，补齐隔离扩展后重跑对应完整检查；保留门禁。
- 同一隔离后端被多个套件复用时，未来时间测试记录触发时钟倒退保护；增加归属明确的测试记录清理后，三驱动及九版本复测通过，产品时钟保护未放宽。

边界与未执行项：

- 已真实读取现有 Apache/PHP-FPM7.2 的 MFA 演示 JSON：HTTP200，`available=false`，明确报告 sodium 缺失。这里未完成启用后的常驻 Apache MFA 验收；不能以隔离浏览器结果代替。
- 宿主完整认证编排、账号／权限撤销传播、真实账号恢复／通知、WebAuthn／联合身份、生产、远端 CI、公开发行与独立安全审查均不能由本批结果推断完成，继续按跟踪表实施。

以[当前执行状态](execution-status.md)和各阶段新增证据为准；下面的早期记录保留当时的运行环境及未执行项，不代表现阶段仍缺少那些运行时。

## 0.1 基础候选验证记录

日期：2026-10-13。交付性质：**本地 0.1.0-dev 候选里程碑**，不是GitHub/Packagist正式发布，也不是独立安全审计。最初本地目录及公开GitHub仓库为空，本次没有覆盖宿主网站代码或连接生产数据。

## 已执行并通过

| PHP 运行时 | 功能/边界断言 | Session 集成 | 文件24进程并发 | Redis真实驱动及24进程并发 | 真实HTTP登录 |
| --- | --- | --- | --- | --- | --- |
| 7.2.34 | 13组，184断言 | 19断言 | 通过 | 14驱动断言+3并发断言 | 20断言 |
| 7.4.33 | 13组，184断言 | 19断言 | 通过 | 14驱动断言+3并发断言 | 20断言 |
| 8.1.34 | 13组，186断言 | 19断言 | 通过 | 14驱动断言+3并发断言 | 20断言 |
| 8.2.32 | 13组，186断言 | 19断言 | 通过 | **未执行：本机缺ext-redis** | 20断言 |
| 8.4.23 | 13组，186断言 | 19断言 | 通过 | **未执行：本机缺ext-redis** | 20断言 |
| 8.5.9 | 13组，186断言 | 19断言 | 通过 | 14驱动断言+3并发断言 | 20断言 |

每个可用运行时均检查38个PHP文件的语法。Argon2id是否可用影响功能断言数量；不可用时验证明确拒绝该配置，不降级。Redis实例只监听新建私有UNIX socket，TCP关闭，无生产实例连接。文件并发也使用新建0700临时目录。

并发情形每个启动24个独立PHP进程：5次额度只成功5次，单次CSRF只成功1次，验证码只成功1次。不是仅顺序循环模拟并发。

HTTP测试通过隔离PHP内置服务器与真实CookieJar执行：跨Session令牌拒绝、数组字段拒绝、多标签页、正确/错误密码、验证码重放拒绝、登录Session ID变化、请求预算429/Retry-After、非允许方法405、存储权限异常503。没有打开真实浏览器，也没有证明生产PHP-FPM/Nginx/代理的行为。

其他验证：

- PHP7.2及PHP8.5独立消费者通过Composer路径仓库真实安装、PSR-4自动加载和公开API调用。
- 核心composer.json与开发工具composer.json通过严格格式检查。核心没有第三方运行时依赖，依赖审计没有可扫描的运行时包；独立开发工具PHPStan 2.3.1的Composer漏洞公告检查未发现公告。
- PHPStan level5、目标PHP7.2，核心src无错误；无忽略基线。工具实际在PHP8.1运行。早期PHP8.5工具尝试加载Turbo因本机glibc太旧发出警告，随后采用PHP8.1运行并通过；这不是核心运行时问题。
- `composer archive`内容检查通过：排除vendor、tools、tests、CI、缓存、私有配置文件名及lock；保留Composer元数据、源码、许可证和使用文档。
- GitHub工作流YAML语法解析通过；Action使用检查时解析到的固定提交SHA。
- 内部审查检查原子生命周期、代理链、密码截断/降级、会话超时和故障策略；不是独立审计结论。

## 已执行但初次失败，现已修复并复测

- 老版phpredis无前缀时返回null，新版/配置可能返回空字符串；适配器明确接受两种无前缀返回，不接受实际前缀。
- 关闭Redis客户端不总能模拟服务故障，旧扩展会重连；测试改成隔离socket不可达并恢复，验证异常拒绝业务。
- Redis错误数据类型GET失败时不能当缺失记录；检查协议错误并抛StorageException，已有回归测试。
- 发布压缩包最初包含本地vendor；显式Composer/Git导出排除规则修复，压缩包内容检查已通过。

## 未执行与发布前验收

- PHP7.3、8.0、8.3本地没有运行时，**未执行**。完整7.2–8.5 GitHub CI已定义，**未在GitHub实际运行**；CI运行前不宣称完整版本矩阵验证通过。
- PHP8.2/8.4 Redis驱动本地未执行，CI要求扩展齐全且缺失则失败。
- 真实Cloudflare Turnstile网络/widget验证未执行；本次只验证适配器响应绑定和异常路径，不将模拟传输结果当成第三方服务验收。
- 真实浏览器、PHP-FPM/Apache/Nginx、HTTPS及可信代理链、旧站认证业务验收未执行。
- 独立安全审计、ASVS逐项验收、负载/持久性故障测试未执行。24进程正确性测试不替代生产容量评估。
- GitHub推送、标签、Packagist注册及正式Composer公开安装未执行。当前仅本地提交与路径仓库安装。
- Docker安装可见，但守护进程不可连接；本次使用现有原生CLI运行时，没有通过容器补齐缺失版本。

下一里程碑依照roadmap.md推进PDO MySQL存储、输入验证和上传能力；先补齐上述发布前验收，再将候选声明为稳定可公开发布版本。

## 复现

```sh
composer install
bin/check.sh php72
bin/check.sh php74
bin/check.sh php81
bin/check.sh php82
bin/check.sh php84
bin/check.sh php85
python3 tests/install.py php72 /path/to/composer
python3 tests/install.py php85 /path/to/composer
python3 tests/archive.py php72 /path/to/composer
php81 /path/to/composer install --working-dir=tools
php81 tools/vendor/bin/phpstan analyse -c phpstan.neon --no-progress
php81 /path/to/composer audit --working-dir=tools --locked
```

## 互动演示追加验收（2026-10-13）

基础里程碑后增加demo/public公开入口和源码目录保护。PHP7.2、PHP8.5隔离演示服务器的HTTP验收通过；最终演示测试84项断言，涵盖十类能力、JSON/表单、畸形操作字段、跨访客隔离、过期和重放。

实际 `http://72.rocky.wsl/SoSecurity/` 在Apache/PHP-FPM PHP7.2上HTTP验收通过。真实Chromium验证AJAX生成/正常验证/篡改拒绝、输入不执行脚本、移动宽度无页面横向溢出、无脚本异常；桌面和手机截图已检查。

`.git/HEAD`、composer.json、demo/app.php、src、tests、bin和tools等仓库路径拒绝HTTP访问；演示首页及静态资源正常。私有数据位于Web根之外；只有demo/public映射为大小写明确的入口。原有基础里程碑的“未执行浏览器/PHP-FPM”是此前状态，此次追加不代表真实旧站生产业务已验收。

演示Redis和Turnstile未配置，真实外部服务未执行；页面不宣称通过。上传、MySQL、SSRF等后续功能仍未实现。部署和复现见demo.md。

## 核心加固与配置候选追加验收（2026-10-13）

Policy/Change不可变、稳定异常reason、有界文件锁、分批清理、状态编码预算、Redis原子Lua CAS和网络等待预算已实现。工厂、只读诊断、Session原有Cookie策略保留和宿主重置版本比较已加入源码与演示。

- PHP7.2与PHP8.5功能回归通过；加固29项、配置/诊断33项、Session24项、宿主SQL重置16项；演示现为95项。
- Redis真实冲突、网络暂停、内存耗尽和诊断/配置变更测试已加入；保留原有24进程并发。Redis重启恢复边界尚待完成，不能据此宣称恢复后仍满足全部保护状态保证。
- 两个PHP版本在独立16KiB tmpfs上实际验证ENOSPC写入失败与原记录保留，各4项；测试结束卸载并移除临时挂载点，不填满共享磁盘。
- PHP8.5实际限制独立测试进程文件大小，验证OS部分写失败4项；PHP7.2缺POSIX扩展，此项未执行，不能当作通过。
- CLI只读诊断退出状态及无状态文件写入已验证；PHPStan level5/目标PHP7.2通过。
- 当前Web入口上的配置/诊断与故障页面HTTP测试通过，真实Chromium已验证工厂成功、配置拒绝、隔离锁超时、移动布局且无脚本异常。

完整目标仍进行中，逐项剩余工作见execution-status.md。

## MySQL、输入验证与Redis恢复追加验收（2026-10-13）

本段是上述历史里程碑之后的最新状态；已实现MySQL与输入验证，不能继续按旧段落的“尚未实现”解读。

已执行并通过：

- `bin/check.sh` 在PHP7.2.34、7.4.33、8.1.34、8.2.32、8.4.23、8.5.9上执行；13套基础测试分别184/186项，Session24、加固29、宿主SQLite重置16、HTTP20和隔离演示108。本阶段追加单项复测：配置/诊断39、输入验证52、MySQL41，六个运行时均通过相关已执行检查。
- 独立MySQL8.0.46无TCP实例：驱动契约、namespace隔离、TTL、损坏/超大载荷、索引/引擎、过期清理、真实默认1秒锁等待、PDO错误模式/会话锁等待恢复、宿主事务不提交/不回滚、真实断连接提交失败拒绝。每次只操作独立测试库。
- MySQL24进程分别竞争限流/CSRF/验证码，精确放行5/1/1；24进程使用4个重置令牌，业务账号密码版本只更新一次。竞争测试显式采用5秒锁等待，不代表默认1秒能承受相同磁盘吞吐。
- MySQL隔离生命周期脚本在PHP8.5实际完成创建/运行/停止/删除；现有网站MySQL未修改。PHP7.2兼容测试账号只在独立实例使用mysql_native_password。
- PHP7.2/7.4/8.1/8.5执行Redis30项驱动集成、24进程竞争和真实旧快照重启：seed1/consume1/reject6项，显式审核恢复后旧令牌仍拒绝。ready/run_id/epoch与Lua内复核已实现；没有宣称恢复所有计数或封禁。
- PHP8.1/8.5 OS部分写故障各4项通过；测试改为输出经管道的子进程，文件大小限制不再连带破坏调用者重定向日志。PHP8.1最初重定向测试失败已修复并复测。
- 实际Apache/PHP-FPM7.2入口演示110项通过，含真实私有MySQL计数/隔离。新增验证与存储页面Chromium手机宽度390px：AJAX正常/422/未知字段、中文错误定位、HTML测试字符串不执行、真实MySQL计数/namespace/陌生访客隔离、无脚本异常及无页面横向溢出。截图已检查。
- PHP7.2/8.5各67个PHP文件语法检查通过；PHPStan level5/目标70200通过；Composer validate严格模式通过。两个运行时新消费者安装和归档验证通过，SQL与验证类实际随包交付；69个包文件不含demo/bin/tests/tools/vendor/private配置。
- 开发工具锁定依赖的Composer审计通过，没有漏洞公告。核心没有第三方运行时包，Composer2.10.2直接audit空锁文件返回非零“No installed packages”，不计为审计通过；CI现显式区分空依赖不适用与存在依赖需审计，不能吞掉真实审计失败。
- 新的SQL资源和演示数据库脚本HTTP路径返回403，私有配置/数据在Web根之外；演示MySQL无TCP监听、应用仅演示表DML权限。

已执行但初次失败，现已修复并复测：MySQL初始1秒竞争等待超时（保留默认拒绝并明确竞争验收5秒）；独立实例初始化45秒超时（有界延长并减少测试实例内存/日志资源，完整生命周期后通过）；apache环境Python3.6不支持capture_output参数（演示管理脚本兼容改正）；配置可选数值null不能作为默认值，新增拒绝检查；上述日志大小限制问题。

未执行/不能宣称：PHP7.3/8.0/8.3实际运行；PHP8.2/8.4 Redis（本机缺扩展）；PHP7.2/7.4/8.2/8.4 POSIX部分写故障（本机缺扩展）；MySQL5.7/8.4/MariaDB/更多客户端；Windows；真实Turnstile、HTTPS部署、生产旧站、独立审计、GitHub CI运行及公开发布。新的CI定义仍不等于远端执行。

演示私有MySQL实例为可操作页面保留运行，管理/停止命令见demo.md；临时测试实例与它互不共享。完整计划仍在执行，上传、HTTP/API和发布验收继续按next-steps.md推进。

## 上传阶段追加验收（2026-10-13）

已执行并通过：

- 本机PHP7.2.34/7.4.33/8.1.34/8.2.32/8.4.23/8.5.9：上传83项检查，PHP7.2另有旧WebP无私有临时目录拒绝检查（84项）；实际原生multipart20项、隔离上传演示32项。配置/诊断39项仍通过。
- JPEG/PNG/WebP实际GD解码及重新编码，扩展/MIME匹配、恶意复合文件名、符号链接/流包装器、截断图片、巨大PNG头、源/编码大小与工作预算、扫描拒绝/故障、私有权限与factory/diagnose、可复用管理器调用。原始附加PHP测试片段不进入重编码结果；源在扫描阶段改变时保存仍使用已经验证的快照。
- PHP7.2 WebP最初有效样例解码失败，证实该版本字符串API缺此能力；专用私有临时快照路径修复并复测，不使用远程/数据URL，不重读原始源。PHP8.5首次测试的imagedestroy废弃警告已修复为仅销毁旧版资源。
- 24进程并发上传：24个独立随机文件，逐文件确认0600和PNG MIME，不覆盖源或其他文件。PHP7.2/8.5执行；同时保持文件/Redis/MySQL原有限流与单次令牌竞争。本阶段bin/check.sh两版本均执行通过，PHP7.2的最新WebP/拒绝分支另行单项复测通过。
- 独立16KiB tmpfs真实ENOSPC：PHP7.2/8.5各7项，含上传拒绝、不完整文件清理和旧文件hash保留。测试新增空专用目录/小文件系统护栏，拒绝指向普通磁盘。PHP8.5 POSIX部分写故障7项通过；PHP7.2缺POSIX，未执行该种部分写测试。
- PHP7.2/8.5 `-n`缺fileinfo时各1项依赖拒绝；仅加载fileinfo而缺GD时各2项，图片拒绝且显式txt可用。没有把跳过GD图片检查当成功。
- 实际Apache/FPM7.2入口：整体演示113项，上传专页31项（正常multipart/CSRF/访客/额度/故障28项加前置请求长度3项）。Chromium验证文件选择与AJAX真实保存、固定正常样例、伪装/扫描故障拒绝、390像素手机宽度和无脚本异常，截图已检查。
- Apache2.4.37/proxy_fcgi初次实测普通LimitRequestBody未按预期阻止大请求，已在演示.htaccess加入请求头阶段规则；只发送超过2MiB的Content-Length头、尚未发送body时收到413；chunked及无长度POST为411。正常FormData与表单继续通过，不修改其他网站配置。PHP内的事后大小检查不能冒充该前置控制。
- CLI清理实际执行，过期安全记录与payload分别有界清理；隔离演示通过修改自己的测试文件mtime验证保留到期后的删除，访客清理只作用于自身记录。未配置真实AV，扫描按钮清楚标记测试实现。
- PHP7.2/8.5语法检查78个文件、PHPStan level5/目标70200、Composer严格校验、两个运行时消费者安装和77文件归档检查通过；开发工具Composer审计没有漏洞公告。Source/Upload及demo/uploads.php HTTP路径403。

未执行：真实扫描服务及恶意样本独立验收、PDF内容重建、Windows ACL/网络文件系统、更多GD构建、缺失PHP7.3/8.0/8.3、生产宿主/HTTPS/独立审计。SDK没有宣称PDF语义解析或所有文件无恶意，不自动公开下载/内嵌执行，宿主仍负责授权/CSRF/请求与总容量预算/保留和安全下载。

完整目标仍进行中：下一阶段按next-steps.md推进安全跳转、CORS/Permissions-Policy、受限外部HTTP、API Key/HMAC/原子Nonce及受控演示。URL/IP验证格式和全版本/真实宿主/独立复核仍保留，不以阶段通过缩小完成标准。

## HTTP策略与受限请求追加验收（2026-10-13）

已执行并通过：

- 本机PHP7.2/7.4/8.1/8.2/8.4/8.5：HTTP策略66项（共享URI、数字IP/反斜杠/userinfo/头注入、固定Origin跳转、CORS预检/缓存Vary/凭据限制、Permissions-Policy、url/ip输入格式）；受限策略/适配80项（全部地址拒绝、逐跳DNS变更、peer、POST不重放、累计限额、factory/诊断、DoH解析、伪造计数不能掩盖过大头、调用示例）。
- 六个PHP版本各23项实际cURL/TLS/DoH测试：全新Linux网络命名空间内设置独立公开IPv4/IPv6地址字节、固定测试服务/每进程CA，验证Host/SNI/证书与实际连接pin、跨来源头清除、私有/变更DNS目标未连接、循环/POST拒绝、真正压缩后body/原始头超限、旧折行头拒绝、不自动携带服务Cookie、慢DNS及慢HTTP共用总预算、URI私有字面量不能借公开pin连接。无宿主路由或系统信任库修改；临时环境结束已回收。
- CORS实际HTTP12项在六个本地运行时执行；真实Chromium跨端口前端触发预检并读取固定JSON，另一来源/方法拒绝，credentials模式不被错误授予。静态端点没有Session Cookie或业务数据。
- 隔离网络演示20项在六个本地运行时执行；真实Apache/FPM7.2入口24项包括实际固定www.php.net/robots.txt请求（200/字节数/hash），初步CLI7.2/8.5公网请求也实际成功。Google JSON DoH端点bootstrap pin、TLS和查询返回已实际核对。
- 整体demo.py隔离114项；实际入口含私有MySQL116项。Chromium确认新增跳转/CORS/网络拒绝AJAX与移动宽度，无脚本异常；截图已检查。拒绝按钮使用固定适配器样例，不冒充公网或内网连接成功。
- PHP7.2/8.5缺cURL最小ini各3项，HTTP策略仍可用，默认外部请求明确DependencyException；原基础功能/Session/加固/配置/验证/上传/Redis/MySQL/并发/HTTP回归保持通过。bin/check.sh两版本已执行；最新HTTP策略小项追加复测单独通过。
- 两运行时100个PHP文件语法检查、PHPStan level5/目标70200、Composer严格校验、消费者安装及95文件归档通过；开发工具依赖审计没有漏洞公告。新demo/network.php及Http/Outbound源码HTTP路径返回403。

初次已执行但失败并修复：PHP7.2不提供新XFERINFO回调常量，改用兼容的PROGRESS回调并通过实际DNS/传输超时；NETRC禁用值按PHP绑定使用false（忽略），通过实际代理/凭据环境隔离测试；DNS数据类型及响应计数增加边界检查。未把最初失败或模拟对象当真实传输证据。

未执行/未完成：API Key/HMAC/Nonce与跨实现向量/并发重放仍待实现；缺失PHP7.3/8.0/8.3、更多cURL/CA/企业网络/Windows、生产宿主试点和独立复核；远端CI及公开发布。新增CI的命名空间步骤只是定义，未在GitHub运行。默认第三方DNS隐私和自定义适配硬预算/传输契约已在outbound.md说明；URL格式/公开地址字节不能保证真实基础设施路由或业务路径授权。

完整目标保持进行中，继续API与1.0逐项验收，不用阶段完成替代完整计划。

## API 凭据与签名追加验收（2026-10-13）

已执行并通过：

- PHP7.2/7.4/8.1/8.2/8.4/8.5：最新200项核心检查（Memory/File；Bearer只存摘要、范围/轮换/撤销/期限；RFC公布原语向量；方法/URI/查询/体/type篡改、结构/重复头/算法/tag/过期/时间偏差/重放；无效签名不碰故障存储；错误KeyProvider拒绝；存储等待/提交跨期限拒绝；工厂拒绝非共享包装，签名端无验证服务不误报故障）。
- 六个版本各4组独立Python/PHP双向向量，包含二进制/中文、查询顺序、IPv6、32/64/128字节测试密钥；完整头字节一致。RFC B.2.5另验证HMAC原语，明确不是完整sosecurity-v1配置档。
- 六个版本各28项真实本地HTTP检查：Python发送签名、原始请求体/查询/Content-Type、重放/范围/过期/未知密钥、超限413、存储/密钥服务503、Bearer撤销；测试服务仅绑定127.0.0.1，固定测试密钥，不进入公开演示或Composer包。
- 六个版本各24项隔离API演示检查；实际Apache/FPM PHP7.2入口同样通过24项，含访客归属与控制CSRF，固定内部签名不发外部业务请求。最新主演示为117项隔离、119项实际入口（配置MySQL）。实际Chromium通过凭据轮换撤销、签名篡改/正常/重放/过期/故障，以及原功能和390px手机宽度；源码demo/api.php及src/Api路径403。
- PHP7.2/8.5最小ini、无Session/GD/Redis/cURL等可选扩展时API核心检查通过；核心仍只要求JSON/hash。117个PHP文件语法检查、PHPStan level5/目标70200、Composer严格校验、两运行时新消费者安装及109文件归档通过，开发工具依赖审计无公告。

驱动完整回归/并发结果在下面追加；历史阶段的“API待实现”描述表示当时状态，以本节及execution-status.md为当前证据。

已执行但初次失败及处理：扩展Redis测试最初使用1970年附近的固定测试时钟，Redis服务器EXPIREAT立即删除；改为贴近当前Unix时间的受控测试预设，并保持逻辑时间边界测试。测试闭包遗漏时间变量捕获已修正。并行独立MySQL初始化各180秒超时，改为顺序执行并将测试重做日志容量从16MiB增至128MiB；未修改宿主或演示数据库。MySQL的24次并发管理轮换在慢盘触发已定义的1205锁等待拒绝；测试明确分别统计成功/拒绝，确认原token失效、后续轮换恢复、撤销不复活，不能把拒绝计作成功或承诺24次均成功。连续对实际入口执行两套大测试触发100次/分钟真实预算，等窗口恢复后单独API复测通过；没有削弱限额。

未执行/未完成：生产客户端/HTTPS代理/原始重复头交付/密钥服务与撤销传播/备份恢复；PHP7.3/8.0/8.3及Windows、其他驱动服务端版本、远端CI/公开包安装、真实旧站试点和独立复核；适当的无状态CSRF及成熟HTML清理接入范围仍待继续。完整目标保持进行中，不用本阶段替代1.0验收。

驱动回归最终已执行并通过：`bin/check.sh php72` 和 `bin/check.sh php85` 顺序完整运行。Memory/File/Redis/MySQL同一API契约组合分别361/362项；差异是随后补充的签名端诊断检查，最新两基础存储200项已在六个版本单独复测。File/Redis/MySQL分别以24进程竞争同一签名，精确放行一次；凭据轮换后原token不可认证，串行新凭据可认证，撤销后不可认证/轮换。MySQL管理轮换本次分别16成功+8锁等待拒绝（PHP7.2）、18成功+6拒绝（PHP8.5），不将拒绝算作成功；保持显式5秒并发测试预算与核心默认1秒拒绝。含三驱动/宿主密码版本/并发上传的组合83项，外层File/Redis组合70项。数据库和Redis临时实例已关闭回收，持久演示数据库仍保留。最新diagnostic追加的39项配置检查及200项最小ini API检查另行通过；不因小范围诊断变更重复无关大数据库验收。

## 无状态 CSRF 与路由策略追加验收（2026-10-13）

已执行并通过：

- 本机PHP7.2/7.4/8.1/8.2/8.4/8.5各118项：签名/站点/场景/每次登录绑定、Cookie双重提交及攻击者自有签名Cookie注入拒绝；重复验证明确允许；期限/未来/提交后时钟边界、保留/移除旧钥、不可变引用与秘密遮蔽/序列化拒绝、配置工厂/诊断、精确方法/路径及编码/子路径不能误获豁免、豁免配置深层引用不能修改。
- 六版本各3个独立Python/PHP向量：Unicode站点/场景和二进制绑定字节长度；Python令牌在PHP验证，PHP新发随机令牌在Python重算MAC。此为本库格式，不宣称通用CSRF协议。
- 六版本各24项真实HTTP：固定私有测试登录上下文、表单/请求头、两种来源冲突拒绝、多个标签页Cookie稳定、缺失/篡改/跨身份/攻击者Cookie双重匹配但身份不符拒绝、PHP Session未启动且没有令牌状态文件；实际使用examples/signed-form.php。
- 六版本各14项实际HTTPS/终止代理：每次测试临时证书，urllib核实该证书及hostname，__Host-/Secure/HttpOnly/Path=/无Domain Cookie，合法/伪造请求，仍无PHP Session。PHP7.2/8.5的Chromium另验收浏览器Cookie实际属性、同源AJAX及同站不同Origin的伪造表单403、跨来源脚本无法读取Token。浏览器只为临时自签证书启用ignoreHTTPSErrors；未安装系统CA、改现有代理或服务证书，生产TLS信任不是此验收结论。
- 六版本各30项隔离演示；实际Apache/FPM PHP7.2入口30项通过，真实演示Cookie/登录绑定/期限/密钥轮换/精确豁免预览；演示控制仍有原有状态CSRF。最新主演示120项隔离、122项实际入口（含MySQL）。实际Chromium新增signed页，正常双重提交/篡改/跨登录/重用/轮换/错误密钥/路由策略和390px手机宽度通过；源码及demo/stateless.php路径403。
- PHP7.2/8.5最小ini各118项通过，无Session/GD/Redis/cURL等可选扩展；125个PHP文件语法、PHPStan level5/目标70200、Composer严格校验、两运行时消费者安装以及114文件归档通过；开发工具依赖审计无公告。
- PHP7.2/8.5原基础13组184/186项、Session24项、配置39项、API200项、真实旧登录HTTP20项及主演示120项通过。存储实现未更改，未为此纯Crypto/路由变更重复MySQL/Redis完整服务端验收；上一节相应驱动证据保持原有范围，不能扩充成生产认证或新环境证明。

已执行但初次失败，已修复并复测：新源码早期字符串拼接语法错误被PHP7.2检查发现，修正后上述语法/功能/静态检查通过；首次可选浏览器启动没有指定已安装Playwright的模块路径，补齐SOSECURITY_PLAYWRIGHT_MODULE后PHP7.2/8.5 HTTPS浏览器通过。没有把未启动的浏览器当作验收。

未执行/未完成：真实生产身份/每次登录新绑定、真实密钥管理与全节点撤销传播、生产HTTPS/代理与备份恢复；缺失PHP7.3/8.0/8.3及Windows，真实旧站业务试点及独立复核，远端CI/公开发布。成熟HTML清理接入及1.0验收继续推进；完整目标仍进行中。

## 可选基础富文本清理追加验收（2026-10-13）

已执行并通过：

- HTML Purifier 4.19.1独立验证清单及锁定安装，Composer严格校验与锁定审计无公告；核心require未增加第三方包，DOM/ctype与清理包仅为此功能的显式可选依赖。
- 本机PHP7.2/7.4/8.1/8.2/8.4/8.5各58项：中文/基础标签/结构修复、安全协议与相对链接、脚本/事件/CSS/资源/SVG/MathML/表单/身份属性移除，输出幂等、UTF-8/控制字节/输入/输出/树/深度/属性预算，故障服务拒绝/未调用超限输入、配置/版本限制/引用不可变及只读诊断。预检DOM只限资源，上游返回清理结果。
- 六版本各19项隔离演示；实际Apache/FPM PHP7.2入口19项通过，控制CSRF/数组/超限422/服务503及错误详情遮蔽。PHP7.2/8.5隔离Chromium及实际PHP7.2入口使用6组结构变异攻击输入，清理结果重新插入实际HTML DOM后无危险节点、脚本执行或外部请求；无脚本sandbox基础预览/390px手机宽度通过。
- 没装清理包、已加载4.19.0假测试类时各2项明确依赖拒绝；PHP7.2/8.5最小ini以及仅补ctype的配置各4项，DOM/ctype缺失时拒绝且普通输出编码仍可用。没有strip_tags/正则或返回原文降级。
- 两运行时新消费者只安装核心时全部既有API成功、调用未安装清理库明确DependencyException；另外显式安装核心+可选包的新消费者实际通过rich-text.php与清理结果/审计，不复用开发工具或演示autoloader。两版本120文件归档排除integrations/vendor/lock/测试/演示/私有配置，保留适配源码/示例/指南。
- 133个PHP文件语法、PHPStan level5/目标70200、核心/集成Composer严格校验、开发工具锁定审计通过。PHP7.2/8.5旧基础13组184/186、Session24、配置39、签名CSRF118、API200与主演示123项通过；实际主演示含MySQL125项。存储实现未改，未重复无关数据库完整并发；上阶段驱动证据不扩充为新环境验收。
- demo/html.php、清理源码和integrations清单HTTP访问403；核心压缩包不带第三方代码。新的全PHP CI清理/集成审计要求已定义，尚未在GitHub运行。

已执行但初次失败，现已修正并复测：旧PHP的DOM文本/文档类型节点childNodes为空导致遍历警告，改为hasChildNodes后遍历；精确版本require导致Composer strict警告，改为^4.19.1并保持lock实际4.19.1；PHPStan在已安装固定版本下把版本门禁判为常量条件，版本范围判断抽成构造/诊断共享的运行时函数并测试旧/预发行/错误版本，不忽略错误或删门禁。初次临时命令引号语法错误后改用独立PHP输入复查libxml行为：模式保留、已有错误不清空，但DOM/上游可追加诊断，该兼容边界已明确写入指南。

未执行/未完成：PHP7.3/8.0/8.3、Windows及更多libxml/上游版本、完整HTML5/复杂编辑器/图片/CSS策略、实际生产渲染与大内容迁移、独立复核及远端CI/公开发布。基础清理不代替业务授权/CSRF/请求预算/渲染上下文审查。1.0全版本/旧站试点/独立复核仍需继续，完整目标保持进行中。

## 1.0 九版本矩阵与宿主组件追加验收（2026-10-13）

已执行并通过：

| CLI版本 | 完整bin/check.sh（必需项不跳过） | 新Composer核心/可选HTML消费者、压缩包 | MySQL并发轮换成功/显式锁等待拒绝 |
| --- | --- | --- | --- |
| 7.2.34 | 通过，临时POSIX ini | 通过 | 17/7 |
| 7.3.33 | 通过 | 通过 | 19/5 |
| 7.4.33 | 通过，临时POSIX ini | 通过 | 24/0 |
| 8.0.30 | 通过 | 通过 | 17/7 |
| 8.1.34 | 通过 | 通过 | 24/0 |
| 8.2.32 | 通过，临时POSIX/Redis ini | 通过 | 15/9 |
| 8.3.35 | 通过 | 通过 | 20/4 |
| 8.4.23 | 通过，临时POSIX/Redis ini | 通过 | 22/2 |
| 8.5.9 | 通过 | 通过 | 24/0 |

矩阵分别顺序运行新三版本和原六版本，各自使用一次新建无TCP私有MySQL。设置REQUIRE_REDIS/MYSQL/HTTP/HTML/POSIX/RESET/UPLOAD=1；各版本30项Redis、重启恢复1+1+6、41项MySQL、24项Session、7项实际部分写故障、39配置、52严格验证、66 HTTP策略、80外部请求策略/适配、118签名CSRF、58HTML与两组依赖拒绝、83上传、16重置宿主SQL版本比较均通过。API早期Memory/File/MySQL281项，加入真实Redis后四驱动362项；24进程组合83项包括三驱动精确一次Nonce消费/轮换/撤销、限流、CSRF、验证码、宿主密码版本比较和私有上传。每驱动File/Redis24次管理轮换均成功；MySQL成功/拒绝如上，拒绝不是成功，但原凭据仍失效、串行后续凭据可用、撤销不能复活。

每版本独立Python API4组/签名CSRF3组、签名CSRF HTTP24项/临时TLS14项/演示30项、HTML演示19项、API HTTP28项/演示24项、网络演示20项/CORS12项、上传演示32项/实际multipart20项、旧原生登录HTTP20项、主演示123项通过。主演示该数字是隔离环境，不等同于实际Apache演示数据库125项或生产验收。

新增7.3/8.0/8.3并行CLI及测试扩展未安装FPM；原7.2/8.5二进制哈希验证相同，演示入口仍PHP7.2.34且HTTP200。原7.2/7.4/8.2/8.4缺扩展使用签名/摘要验证通过的Remi RPM解包到临时目录并通过PHP_INI_SCAN_DIR只为测试命令和子进程加载；没有安装到其系统扩展目录、修改其FPM配置或更新原CLI。PHP8.2/8.4测试Redis6.3.0；原CLI直接执行仍没有Redis。新版本模块不改变核心依赖JSON/hash及可选模块边界，PHP8.0/8.3原生Argon2不可用场景按实际能力拒绝，不当作算法验证通过。

新增三版本各23项实际命名空间cURL/TLS/DoH/IPv4/IPv6/重定向/预算通过，补齐先前六版本相同测试的目标版本范围；各7项独立小型tmpfs ENOSPC通过。没有改宿主路由/CA或填满共享磁盘。九版本新消费者安装及HTML可选依赖审计通过；压缩包排除resources/api及所有integrations测试项目。新增公开API候选包含78类/接口的签名/默认值/继承/本库接口/公开常量及属性默认值，九版本检查通过；PHP8引擎自动Stringable及8.5反射self差异经规范化，不掩盖本库真实接口变化。候选清单仍未经独立复核和正式冻结。

CoreRepo已提交基线24a64019的独立工作区，PHP7.2/7.4各33项实际HTTP组件检查通过；真实Session/SessionManager/Symfony CSRF/Twig与独立Composer SoSecurity共同运行，验证码/共享失败预算/Session更新/宿主数据保留/存储故障503。此为已撤回的历史实验，不属于本次交付验收。原CoreRepo工作区有未提交改动，试点没有修改它；现有第三方vendor只读用于该集成，未证明其全部依赖安全，也没有接入真实旧站数据库/管理员/SSO/路由。

初次已执行但失败及修复：API候选比较遇到不同PHP反射self/Stringable差异，按声明类与引擎内置接口规范化后九版本通过；临时Redis模块缺少其构建依赖igbinary/msgpack，补齐同版本测试模块并验证子进程继承ini后完整套件无跳过通过；试点自动加载优先级最初触发宿主类来源503拒绝，修复注册顺序后两版本通过。

最终135个PHP文件语法检查、PHPStan level5/目标70200、Composer严格校验和开发工具/可选HTML依赖审计通过；文档追加后PHP7.2/8.5压缩包为123文件，仍无vendor/测试/演示/私有配置。

未执行/未完成：原后台完整业务及SSO/真实第三方服务、Windows原生PHP/ACL/驱动（WSL互操作和Windows PATH查询不是PHP运行证据）、更多数据库/Redis/GD/cURL构建、生产密钥/代理/恢复链路、独立代码复核/专业审计、远端CI、GitHub/Packagist发布及公开包安装。完整1.0目标保持进行中；专业审计与独立代码复核分别记录。

## Windows原生平台追加验收（2026-10-13）

已执行并通过：专用Windows临时目录中的官方NTS x64 php.exe实际报告WINNT/PHP7.2.34与8.5.11，均由PowerShell运行tests/windows-check.ps1成功退出。每版本472项断言：6项私有文件系统拒绝、48项测试MemoryStore上的验证码/有状态CSRF/限流/密码/API Bearer轮换撤销/HMAC篡改与Nonce重放/代理/转义/审计脱敏流程、118签名CSRF、52严格验证、66 HTTP策略、80外部请求策略及模拟适配、24实际原生Session、58 HTML Purifier、2+2缺失/旧HTML依赖拒绝及16真实内存SQLite重置版本比较。MemoryStore仅用于测试，不支持跨请求共享状态声明；Windows实际外部网络不在80项模拟传输中。78类/接口API候选检查使用同一Linux签名清单，通过。

两版本还在新的WindowsComposer消费者实际安装核心包，本地路径仓库关闭Packagist，无第三方强制依赖；消费者自己的autoload完成签名双重提交与跨登录拒绝验证。可选HTML测试使用已锁定4.19.1；测试代码及依赖树复制到临时Windows目录，未更改宿主工作区、PATH/注册表/系统CA、主机路由或网站PHP/FPM。下载来自PHP官方Windows站，实际TLS下载；本次计算的下载SHA256用于记录，不将自计算值称为第三方签名：7.2.zip为3c673eab656e26fd6bc3ad27fe71169ad888b04e21d63d3c6b3151d5ed216563，8.5.zip为0ea96e0d2b9b737a6036f05cf4e95c49313faa6d0f27bd97edb2742503f0c043。版本来源及复现说明见platforms.md。

文件存储、上传保存和Validator私有临时目录在Windows模式0777时明确拒绝，并确认未留下状态文件。当前这些私有文件后端不支持原生Windows，不提供0700检查绕过；这属于已验证的限制，不是成功保存。Windows共享驱动仍须独立验收，不能把MemoryStore替代生产驱动。Linux九版本新增48项portable-core.php及规范化后的API检查通过，原完整驱动矩阵保持上一节范围。

初次已执行但失败及修复：API开发检查按POSIX分隔符判断源文件，Windows忽略公开方法导致签名比较失败；仅规范化路径后两平台复用同一基线通过，不修改候选清单。PowerShell5.1向php -r传递嵌套引号产生解析错误；改为直接运行PHP测试文件后脚本通过。新组件组合测试最初误传Bearer文本给仅用于受信任管理的rotate(id)/revoke(id)，以及错误预期存储错误代码；按照已有公开合同修正测试后通过，未改变SDK契约。

新增windows-components CI定义只运行明确范围的组件套件，远端未执行。未执行：Windows其他PHP版本/IIS/Apache/FastCGI、浏览器/GD上传、实际Redis/MySQL共享驱动及并发、NTFS/网络盘私有保存适配、实际外部网络/cURL/TLS/代理；真实旧站后台/SSO、独立复核及公开发布继续待验收。本节不将Windows局部组件结果扩展为Linux完整矩阵或所有平台能力相同。

Windows阶段最终137个PHP文件语法、PHPStan level5/目标70200、Composer严格校验、CI YAML结构解析及PHP7.2/8.5各124文件发行包检查通过。九版本48项平台组件检查和API签名检查通过；临时WindowsPHP/消费者/源码目录及下载归档已回收，演示入口仍HTTP200，原PHP7.2/8.5哈希相同。

## 范围纠正（2026-10-13）

用户明确未要求接入CoreRepo。先前由开发代理自行选取的CoreRepo专用试点超出了已确认的项目范围，现已删除其测试入口/运行脚本/专用文档，并移除代理创建的干净独立工作区。原CoreRepo工作区Git状态移除前后完全相同，未修改其业务、数据库或SSO。保留此前测试记录作为历史，不将其计为当前交付或发布前置条件。本次范围为SoSecurity本身、独立迁移示例和72.rocky.wsl/SoSecurity演示；其他项目接入必须由用户明确指定。

## 按最终规划对话重整项目（2026-10-13）

范围：以用户重新提供的最终共识整理SoSecurity本身、独立示例、文档、测试和指定演示。不接系统Fail2ban、不重复创建AutoBan、不接入其他项目、不再操作Windows。移除Windows自动CI任务，保留目标PHP九版本Linux矩阵与已有历史证据。

已执行并通过：

- 七种配置预设在现有PHP7.2/7.3/7.4/8.0/8.1/8.2/8.3/8.4/8.5各46项工作流检查：不污染宿主变量/启动Session/发头；文件登录额度与隔离/解除；仅签名端不要求共享状态；缺少验证端/私钥服务拒绝；可信签名双重提交及跨登录拒绝；可选HTML工厂保持懒加载；连接仅为宿主注入引用。
- PHP7.2/8.5公开API78类/接口签名未变化；138个PHP文件语法及PHPStan level5/目标70200通过。核心默认策略/接口/存储协议没有修改，未重复无关的完整数据库/并发矩阵；已有九版本矩阵维持此前范围。
- PHP7.2隔离主演示123项HTTP检查通过；实际Apache入口HTTP200且总览采用最终项目定位。实际Chromium首页检查17个模块卡片、390px手机宽度无溢出/无页面错误，截图已检查；只验证本次改动的总览，不扩大为新的全模块浏览器验收。
- PHP7.2/8.5独立Composer消费者安装通过，并从安装包读取配置预设构造工厂；两版本发行包各127文件，包含文档导航/功能矩阵/完整需求与配置示例，排除开发/测试/演示/私有配置。133个现有相对Markdown文件/目录链接存在；CI YAML解析与九版本矩阵检查通过；Composer严格校验及开发工具/可选HTML锁定依赖审计通过。
- 只读检查远端Git未返回分支/标签，Packagist包元数据HTTP404。尚未执行推送、标签或公开发布，本地路径安装不当作公开包安装。

初次已执行但失败及修复：归档检查发现虽然移除了Composer配置中的requirements排除，Git export-ignore仍遗漏该文档，导致发行包内README/导航所链接的需求不存在；同步Git属性后两版本归档检查通过。另经源码检查将配置预设局部变量移入闭包，增加并通过宿主同名变量保留检查，避免require配置文件污染调用方作用域；此项是作者检查修正，不是已观察到的测试失败。

未执行：新的远端CI、公开包安装与发布、独立安全审计、真实第三方验证码/扫描/泄露检查服务及具体宿主生产接入。既有项目接入和额外平台不是本轮完成前置条件，不以这些未授权事项扩大计划。当前实施顺序统一为roadmap.md和next-steps.md，当前能力/状态统一为features.md和execution-status.md。

## 扩展验证码：2026-10-13

- 已执行并通过：本轮完整PHP7.2–8.5九版本 `bin/check.sh` 回归矩阵，包含真实隔离Redis/MySQL驱动、全部模块/HTTP用例及新增验证码测试。File/Redis/MySQL上每类24个进程同时提交滑块/点选正确答案，均恰好一次成功。7.2/7.4的posix与8.2/8.4的redis扩展继续使用进程限定的临时测试包装器，不修改系统/FPM配置。GitHub远端CI未运行。

- 已执行并通过：PHP7.2.34、7.3.33、7.4.33、8.0.30、8.1.34、8.2.32、8.3.35、8.4.23、8.5.9的 `tests/captcha.php`（私有Memory/File/Session状态、五种文字运算、数字/字母及图片算术、滑块/点选、绑定/过期/失败预算/刷新/容量/一次消费/损坏状态/存储故障；随机运算分支使断言数略有变化）。字母答案校验使用测试代码访问私有存储后在有限字母空间内查找，生产API和演示不提供答案接口。
- 已执行并通过：九版本提供器契约各85条断言，覆盖sitekey载荷、hostname/action、v3评分类型/范围/阈值、畸形JSON/非布尔success、超限输入/响应和异常拒绝；响应为注入的模拟对象，不属于外部服务验收。
- 已执行并通过：九版本原生cURL固定端点HTTPS，每版本36条断言，7.2/8.5额外各一次总超时拒绝。使用独立网络/挂载命名空间、只在该命名空间绑定的hosts、进程测试CA和本地TLS服务器；不修改宿主hosts或系统信任。错误证书、环境代理诱导、重定向、HTTP错误、畸形/超限正文与超限头均不能放行。
- 已执行并通过：hCaptcha官方公开测试密钥经真实官方HTTPS端点验证，公开测试令牌通过、FAKE-TOKEN拒绝；测试密钥没有配置到演示站，也没有生产反机器人能力。
- 已执行并通过：PHP7.2/8.5的无GD依赖拒绝及仍可用的文字算术各6条断言；首个PHP7.2 `-n` 尝试同时禁用了必需JSON扩展而失败，显式加载JSON后复测通过，没有安装新运行时或修改FPM环境。
- 已执行并通过：扩展HTTP演示96条断言，生成/错误/预算耗尽/刷新与未配置提供器503；实际72.rocky.wsl/SoSecurity入口也执行并通过。
- 已执行并通过：实际Chromium在390px宽度通过公开题图像素求解滑块与点选，服务端首次接受、重放拒绝；键盘/重复点选/重新选择、AJAX切换和传统表单正常，截图已人工检查，未出现脚本错误或横向溢出。该自动求解也说明本地形式不能宣称可靠阻止自动化。
- 已执行并通过：配置后的第三方UI接线测试，明确使用模拟SDK/拦截POST响应；检查hCaptcha `recaptchacompat=off`、v2/v3 SDK隔离、AJAX后重置、v3固定action/即时令牌及传统表单。没有将这些结果当成真实第三方widget业务验收。
- 已执行并通过：PHPStan level5/PHP70200目标、147个PHP文件语法、80类API签名、Composer严格格式；新建Composer消费者PHP7.2/8.5真实安装并调用新增本地/提供器API与独立类型选择示例；133文件发行归档含新增运行时代码/指南/示例，排除测试、demo和私有配置。

未执行：真实业务密钥下Turnstile/hCaptcha/reCAPTCHA全部widget/令牌流程、真实业务风险评分阈值调优、GitHub远端CI及公开发布、生产负载和独立安全审计。演示第三方默认未配置并拒绝，不偷偷切换其他服务放行。

## R2.7维护检查点候选的九版SQLite终态（2026-10-17）

`/tmp/sosecurity-change-maintenance-x9k839rv/maintenance-validation/report.json` 的82组命令与270次语法检查均退出0；37个源码／测试／DDL文件哈希保持且与当前内容相同。八版每版1071项，当前无Intl的PHP7.4为1067项；各版本新增维护95项，12类／PDO示例静态分析通过。两版另各12项验证等长单条正文篡改，根元数据和长度不变时仍拒绝注册／地址维护与轮换，并保留原正文；独立探针日志位于 `/tmp/sosecurity-maintenance-body-6qj7b_10/`。

旧35文件核心的MySQL矩阵与新37文件维护矩阵仍分别运行；不能把SQLite终态外推MySQL。MySQL真实并发测试已另起无TCP实例，与两个矩阵的库分离；源码仍未合入SDK，完整R2.7保持未完成。

## R2.7邮箱与加密通知基础纳入工作树（2026-10-17）

`/tmp/sosecurity-account-foundation-integration-bv1znjiv/acceptance.json` 选取79组已通过命令：九版基础各140项（无Intl的PHP7.4为136）、九版170类API、九版可移植核心、45次新增文件语法、四类静态与Shell检查，两版独立Composer消费者／332文件发行包，以及无sodium的PHP7.2非加密77项。初次五项API反射在8MiB限制下内存不足，日志和首轮报告保留；仅这五项改为32MiB复验，全部通过，没有改代码或产品限额。基础功能仍在8MiB进程执行。

208个当前src类中新增四类，与维护候选对应文件逐字节一致；原166类公开成员签名保持，新公开候选170类。合并清单覆盖233个代码／门禁／测试／SQL资源文件，均与当前哈希相同，原208文件共享依赖保持，未干扰正在执行的隔离矩阵。新增测试无临时目录自动加载或绝对测试路径依赖，已纳入常规SQLite门禁。消费者实际调用规范化、通知加密／解密、移除旧键后的轮换及错误上下文拒绝。

本阶段不包含账号事务状态机、恢复流程、SDK工厂、HTTP／浏览器、SMTP或整库完整门禁；无sodium结果不能算作加密通过。未提交、推送、发布或操作生产。

## R2.7 MySQL完成／取消竞争与锁顺序（2026-10-17）

四轮MySQL旧维护源码竞争未完整通过，均保留于 `/tmp/sosecurity-change-mysql-race-5jt8suoo/`：首轮提交未知、次轮账号变化后的授权拒绝、后两轮完成／取消的死锁拒绝。第四轮记录实际驱动40001／1213，服务器日志确认宿主账号与私有账本根的反向锁顺序；测试诊断读取MySQL不存在的 `@@SESSION.in_transaction` 未取得状态，因此该轮仍明确失败，不能当作已确认回滚断言通过。

新锁顺序候选另起 `/tmp/sosecurity-change-lock-order-iyyetiph/`，不改动旧37文件矩阵。真实PDO查询次序探针在旧源码按预期失败，新源码PHP7.2通过12项；新九版SQLite关联及新独立MySQL竞争仍在执行，不计通过。提交结果未知与未提交拒绝分别记录，竞争最终状态／唯一变更／版本／通知／一次性授权不退款断言保持；新修复矩阵不接受任何死锁错误作为成功或普通拒绝。

## R2.7锁顺序候选MySQL并发终态与SDK接入（2026-10-17）

`/tmp/sosecurity-change-lock-mysql-race-6owmqw04/acceptance.json` 确认两版各九场景、共336并发进程及4次SIGKILL全部通过，39文件清单相同且保持，208共享依赖保持；启用全部死锁输出的服务器日志无死锁记录，独立实例已停止清理。两个提交后未知结果独立记录；第一轮未识别实际凭据变化后的 `operation.authentication` 而失败，依据Grants当前身份检查路径修正预期后通过，不放宽SQL错误或最终状态／唯一性／通知／授权不退款断言。

同字节的12个账号源文件现已接入SDK工作树，公开候选177类；新增DDL、宿主示例及可移植测试／并发运行框架。来源与根目录组合报告位于 `/tmp/sosecurity-account-core-integration-fpzor5o0/`，九版SQLite／两版无TCP MySQL及真实SDK并发正在执行，不提前计通过，也不替代完整R2.7／整库门禁。

## R2.7注册申请提交前预算修复与重新组合（2026-10-17）

实际反例：预算100060到期，回调把时钟推进至100061，旧 `Registration.request()` 仍提交账号1／通知1。修复后同一探针以 `account.budget` 拒绝，账号0／通知0；提交前调用最终预算并复核回调后的账号。仓库新增 `tests/account-request-budget.php` 44项，PHP7.2 SQLite及既有注册199项通过；覆盖请求尾部／提交回调／最终预算中的到期、拒绝、故障、账号变化，以及SQL回滚不退款外部扣减。请求预算回调新增最终阶段要求，无公开签名、状态格式或DDL变化。

当时根目录三组验证因上述已确认缺陷主动中止；中断记录与262文件前快照位于 `/tmp/sosecurity-account-core-integration-fpzor5o0/`，未计为通过，私有实例已清理。新九版SQLite110组及语法／静态、两版私有MySQL和当前预算版本SQLite并发分别在运行；不能用旧通过记录替代。测试MySQL缺少自建实例配置时会在连接／建表前拒绝，未降级为SQLite。

预算修复后两版新消费者／两版发行包四组通过，`budget-consumers.json` 与248文件哈希保持。实际安装流程包含注册所有者设密和重放拒绝、真实密码／重新认证／一次性授权的完整双地址核心、保留密码／角色／MFA、版本推进及旧会话拒绝、最终七条通知意图；发行包346文件。此处是直接核心接口和合成身份的本地验证，不是HTTP／浏览器／SMTP或正式预算适配验收。

另核验独立历史终态：旧核心九版MySQL63组各810项、35文件保持；锁顺序候选九版SQLite91组及270次语法全部通过，八版各1083项、当前无Intl的PHP7.4为1079项，37文件保持。旧维护MySQL矩阵继续；这些快照都早于本节预算修复。

### 当前SDK预算版本的SQLite终态

`sqlite-budget/report.json` 的110组命令和252次语法检查均退出0：八版各1127项、当前无Intl的PHP7.4为1123项，包含44项注册提交预算；九版177类公开API、12个账号源文件／PDO示例静态及Shell检查通过。267文件清单保持并与当前内容相同，原170类全部公开成员签名保持；新12类中11类与锁顺序候选相同，Registration另有本节已复现的最终预算修复，原208共享依赖保持。

当前根目录两版SQLite真实并发也已终态，`races-budget-sqlite.json` 及对应两份report确认共336个并发工作进程／4次SIGKILL通过，源码哈希保持且当前一致。它使用仓库自动加载、可移植工作进程和同一套FileStore会话／授权／预算，不借用临时候选报告。两版MySQL组合（含同一并发框架）仍在运行，未提前计通过。


## 2026-10-18 TOTP 配置对象导出防护接入

当前 SDK 复现 `Enrollment` 的 `var_export()` 包含完整配置 URI；修复用静态闭包保存状态并拒绝反序列化，显式 URI／标识／到期读取及真实 TOTP 绑定确认保持。可移植新增检查 `tests/mfa-enrollment-export.php` 已接入 `bin/check.sh`，安装消费者也检查自动导出不含 URI 和种子。

已执行并通过：PHP7.2—8.5 九版各 12 项新增检查、既有 MFA、191 类 API 和语法共 36 组；定向 PHPStan、PHP7.2／8.5 全新 Composer 消费者及 363 文件归档。全部原公开成员保持，仅追加 `Enrollment::__wakeup`；相关源码／测试快照在检查和消费者／归档后保持。证据为 `/tmp/sosecurity-enrollment-integration-u2z4m740/acceptance.json`、最终 `report-final.json`、`source-final.json` 及对应日志。常规入口将新增加密检查放在 sodium 条件内，Shell 语法通过；额外执行无 sodium 的 PHP7.2 既有 MFA 75 项通过，明确未执行加密生命周期。初次 API 比较脚本把空列表当作映射而退出，运行时矩阵尚未执行；修正运行框架后取得上述终态，不将初次执行计为通过。未执行完整 SDK 门禁、原生 HTTP／浏览器或生产验证。

因子目录仍在 `/tmp/sosecurity-factor-recovery-dpebpdlt/` 隔离：`directory-matrix/report.json` 确认 108 组通过且快照保持；`mysql-directory.log` 两版 PHP 下 FileStore 和独立 MySqlStore 各 68 项通过。它验证显式目录初始化／首次接入、真实密码／TOTP／会话、缺失状态不降级、越权与回调修改回滚、旧 PDO 事务和代际／有界读取。未实现审批后的原子因子替换，不作为完整 R2.7 通过证据。


## 2026-10-18 受管理因子强审批替换候选终态

当前 SDK 保持 230 个源码类、191 个公开候选；本节是未接入的隔离候选验证，不将其作为完整 R2.7 已交付。实现与接入缺口见[因子替换设计](account-factor-recovery-design.md)。

最终 `/tmp/sosecurity-factor-switch-final-vgzd23uw/acceptance.json` 确认 226 组检查通过：九版 189 组（每版含 431 项断言与 10 次语法）、两版私有 MySQL 在 FileStore／独立 MySqlStore 下 36 组（每版合计 428 项），以及候选源码／PDO 示例静态检查。252 个相关文件在 MySQL 完成后仍与运行前 SHA256 一致，进程已终止，临时 MySQL 经运行框架关闭清理；当前根目录 191 类 API 另行检查通过。

验证包含真实密码、TOTP、会话登记和旧挑战、一次性恢复码、独立操作员及参数绑定一次性操作授权。新槽位证明不切换身份，强审批成功后在同一 PDO 内推进凭据版本、切换签名指针、消费流程和写入安全通知意图；原密码、地址及其版本、角色保持。错误用途／目标、审批拒绝／撤销、通知写入失败、同版本密码修改、最后一次回调撤销新因子或越过绝对期限均拒绝／回滚；SQL 外已消费的证明／审批不退款。SQL 保存失败后的新时间步证明不重新导出恢复码。实际 COMMIT 后注入确认失败报告完成结果未知，重试不重复切换或新增通知。

初版 `/tmp/sosecurity-factor-switch-5xu3nxj3/` 的九版 153 组、追加九版操作员组合及两版 MySQL 各 330 项通过后，新增 `late-identity-before.log` 反例确认最后一次读取回调的同版本密码修改会先提交。修正版本 `/tmp/sosecurity-factor-switch-fixed-act70nt6/` 九版 171 组及两版 MySQL 各 396 项通过后，又由 `commit-unknown-before.log` 确认实际 COMMIT 的确认异常被错误分类为通用清理失败。两份反例及旧源码保留，最终源版本重新执行全部上述组合，不以旧通过结果替代。初始测试的错误列名、认证失败状态名称及回调异常类型预期已经更正，没有将这些运行框架错误计作 SDK 发现。

只使用本地临时 SQLite、FileStore、独立无 TCP MySQL 和合成操作员；通知仅验证同事务 Outbox 意图。没有正式邮件、原生 HTTP／CSRF／缓存／浏览器、完整 SDK 门禁或生产结论。取消／孤立槽位清理、真实并发／进程终止、独立恢复及代际运维、新账号迁移、正式工厂／API／消费者接入仍待完成；完整 R1—R6 保持进行中。


## 2026-10-18 因子取消／代际清理及真实 MySQL 死锁修正

候选 `/tmp/sosecurity-factor-cleanup-7ry13843/` 将恢复流程格式推进为 2，外部创建前预留新代际并保留旧槽位信息，新增创建空槽位、按准确代际删除、取消及单流程定向清理。取消先封锁 SQL 流程并写入通知意图，不修改账号或当前因子；已消费流程只清理旧槽位，已取消流程只清理新槽位。其他已启用／待确认代际及当前指针目标均保留。签名流程记录不自动删除，模拟晚到创建者无法激活并可再次清理。停用／删除账号和工作进程隔离后的容量释放仍待实现，不通过放宽权限或猜测未知代际绕过。

首次九版 207 组和两版 MySQL 定向 16 组通过、SQLite 两版各 127 项真实进程检查通过后，MySQL 并发取消失败。`before-lock-order/` 保存原源码、运行结果及独立诊断实例的 `innodb-status-readable.log`：InnoDB 确认两个事务分别持有工作流根和目录根并互相等待；完成复核先目录后工作流，与主流程相反。修正为所有阶段先工作流、再目录／账号，并保留回调后的内容复核。原 16 进程诊断通过，其 47 项仅为纯并发，不计 SIGKILL；最初诊断描述的运行模式错误已在当前运行框架修正并在设计文档明确。初始测试漏传 SQL 时间预算参数的运行框架错误也保留，未计作 SDK 缺陷。

最终 `acceptance.json` 确认同一修正源码 230 组检查通过：`cleanup-final-matrix/report.json` 九版 207 组（每版 532 项断言及 10 次语法）；`mysql-cleanup-final.log` 两版私有无 TCP MySQL 的 FileStore／独立 MySqlStore 定向 16 组（每版 300 项）；六组实际进程各 127 项，以及候选源码／PDO 示例静态检查。进程仅在 PHP7.2／8.5 的 SQLite+FileStore、MySQL+FileStore、MySQL+独立 MySqlStore 三组合执行，共 96 个并发工作进程及 36 次实际 SIGKILL，覆盖预留提交、外部创建、取消 COMMIT 前后和物理删除前后。准备中断仍能按已预留代际清理，SQL 取消和通知不重复，删除后 SQL 失败保留签名记录供重试。

256 个相关源码／示例／测试文件在全部检查结束后与运行前 SHA256 一致，所有任务已结束，私有 MySQL 由运行框架关闭清理。当前 SDK 仍是 230 源码／191 公开候选，本次没有将候选写入 SDK、冻结新 API 或执行完整 SDK 门禁；通知仍是本地 Outbox 意图，不是 SMTP、原生 HTTP／浏览器或生产验收。完整 R2.7 和 R1—R6 保持未完成。


## 2026-10-18 停用／删除账号因子管理与凭据状态绑定

`/tmp/sosecurity-factor-retirement-a9i0dj7m/` 新增 `FactorInspection` 和独立管理读取／退役。目标账号为空也要核验管理权限；对当前有效账号拒绝退役。先在同一 PDO 提交签名退役标记及审计，再按准确代际清理物理槽位；其他代际保留。管理回调获得服务器生成的原始目标快照，实际独立操作员密码／TOTP／一次性授权组合绑定主体、状态及槽位，错误主体或版本不产生修改。普通重新启用、MFA 标志重置、同主体重建以及调用首次初始化／绑定均不能让受管理路径恢复认证；显式独立恢复仍待实现。

初轮 243 组及全部进程组合通过后，追加 `retirement-inactive-credentials.php` 确认停用账号没有登录身份时，审计回调修改实际密码但不推进版本可绕过原管理快照。`inactive-credentials-before.log` 和 `before-inactive-credential/` 保存反例及源码。可选 `FactorRepository::credentialBinding()` 补充当前主凭据状态，PDO 示例按 4096 字节限制读取，并区分 SQL NULL 与超限无效值；先摘要实际字节再编码，支持 NUL 后内容及非 UTF-8。它不产生认证身份，不改普通 Repository／IdentityRepository 契约。新的管理摘要域版本 2 令旧快照强授权失效。

最终 `acceptance.json` 确认修正源码 291 组通过：`retirement-credential-matrix/report.json` 九版 252 组，每版 736 项及 11 次语法；`mysql-credentials-final.log` 两版私有 MySQL 定向 24 组，每版 FileStore／独立 MySqlStore 合计 598 项；12 组真实进程，取消／清理每组 127 项、退役每组 79 项；两版实际旧读取代码各 7 项；候选源码／PDO 示例静态检查。新增凭据反例在 SQLite 每版 17 项、MySQL 每版 8 项，含同版本密码改写回滚，SQLite 另覆盖 NUL／非 UTF-8 区分及 16MiB 异常字段在 8MiB PHP 内存限制下拒绝。

进程仅在 PHP7.2／8.5 的 SQLite+FileStore、MySQL+FileStore、MySQL+独立 MySqlStore 六个组合执行，共 144 个同时启动的工作进程、60 次实际 SIGKILL，覆盖工作流预留、外部准备、取消和退役标记 COMMIT 前后、物理代际删除前后。审计只有首次退役写入，部分完成保留标记并可重试。两版独立旧解析器进程通过反射确认实际加载原始类，旧格式可用，退役格式拒绝；不是替代解析器模拟。

矩阵 266 个相关程序文件在全部 MySQL／进程检查后与运行前 SHA256 一致，旧兼容性组另有含原源码的 276 文件清单。全部任务结束、私有 MySQL 正常关闭清理，仅使用合成账号及本地隔离数据库／存储。当前 SDK 保持 230 源码／191 公开候选，没有将此候选整合到 SDK、公开冻结新接口或验证正式邮件／原生 HTTP／浏览器／生产。工作进程隔离后的容量回收、完整 MFA 管理、独立恢复／代际运维、SDK 工厂／消费者和完整 R1—R6 继续。


### Outbox 键列表读取上限补齐（本地专项）

本次沿用已有正文及元数据防护，为 `claim`、`candidates`、`maintain` 的键列表添加 SQL 字节限制；聚合阻塞查询只返回存在标记。无效键在后续记录查询前以 `outbox.corrupt` 拒绝，维护按实际列排序以避免表达式别名引入排序成本。

新增三个实际 SQLite 事务测试：历史校验完成后、键列表查询前，把键改成含 NUL 的 16MiB TEXT。在 8MiB PHP 内存限制下拒绝，独立连接确认消息及根记录完全不变。仅撤销三个键投影的隔离反例在领取读取处因尝试分配 16777248 字节而耗尽内存（退出 255，预期失败），证据为 `/tmp/sosecurity-outbox-negative-6fkmeg3e/result.json`。

已执行并通过 PHP7.2—8.5 九版 SQLite 六类定向测试，共54组，每版1236项：字段／正文626、输入边界50、硬上限8、核心175、安全370、索引7。覆盖合法空正文／NUL／非UTF-8、超策略限额、1MiB精确硬上限及超出1字节拒绝；拒绝输入不调用 SQL 或权限回调，宿主事务保持。16MiB异常读取及10000条历史验证使用8MiB PHP限制，合法1MiB正文单独使用32MiB。结果和源码哈希保存在 `/tmp/sosecurity-outbox-bounds-8raq1u4f/`。本次修改的 SqlOutbox 通过 PHPStan，修改的 PHP 文件通过 PHP7.2语法检查；未执行完整SDK门禁或生产测试。

同一源码随后通过 PHP7.2／8.5 的私有 MySQL 关联专项，每版9组、1416项（结构依赖360、核心175、安全370、对账268、对账并发31、并发148、输入50、硬上限8、索引6）。控制器退出0，禁用TCP的临时实例 `/tmp/sosecurity-mysql-qha536cv` 已停止并删除；摘要保存在上述证据目录的 `mysql-result.json`。仅测试本地隔离数据库，未访问业务数据库。


### Outbox 防御性修复续验（2026-10-18，本地测试库）

本次核对现有字段、正文与键列表读取限制，保留超限／类型异常按损坏状态拒绝、合法 NUL 正文字节不截断的行为。新增同一宿主事务中的拒绝后续写测试：5字节含NUL正文超过4字节策略时不执行SQL或权限回调；随后合法4字节消息与业务写入可以由宿主一并提交或回滚。独立连接确认提交前不可见、回滚后消息与业务写入均不存在且根记录恢复原值；提交后正文逐字节领取及确认。输入专项由50项增至76项。此行为不替代必需业务事件入队失败时应中止业务单元的要求。

已执行并通过九版PHP7.2—8.5 SQLite六类定向检查，共54组、每版1262项（字段／正文626、输入76、硬上限8、核心175、安全370、索引7）。异常16MiB字段与10000条历史在8MiB PHP限制下检查，合法1MiB正文使用32MiB；来源哈希执行前后保持一致。证据为 `/tmp/sosecurity-outbox-local-review-ybgevzwu/report.json`。同一来源随后通过PHP7.2／8.5私有MySQL关联专项，各9组、1442项（输入76项），控制器退出0；禁用TCP的临时实例已停止并删除。摘要为同目录 `mysql-result.json`，完整日志为 `/tmp/sosecurity-outbox-local-review-mysql.log`。测试仅针对本地临时测试库和合成数据，未访问业务数据库。Outbox与共享SqlSchema通过PHP7.2目标、level5静态分析，新增测试通过PHP7.2语法检查，Shell／MySQL控制器语法与 `git diff --check` 通过。完整SDK门禁及生产测试未执行。


### 受管理 MFA 前置请求与历史目标权限（隔离候选）

最新候选 `/tmp/sosecurity-factor-preflight-b4mgifg0` 继承首次绑定阶段，验收为该目录 `acceptance.json`，当前尚未接入 SDK。实际反例确认缺失意图的确认请求在预算拒绝时仍返回 null；修复前源码和失败记录在 `before/`。另一修复前反例确认历史 inspect 跳过目标权限，记录在 `negative-inspect/result.json`（预期退出255）。首次负向测试的加载脚本错误单列于 `negative-inspect/autoload-error.json`，不作为修复有效性或SDK故障证据。

实现将八个含 source 的公开请求统一为 public预算→当前权限→组件主体的账号／因子账本读取；所有内部提交前及最终事实复核保留。覆盖缺失、pending、过期、终态和尝试耗尽的确认，检查拒绝时没有安全表读取或审批回调；预算回调撤权后必须再次检查当前权限。initialize 无 source，仅提前管理权限。事务归属探测可先执行，宿主预算／权限回调也可执行自己的受控查询，因此不声称“完全没有SQL”。历史 inspect 在 current／return 阶段传入账本认证的目标review，最终预算之后重新授权，保留账本密钥独立轮换后的历史审计，不强制读取当前目录。

初始动态源码的九版 SQLite 共369组（25类程序×9及16次语法×9）通过，`matrix/report.json` 确认328程序文件在执行期间保持；每版主程序统计1479或1480项，差异来自确认／取消争抢的允许结果。两版私有无TCP MySQL、FileStore及独立连接MySqlStore共44组通过，`mysql-report.json`及`mysql.log`保留每组合11类／671项（每PHP版本1342项），实际一次性授权、正常管理、绑定、限次、权限撤销、未知结果及历史权威／密钥轮换均覆盖；实例 `/tmp/sosecurity-mysql-5f493x9f` 已停止并删除。

初次静态检查发现3处无用闭包捕获。待初始动态快照完成后，仅删除这三处捕获；`unused-captures-before/` 保存原文件、静态失败和准确差异，327个其他程序文件保持。清理脚本最初的匹配断言拒绝了两个同形闭包，未修改源码；随后因未生成最终清单导致验证启动失败，日志保留在 `final-start-error.log`；限定正确上下文后重跑。最终源码的请求／历史目标权限／两种历史轮换四类程序×9、目标文件语法×9及候选源码／示例静态，共46组通过，`final-checks/report.json`确认最终328文件哈希保持。动态初始369＋44与最终46合计459组分阶段验收，不将初次静态问题或验证脚本错误隐藏为全程一次通过，也不声称全部使用同一源码哈希。

`parent-delta.json` 显示本候选修改 FactorOperations、新增两份测试；相对父快照还包含前一轮已在SDK修复的SqlOutbox依赖变化，其余父阶段程序文件保持。主SDK实际仍230源码／191公开候选，本轮未接入因子候选，未执行完整SDK门禁、SMTP、浏览器、生产或部署验收。全部旧认证／修改入口统一、活跃账号特权撤销、容量／保留期及未知结果处置、跨账号／维护并发、独立恢复、正式通知／原生入口、SDK接入及完整R1—R6继续，见候选 `next-factor-work.md`。


### 受管理 MFA 封存与旧入口边界（隔离候选）

当前 `/tmp/sosecurity-factor-mode-3856mcz4/acceptance.json` 取得本地定向终态，未接入SDK。相对父前置候选，修改TotpFactors／FactorRegistry，新增两个内部候选类和13个测试／辅助程序；`parent-delta.json`核对，主SDK仍230源码／191公开候选。原17个MFA和15个Registry公开成员参数前缀保持，Registry只追加可选fence；受管理依赖必须配置相同权威。

v2 HMAC封存包绑定实际键与部署上下文，显式adoptManaged迁移空／准确旧代际。包永久保存，禁用／撤销／准备过期清空payload但保留旧入口屏障。普通读取／认证／begin不自动创建或迁移；授权prepare／准确删除／明确revoke可在全新空槽位建立屏障，但不接受原v1占用。15种原始物理方法在受管理模式中调用准确用途的当前权限，并持有完整操作栅栏；回调不进入可重试存储回调，重复真实存储回调的14次执行只有12次外层权限检查，随机数／加密nonce不在重试内重发。

签名目录current／binding／verify／初始化／采用／退役跨完整SQL及物理操作持锁；恢复工厂继承已配置fence，其他权威拒绝。元数据inspect独立管理授权，关闭后仍可检查，不作为认证。实际桥接覆盖密码／TOTP／会话、正常禁用／恢复码轮换／重加密、首次及重新绑定、替换、取消删除屏障和停用退役；恢复桥接使用参数绑定的独立测试回执，不将其称作正式迁移审批或生产授权提供器。

初始 `matrix/report.json` 九版SQLite共468次执行（每版34类程序与18次语法）通过，343程序文件执行期间哈希保持。`mysql.log` 两版／FileStore及独立连接MySqlStore四组合各11类，共44次通过。标准未受管理MFA205项及既有认证／目录／正常管理／绑定／并发检查保持，未全面关闭原API来替代迁移。

三个实际退化反例分别删除空封存标记、移除物理逻辑操作栅栏、移除目录完整操作栅栏，触发实际旧begin写入、重加密暂停期间维护及物理证明后认证返回前维护；`negative/`初版与`negative-final/`补测各3组均预期退出255，检查具体副作用标记，不把任意异常当作有效反例。正式mode-processes累计35组、280个业务工作进程、210对SIGSTOP／SIGCONT，包含真实原SDK10个物理方法、上一候选15个方法、两个原MFA适配器方法及新工作进程；原密码流程补测使用实际AuthenticationFlow／PasswordIdentityProvider，在密码正确且MFA标志false时仍通过原适配器触发v2拒绝，不退化成密码认证。进程统计不含其他旧基础专项、fsync辅助子进程或反例。

补查3000个控制字符的JSON转义，原先已拒绝但误归为configuration.hmac_message；`encoded-before.json`保留实际分类。随后JSON编码上限15000字节，修正为mfa.managed_corrupt，`encoded-after.json`核对；真实存储拒绝后快照不变，对象编码钩子未执行。与实际旧密码流程补测一起，`final-checks/report.json`九版复验／语法／静态／两版签名采集86次，以及`mysql-final.log`两版双后端8次通过。

最后补齐权限回调元数据边界：按16个准确用途校验字段及类型，代际必须为32位小写十六进制，超长、NUL和无效值在回调前以mfa.input拒绝；未受管理实例的无效Bound ID仍按原行为返回。`metadata-checks/report.json`九版复验／语法／静态／两版签名采集59次、`mysql-metadata.log`两版双后端4次通过，最终343文件哈希保持。`negative-metadata/results.json`修正代码探针通过，实际前一权限实现把100000字节编号传入回调，预期退出255；不称作已证实数据库写入攻击。

验收选取468＋44＋86＋8＋59＋4＝669次分阶段程序／静态执行，包含两次两版签名比较各4次数据采集；不是669个独立功能，也不声称所有执行使用同一源码哈希。初始清单在matrix/source.json，编码／旧密码阶段为encoded-source.json，最终为final-source.json；最终相对初始改2个实现／4个测试，其余337文件保持。初次recovery新测试误解既有clean四字段返回结构，只改测试期待，记录在exploratory-errors.json。三套私有无TCP MySQL实例均已停止删除，mysql-phases.json逐项核对。仅合成本地身份和数据库，未执行生产、真实浏览器、SMTP、远端CI、归档消费者或完整SDK门禁。

明确未完成：实际closed-cleanup.json探针在取消流程到期后drainAndPurge，返回account.completion_unknown，权威已关闭，SQL记录2→2保留，没有错误释放容量。当前普通开放工作能力不能重入已关闭独占清理上下文；下一步补专用准确代际清理能力，禁止重新开放旧权威或让认证／准备借用关闭能力。正式迁移意图／精确独立强审批／同PDO版本及审计通知、已登记权威提供器（任意open本地fence不是权威切换）、停止旧进程协议、全部恢复／回收／轮换组合、活跃账号特权撤销、永久标记容量与未知结果、独立恢复、正式通知／原生入口／SDK及完整R1—R6继续，见候选next-factor-work.md。HMAC不防完整有效旧状态重放，不将本轮边界当作独立备份新鲜度证明。


## 关闭权威下的准确因子回收（2026-10-18）

受管理MFA关闭清理隔离候选已完成550次本地选取检查（九版SQLite513、两版私有无TCP MySQL双后端32、静态1及公开签名采集4），350程序文件哈希保持。仅复用已持久关闭的EX排空上下文，允许准确代际删除或保持原样的冲突，不开放普通认证／准备／修改；四组退化反例验证上下文、效果、最后目标复核和预算后当前权限不可省略。原始到期取消探针从保留两条记录变为准确回收，权威始终关闭。私有实例已清理，候选未接入SDK，完整规划继续。

候选 `/tmp/sosecurity-factor-closed-_i5ngbhk/acceptance.json` 保存选取证据。`LocalEpochFence::closedWork` 只在同一对象当前排空回调持有已验证EX文件句柄时运行；`TotpFactors::revokeGenerationClosed` 要求准确代际及物理写入前的当前目标校验，存储适配层独立限制返回和写入效果。`FactorRecovery` 最终预算之后复核权限；失败不释放SQL容量。13组新增进程检查实际包含26业务工作进程、26次SIGSTOP、13次SIGCONT及13次SIGKILL。此阶段不代替正式迁移、已登记SQL权威提供器、全部维护组合、独立恢复或SDK交付。


## 已登记SQL权威与拒绝回滚候选（2026-10-18）

当前隔离候选 `/tmp/sosecurity-factor-registered-typed-oxj0j0o7` 新增 `FactorWorkerAuthority`，在准确宿主PDO中认证已有format2恢复根、site／scope／epoch／策略／密钥及本地栅栏绑定，检查历史元数据，并在权限回调之后重核相同根；不存在或不匹配均拒绝，不创建根、不自动迁移。`FactorRegistry` 的目录授权前后先登记根再目录／账号，保持已有恢复锁顺序。完整物理操作的SH或关闭EX由原栅栏负责，SQL提供器不是独立的登录凭据。

`managedRegistered()` 强制直接提供受类型约束的SQL权威对象，并显式使用该SQL策略的I/O预算（当前测试默认10000毫秒，范围1—30000）；既有通用 `managed()` 及其1000毫秒默认保持。权限提供器仍必须验证当前调用者、准确用途／槽位／代际；测试中的允许回调只隔离登记契约，不是生产授权。物理scope／subject可能是隔离槽位，宿主须由当前工作流确认它与实际账号的关系，不能把字符串本身当作身份。

追加真实反例确认返回false的权限回调曾提交其账号删除；现于提供器SQL事务／保存点中抛出内部拒绝，完成局部回滚后再转换为false，外层继续返回 `mfa.authority_denied`。异常与返回阶段拒绝也回滚该权限检查的SQL副作用；返回阶段可能已经发生的物理写入仍报告 `mfa.completion_unknown`，不伪称撤回跨存储副作用。新增21项同时验证宿主此前业务写入仍可自行提交。

本地定向验收文件为 `/tmp/sosecurity-factor-registered-typed-oxj0j0o7/acceptance.json`。分阶段选取869次检查通过：拒绝修复后父候选九版567次，当前受类型约束入口252次、PHP7.2／8.5私有无TCP MySQL双因子存储后端36次、九版预算对照9次、静态1次及公开签名采集4次，共302次。父／当前各358程序文件快照保持，二者仅两个源码及三个测试辅助文件不同，不能当成一份快照；主SDK230源码保持。七个相关类型的91个旧公开成员保持，四组撤去防护的实现触发准确副作用。当前新入口13组进程检查含52业务工作进程、26次SIGSTOP、13次SIGCONT及13次SIGKILL。预算对照实际延迟1100毫秒，原通用入口1000毫秒预算在物理存储前拒绝，新入口10000毫秒SQL策略成功；此对照不证明首轮异常的原因。全部自建MySQL实例已停止并清理，无在途句柄。该验收只覆盖所述本地配置，未接入SDK或执行生产验证。

初轮MySQL在PHP8.5／独立MySqlStore组合的恢复确认处出现回调不可用，已退出并清理；原始日志 `/tmp/sosecurity-factor-registered-ck7bxxfu/initial-phase/mysql.log` 保留。仅增加底层异常记录的隔离复制版使用原预算通过，未重现异常，故不能确认原始根因；新的受类型约束SQL入口采用明确的SQL预算，这与旧通用入口的预算不同，不能以新通过覆盖旧失败。父阶段与当前阶段是不同快照，后续验收须分别列明。候选未接入SDK；正式精确迁移／强审批／审计通知、活跃账号特权撤销、完整维护组合、独立恢复及完整R1—R6继续。


### 精确迁移取消竞态与显式续办（2026-10-18，开发候选）

最新候选 `/tmp/sosecurity-factor-migration-cancel-cnh7ao6t` 在父候选迁移核心之上修复最后权限回调封存物理因子的取消缺口。提交前封存保留SQL预留，提交后封存报告未知；SQL已取消且存在准确prepared物理回执时，只允许新审阅和独立审批后重建目录屏障，普通取消不续办。PHP7.2新增191项通过，包括两种因子状态、两种目录来源、提交／返回回调、拒绝审批无写入及普通取消终态。首轮遗漏闭包捕获导致通用sql.unavailable，底层诊断确认后修正，初轮与诊断日志分别保留，共享SqlTransaction保持原样。

六组确定性反例与修正代码正向对照均完成，`negative-final-report.json`逐项记录SHA、预期退出255和准确副作用标记，覆盖取消丢失意图、假CAS凭据版本、准备态认证、实际密码变化后封存、已消费恢复码被回滚以及SQL意图未提交前封存。PHP7.2／8.5八类型的109个既有公开方法保持；候选src／PDO示例通过PHP7.2目标静态检查。

父候选 `/tmp/sosecurity-factor-migration-qoqqe34l/matrix-final/report.json` 的九版702次关联／语法检查已终态0、来源哈希保持，但它未覆盖新发现的最终取消回调问题，不能据此认定缺口已关闭。修正候选九版324次定向／语法检查也已全部终态0，源码哈希保持；父／当前清单分别387／389个程序文件，差异为一个迁移源码、一个新增测试与一个新增探针，SDK源码保持。父／修正两轮PHP7.2／8.5私有无TCP MySQL双后端仍在执行，终态及准确句柄见新候选 `progress.json`，不可将待完成检查写为通过。只使用合成身份与本地临时测试数据库，SDK未整合，完整R2.7和R1—R6继续。


### 迁移历史维护（2026-10-18，开发候选）

当前 `/tmp/sosecurity-factor-migration-maint-9c12hdo5` 完成首轮PHP7.2八组409项：维护102、关闭只读13、混合／重封存43、安全／未知提交52、最小容量15、1000条合成历史114、实际独立审批40、真实进程30。1000条认证合成历史回收901条迁移终态并逐条保留99条其他用途，8MiB限制保持，之后实际新迁移成功；不把合成历史称为1000个真实账号迁移。三业务工作进程、3次SIGSTOP、1次SIGCONT及2次SIGKILL验证存活工作阻止EX、COMMIT／返回中断及准确后续处理。

六组准确副作用反例和正向对照在negative-maintenance-report.json保留；关闭能力的正向源码与当前版本仅一行注释变化，negative-source-note.json验证可执行代码相同，不能写为同一完整哈希。最终静态和PHP7.2／8.5九类型131个既有公开方法对照通过。首次不存在列、重复加载与进程依赖设置错误，以及排空前重入栅栏的产品失败均单独保留。九版matrix及三轮私有MySQL仍在执行，准确句柄／边界见progress.json；当前阶段未全部验收，未接入SDK或执行生产操作。


### 生命周期组合与恢复锁顺序（2026-10-18，开发中）

精确迁移两阶段已终态：387文件祖父九版702次／私有MySQL52组，389文件修正九版324次／MySQL56组，两份SHA分别保持；后者的六组反例、静态及8类型109个旧方法对照保留于acceptance.json。祖父未覆盖最终取消回调缺口，不能用其绿色矩阵关闭后来问题。两私有实例均已删除，完整R2.7未完成。

维护401文件矩阵792次终态1，8个失败全部在migration-maintenance.php的NULL秘密搜索，其他784次通过；MySQL在第七组因新增操作者排序导致未限定账号的测试辅助取错行而退出1，六组先通过，实例清理。不会将上述部分检查写成全矩阵通过。修正限定账号后的407文件生命周期候选九版117次终态0；实际五组156项，包括正常32、替换22、退役78、混合19、账号选择5。保留期及cleaned状态的初次预期错误单列于该目录first.log；当前MySQL78组仍执行，继承的NULL测试尚未在该快照修正。

最新 `/tmp/sosecurity-factor-lock-order-53orjz4m` 修正FactorRecovery事务内操作者／根锁顺序、预算前置及回调后的根快照复核，并修正空因子测试；PHP7.2新增68项、六组准确反例及静态通过，PHP7.2／8.5九类型134个旧方法保持，PHP8.5维护100项通过。角色读取使用实际SQL行和事务检测，未声称已复现数据库死锁。当前九版864次关联及两版双后端私有MySQL60组、两版file-store满额MySQL2组仍在执行；一次控制器早于脚本生成的启动退出2、未创建实例，单独留档后顺序启动。终态以progress.json对应准确句柄为准，不在观察超时后重启活动控制器。

仅本地临时数据库与合成身份；未接入SDK、未执行生产、发布或外部通知验收。


## Outbox 正文返回值保护与读取前篡改复验（2026-10-18）

在现有元数据字节投影、实际 BLOB 类型检查和正文长度筛选之上，`SqlOutbox::body()` 的 SQL 返回值增加等长 `CASE` 保护；不返回不匹配的原始正文，也不将异常正文截断后使用。保持公开接口、表结构、空 BLOB 的旧 PDO 兼容处理及合法二进制 NUL 往返。

`tests/outbox-input-bounds.php` 新增真实 PDO 语句执行前的故障注入：在历史和元数据已校验后、独立正文查询前，将正文改成超大 BLOB，SQLite 另外覆盖 NUL 开头／中间含 NUL 的 TEXT。领取、状态查询、维护均须拒绝；独立连接核对消息及根记录完整回滚，并重新领取确认原始含 NUL 正文。异常值由数据库生成，检查过程不在 PHP 中分配大正文。

已执行并通过：

- `php72`、`php73`、`php74`、`php80`、`php81`、`php82`、`php83`、`php84`、`php85` 各执行核心、安全、对账、正文／字段边界、输入边界、硬上限六组，共54组、14328项；每版分别175、370、274、626、139、8项。正文／字段及输入专项使用8MiB PHP限制；合法1MiB硬上限专项单独使用32MiB。仅使用测试自动创建的临时SQLite文件。
- PHP7.2／8.5私有无TCP MySQL各九组1463项，共18组2926项：每版结构依赖360、核心175、安全370、对账268、对账并发31、核心并发148、输入97、硬上限8、历史索引6。测试控制器退出0，专属实例 `/tmp/sosecurity-mysql-9lowjx5z` 已停止且目录已删除。
- PHP7.2修改文件语法检查；PHPStan level5、目标PHP7.2的修改实现检查通过。首次用默认PHP7.2启动当前PHPStan工具发生工具语法错误，改用PHP8.5运行后退出0；可选Turbo扩展因系统glibc版本不足未加载，分析仍完成且无错误。未修改工具或降低分析级别。

命令为本地SQLite六组专项以及 `python3 tests/mysql_check.py --outbox php72 php85`。日志分别保存在 `/tmp/sosecurity-outbox-defensive-sqlite-20261018.log`、`/tmp/sosecurity-outbox-defensive-mysql-20261018.log`，静态日志保留首次启动失败及改用PHP8.5后的结果。MySQL测试脚本创建独立数据目录、关闭TCP，仅使用其专属Unix socket，禁止指向业务数据库。

未执行完整SDK门禁、生产数据库测试、远程投递、部署或发布；没有提交或推送Git。上述内存边界指PHP读取的字段和PHP内存限制，不代表数据库引擎内部内存或进程RSS上限。


## 受管理 MFA 的 SDK 增量接入与当前整合门禁（2026-10-18）

当前运行时代码已接入工作树，249源码／208公开候选，原191类已有公开成员保持，PHP7.2／8.5反射契约一致。新增 `account_factors` 配置、`Security::accountFactors()` 强类型注册权威工厂、当前目录的 `ManagedSecondFactor` 及只读能力诊断；43个可移植PHP测试文件、28组常规运行入口位于仓库中，不依赖临时源码自动加载。接入内容及剩余能力见[指南](account-factors.md)。

证据目录 `/tmp/sosecurity-factor-sdk-integration-r3f52ta9` 保留接入前已有工作树文件、源码清单、API对照、原始失败、定向复验及当前私有MySQL日志。本地源码接入不是完整R2.7交付或发布。

已执行并通过：

- 原191类已有公开成员逐项对照；当前208类候选的PHP7.2和8.5契约相同。新工厂九版各112项，验证构造／诊断没有SQL、权限回调或文件变化，准确PDO／上下文绑定，未初始化栅栏不自动补建，实际登记权威、TOTP证明及权限拒绝均生效。
- 首次741次九版关联／双版语法检查中737次通过，四次原有 `account-factory.php` 在PHP7.3／7.4／8.0／8.3的8MiB聚合进程中失败，不能记作整矩阵通过。其余MFA用途、保留期、重封存、未知结果、独立真实操作员审批、现有账本／配置及API检查均保留日志；记录的源文件清单保持。
- 原工厂测试多个独立场景留下不可达的回调／PDO环；PHP8.0实测回收165个环后用量由6430344降至3201928字节。最终仅在下一独立场景开始前调用GC，不跳过任何断言、不扩大8MiB。随后九版原工厂各140项以及公开首次登记／实际迁移各4项，共18次补充检查全部退出0。首次登记通过 `FactorMigration::initialize()`，没有直接调用内部Ledger初始化。运行时源码在这次修正前后逐文件相同。
- 两版新Composer消费者退出0，验证新类型、配置、缺失服务拒绝及现有端到端流程；384文件归档退出0，源码完整且不含开发／私有配置制品。目标PHP7.2的level5静态检查通过；首轮分析器128MiB工作进程不足保留失败，改为512MiB仅扩大分析工具预算，产品及测试预算保持；可选Turbo扩展的glibc告警保留。

已执行但失败／中断及当前在途：

- 首轮PHP7.2默认环境缺少sodium，按依赖异常拒绝，未计通过；使用已确认加载sodium的隔离运行时执行后续检查。工厂首次测试误用已消费的绑定TOTP并误判返回契约，保留first.log，修正为下一时间步及返回totp标识后通过，未修改产品验证。
- `memory-fix/` 中的可选实现拆分仅为排查探针，未写入SDK；当前运行时仍为首次整合源码。
- 整合后私有MySQL首次在排查内存时受控停止，句柄37022退出130，专属 `/tmp/sosecurity-mysql-lv0c6lde` 已清理；保留已经通过的7组和中断日志，不算整个控制器通过。运行时未改写后，在新的私有实例明确续跑其余33组并追加公开首次登记，合计目标40个组合；当前句柄59808，实例 `/tmp/sosecurity-mysql-pqnujzbu`，日志mysql-resume.log，尚不能声称整阶段全部通过。这次续跑基于已确认的受控终态与明确排查结果，非观察超时重启。

前置隔离候选的终态另列：`factor-lock-order-53orjz4m` 的864次命令均通过，但控制器退出1，因为同期间主仓库Outbox文件被本轮已验证的修复修改，汇总清单不再相同；候选自己的文件保持，不能写成同一整体快照验收。该候选私有MySQL60组及两版FileStore物理后端的1000条历史检查2组均退出0，独立实例已删除。更早生命周期407文件候选的MySQL在PHP8.5继承NULL搜索测试处退出1，原日志保留；不能用后续修正覆盖旧失败。

未执行本阶段完整SDK门禁、原生浏览器、正式MFA通知投递、生产数据库、远端CI、发布或独立安全审查。普通prepared未知意图处置、活跃账号特权撤销、独立备份新鲜度及退役恢复、正式通知／预算／原生请求保护和其余R1—R6保持未完成。


### SDK 接入私有 MySQL 终态补记

接入阶段句柄59808已退出0，`mysql-final.json`逐项核对两版运行时×两种物理后端×十组用例共40个唯一组合，原控制器停止前7组与续跑33组均有实际通过日志；新增的公开首次登记也覆盖两版／双后端。当前300文件清单保持，`/tmp/sosecurity-mysql-pqnujzbu`已删除。该阶段 `acceptance.json` 只证明249源码／208公开候选的本地增量接入，首次741次检查的四个引用环测试错误、18次修正补充及受控停止仍分别保留；并非完整SDK或完整R2.7验收。


## Outbox 防御性修复的等长二进制替换续验（2026-10-18）

本次核对工作树已有的 SQL 字段字节上限、实际 BLOB 类型、正文返回值等长保护及超限输入提前拒绝，保留公开接口与表结构。`tests/outbox-input-bounds.php` 在历史校验后、正文查询执行前，新增两种等长二进制替换，与既有超大 BLOB／SQLite 含 NUL 的 TEXT 一起验证领取、状态和维护。检查准确拒绝码 `outbox.corrupt`，并通过独立连接核对整个操作回滚及原始 NUL 正文可继续领取确认。

已执行并通过九版 PHP7.2—8.5 SQLite 五组专项，共45组，每版1375项：核心175、安全370、字段／正文626、输入196、硬上限8。前四组使用8MiB PHP内存限制，合法1MiB硬上限专项使用32MiB；字段／正文包含SQL生成的16MiB异常值。相关 Outbox 源码、共享 SQL 字段实现和两份边界测试执行前后哈希保持，清单及结果为 `/tmp/sosecurity-outbox-local-followup-20261018-report.json`，完整日志同前缀 `-sqlite.log`。

PHP7.2／8.5 私有 MySQL 各九组1514项、共18组3028项全部通过：每版结构360、核心175、安全370、对账268、对账并发31、核心并发148、输入148、硬上限8、索引6。控制器退出0，专属实例 `/tmp/sosecurity-mysql-9r464p8p` 已停止且目录已删除。控制器使用 `python3 tests/mysql_check.py --outbox php72 php85`，关闭 TCP，仅使用自己创建的 Unix socket 和合成数据，日志为同前缀 `-mysql.log`。不得将专项指向业务数据库。

PHP7.2 修改测试语法检查及 PHPStan level5、目标PHP7.2的 Outbox／共享SQL字段实现检查均通过，静态日志为同前缀 `-static.log`。隔离反例 `/tmp/sosecurity-outbox-digest-control-zqn833vn/result.json` 仅在临时类副本移除正文摘要比较，输入专项因等长替换没有被拒绝而按预期退出255；正式源码未修改，反例不是正式测试失败。

仅本地测试数据库；未执行完整SDK门禁、生产、远程投递、部署或Git发布。PHP内存限制不等同于数据库引擎内部内存或总进程RSS限制。


## 活跃账号因子特权撤销候选与SDK接入（2026-10-18）

隔离候选位于 `/tmp/sosecurity-factor-privileged-revocation-b730342i`，现已增量接入SDK；原209类已有公开成员保持，当前251源码／210公开候选、62份可移植PHP测试、41组常规入口。`FactorRevocation` 和 Registry 工厂使用准确已登记的同PDO物理服务；预览与审批区分特权撤销、仅清理两种用途，绑定完整当前账号／目录／工作进程根、明确的 `block_mfa_login` 效果与300秒以内期限。请求预算先于历史和当前操作者查询，审批消费在SQL之外，授权排空及各提交／删除阶段再次检查当前预算／权限／状态。

实际动作永久关闭整个旧工作进程权威；同PDO推进活跃账号凭据版本、保留MFA要求及密码／地址／角色／账号状态，将目录写成严格格式6的revoked标记，并提交审计及通知意图，再定向清理准确旧物理代际。保留操作ID、原预览摘要与决定时间；不交付因子秘密／恢复码，不把撤销改成普通自助禁用。提交或持久化状态不确定均报告 `account.completion_unknown`；关闭EX上下文中只读检查，再以新的独立审批明确执行原撤销或仅清理，不能自动重放旧决定。恢复该账号的独立流程尚未实现，普通绑定／替换不能绕过。

PHP7.2五组初步检查220项已通过：正常／故障51、安全76、独立操作员56、实际认证12、真实进程25。操作员使用真实SQL身份、密码、TOTP、近期重新认证及一次性Grants，验证用途／scope／目标／状态不符和账号／角色撤销拒绝。认证测试先完成真实密码与TOTP登录，再确认旧会话和新的密码登录在撤销及显式工作进程权威交接后均拒绝；不包含HTTP或浏览器验收。进程测试启动三个自有工作进程，内核确认SIGSTOP、共享锁阻止排空、SIGCONT及逻辑提交前后实际SIGKILL，明确续办且不重复审计。

`negative/report.json` 两个控制组通过：正式代码各退出0；仅移除独立审批verify结果检查后，实际提交撤销并产生审计，准确标记 `UNSAFE_REVOCATION_WITHOUT_INDEPENDENT_APPROVAL` 后退出255；仅移除工厂的实际密码材料保持检查后，错误密码写入与撤销被一并提交，准确标记 `UNSAFE_REVOCATION_PASSWORD_CHANGE_COMMITTED` 后退出255。所有变体只存在私有副本。

九版执行真实上一版Registry读取代码，current／initialize／adopt／inspect均拒绝格式6并保持数据，`previous-reader-report.json` 九次退出0。PHPStan level5、目标PHP7.2检查候选两份实现通过。初次物理清理漏传必需的当前复核回调已修正；错误码预期和非法输入异常类型的测试错误分别修正，日志保留；首次静态提示冗余instanceof，删除冗余判断后通过。

九版候选五组及两份语法检查共63次全部通过，每版220项断言；冻结的运行时与既有测试清单保持。两版各12组既有流程共24次退出0；PHP7.2／8.5反射候选相同，209类原公开成员保持。接入后的五组测试各两版加九版API检查共19次全部通过，源码／测试清单保持；接入后静态、两版新Composer消费者及386文件归档也退出0，分别见 `integrated-report.json`、`integrated-source.json` 和相关log。初次移植脚本的消费者类名匹配断言在拷贝后停止，确认部分写入状态后修正选择器，根API与冻结候选完全相同，再完成上述检查，没有覆盖其他已有修改。

两版双物理后端私有MySQL20组880项全部通过（handle30162终态0）；251份有效运行时代码哈希保持，与当前SDK相同，专属 `/tmp/sosecurity-mysql-mnledh7m` 已停止且目录已删除，见 `mysql-final.json`／`effective-mysql-runtime.json`；上一普通prepared处置MySQL32组2980项（handle12943终态0）已全部通过，250份有效运行时代码清单保持，实例 `/tmp/sosecurity-mysql-_le_428l` 已停止且目录已删除，接入前250文件的历史整体root清单已随本轮新功能改变，只有实际选用的有效运行时文件映射保持，不得把两份证据合成一棵新快照。以各report及控制器终态为准，未完成的组不计为通过。本地源码／测试冻结，未测试生产、实际通知投递、浏览器、部署或发布；完整R2.7和R1—R6仍未完成。


## 撤销／退役后的独立新因子恢复候选（2026-10-18）

隔离候选 `/tmp/sosecurity-factor-restoration-c0gjzjtu` 尚未接入SDK。新增 FactorRestoration，扩展严格格式7目录与专属历史维护配置；当前主SDK仍为251源码／210公开候选。恢复只接受当前active／verified账号的retired／revoked标记，账号启用与地址验证由宿主完成，不能通过恢复顺带改变状态、密码、地址或角色。新槽位由服务器生成并独立于旧槽位，先持久化恢复意图及单一待处理游标，再返回一次性准备资料；SQL尝试计数先于外部证明，新因子证明后才可签发新的独立启用预览与审批。

启用永久关闭整个旧工作进程权威，准确复核新物理状态后，同PDO推进账号凭据版本、设置MFA必需、写格式7目录和审计／通知意图。未知提交／关闭／返回状态只能读取保留记录、另取新审批明确续办；不能重新交付旧恢复码。继续认证须显式交接到新权威。单纯构造服务不建表、不初始化根、不采用旧因子。

取消不清理当前认证槽位；准备槽位和旧槽位清理使用独立用途，排空后只删除准确非当前代际。已清理动作经准确新预览检查不重复审计。保留期外显式删除终态时，一并选择并认证关联游标，页游标仍按实际扫描页推进，最多50条直接扫描加50条关联记录；页大小1的实际回收及容量复用已有证据。历史重封存覆盖流程及其游标，保留原payload和时间，其他用途不改写；三条历史满额时启用不额外占用记录，两个空位不足时原子拒绝。极旧意图保留原created_at／retire_at，本次取消／清理独立retain_until防止新决定立即被删。

首轮PHP7.2各专项已有通过日志：正常87、取消／保留期67、证明26、故障78、持久化33、真实独立操作员147、重封存46、容量18、进程28、实际认证19、输入／当前权限79项。后续已加强检查新准备槽位，而非仅观察旧user槽位；最终冻结组合仍以matrix-report.json为准，不能把这些初步结果合称同一冻结快照验收。操作员覆盖真实SQL密码／TOTP／近期重新认证／一次性Grants及错误用途、目标、scope、状态和撤权；实际认证覆盖旧会话失效、旧因子／旧恢复码拒绝、新TOTP与新恢复码仅一次接受；进程使用三个自有工作进程及真实SIGSTOP／SIGCONT／SIGKILL验证共享锁和提交前后续办。

`negative/report.json` 三组控制全部取得预期结果：正式代码退出0；移除独立启用审批检查后实际推进版本并提交恢复审计，标记 `UNSAFE_RESTORATION_APPROVAL_BYPASSED`；移除实际凭据材料保持检查后错误密码与恢复一并提交，标记 `UNSAFE_RESTORATION_PASSWORD_CHANGE_COMMITTED`；移除新决定保留期后实际删除极旧流程与游标两条记录，标记 `UNSAFE_FRESH_RESTORATION_DECISION_PURGED`；三种变体均因准确副作用标记退出255，仅存在于私有副本。目标PHP7.2的level5静态通过。

初次目录辅助代码在第二次交接时重复使用路径、超期取消的错误码预期、把300秒原生准备期限误当900秒工作流证明期限、审批测试只观察旧槽位等测试问题分别修正并保留日志。外层栅栏读取失败的未知结果分类、最后一次证明计数及新决定保留期由代码复核补齐，并有专门测试；不降低证明／权限或内存限制。当前九版135次（12种专项与三份语法）和两版既有41组关联流程仍在执行，未完成组不计通过。

仅自己创建的本地测试状态；未进行生产、真实SMTP、HTTP／浏览器、发布或独立审查。独立备份新鲜度／安全代际、所有用途统一运维、正式MFA通知与原生入口及完整R1—R6继续。


## Outbox NUL 后等长篡改与中文标识边界复验（2026-10-18）

核对当前工作树的 SQL 字段受限投影、SQLite 实际 BLOB 类型与长度、正文查询等长返回保护和完整摘要比较，现有运行时实现保持。新增测试只修改 `tests/outbox-input-bounds.php`：原正文 `a\0b` 在元数据验证后、正文查询前被替换成 `a\0c`，验证 NUL 后的不同字节不会因长度一致而被接受；同时保留 NUL 前移、NUL 被替换及超大值注入。领取、状态和维护均以 `outbox.corrupt` 拒绝，独立连接确认整次操作回滚，随后仍可领取并确认原始正文。

中文聚合标识按 UTF-8 字节计数：85个中文字符加一个ASCII字符共256字节可正常入队、领取及确认；257／258字节以及含NUL标识在SQL查询和权限回调前拒绝，根记录与消息数量保持。

已执行并通过：九版PHP7.2—8.5临时SQLite共45组，每版1414项（核心175、安全370、字段／正文626、输入235、硬上限8）；除合法1MiB正文使用32MiB外，均为8MiB PHP限制，异常数据在数据库内生成。源码／测试清单执行期间保持，详见 `/tmp/sosecurity-outbox-nul-final-el47qr10/sqlite-report.json` 与 `source.json`。PHP7.2测试语法检查通过，Outbox及共享字段实现按PHP7.2目标、level5静态检查通过。首次静态命令因 `vendor/bin/phpstan` 不存在而未执行分析，改用已有 `tools/vendor/phpstan/phpstan/phpstan.phar` 后退出0，原日志保留。

已执行并通过：PHP7.2／8.5私有无TCP MySQL共18组，每版1553项（结构360、核心175、安全370、对账268、对账并发31、核心并发148、输入187、硬上限8、索引6）。控制器终态0，专属实例 `/tmp/sosecurity-mysql-c4btot2n` 已停止且目录已删除；相关源码与测试清单终态复核保持。结果为同目录 `mysql.log`、`final-report.json`。仅本地合成测试数据库；未执行完整SDK、浏览器、生产、部署或发布。PHP内存限制不代表数据库引擎内存或总进程RSS上限。


## 独立新因子恢复接入与共享历史未知结果分类（2026-10-18）

三份实现 `FactorRegistry`、`FactorRestoration`、`FactorIntentMaintenance` 已从隔离候选增量接入本地SDK；当前252份运行时PHP、211个公开候选、Account46文件。新增16份可移植PHP测试文件，常规 `tests/account_factor.py` 从41组扩为54组，另保存实际上一版Registry读取代码为 `tests/fixtures/account-factor/registry-format6.php`，仅改类名避免冲突，原始和测试样例SHA在同目录JSON中保存。恢复不重新采用旧秘密，准备和启用使用不同用途的独立审批；流程及同PDO契约见[接入指南](account-factors.md)。

共享历史维护新增确认缺陷：授权排空后同步持久化失败透传 `factor.fence_durability`，SQL提交后的外层权威检查也未分类为未知结果。候选修复覆盖迁移、普通操作、恢复三用途的关闭持久化、开放／关闭上下文最终读取及重封存最终读取，关闭前授权拒绝保持原拒绝语义。修复前 `maintenance-outcome-before.log` 退出255，修正后单版108项通过。旧MySQL控制器在确认产品缺陷后仅对准确自有控制器发SIGINT，终态130，旧实例已清理；三组初步通过不计最终验收，原快照映射和停止原因保留。

最终候选 `matrix-final-report.json` 的144条命令全部退出0，九版各13组752项及三份语法检查。汇总控制器退出1：其覆盖整个主仓库测试的清单中，只有无关 `tests/outbox-input-bounds.php` 在独立用户任务中变化；候选252份有效运行时代码及候选测试未变。有效文件清单与边界另存 `effective-matrix-final.json`，不将整个主仓库描述为同一冻结快照。两版各41组既有流程共82次全部通过；目标PHP7.2的level5候选静态通过。先前135／82组是历史维护IO修正前快照，只保留为历史证据。

接入后35条检查全部退出0（两版13组新专项及九版公开API），`integrated-source.json` 清单执行期间保持，API与冻结候选完全相同，原210类已有成员保持。接入静态、PHP7.2／8.5全新基线消费者及387文件归档退出0。基线消费者只证明新增类可加载及既有功能；另新增 `tests/account_factor_consumer.py`，全新Composer安装独立包副本，反射确认恢复类来自安装包，外置测试只加载消费者自动加载器及安装包的示例／SQL资源。两版各四组281项（恢复87、生命周期67、实际认证19、共享历史故障108）全部通过，临时消费者及其SQLite状态自动清理；该命令已加入CI，但未声称远程CI已执行。Python新增／修改运行框架语法解析通过。

候选的13组私有MySQL按两版、两种物理后端共52组已全部输出通过，每版1504项，`mysql-final-report.json` 记录568份冻结程序哈希保持；控制器PID2536163及其父进程均已终态，专属实例 `/tmp/sosecurity-mysql-6psxnld1` 已停止并清理。原执行句柄无法重新取得，退出码保留null，未从每组通过日志推断控制器退出0。当前SDK与冻结252运行时代码仅随后上传导出修复的两个文件不同，恢复相关250份保持，不能称当前整库统一快照。没有生产、实际SMTP、原生HTTP／浏览器、独立审查、提交或发布结果，完整R2.7与R1—R6保持进行中。所有候选与接入日志均在 `/tmp/sosecurity-factor-restoration-c0gjzjtu`。


## 完整有效旧备份的新鲜度缺口复现（2026-10-18，未关闭）

`/tmp/sosecurity-factor-freshness-u4qhnsjx/backup-session-before.php` 使用自动创建的私有SQLite与FileStore、合成账号，先完成真实密码／TOTP登录，普通恢复码轮换推进凭据版本后确认旧会话拒绝。随后将全部自有SQL表的原始封存根／行／账号数据、会话及因子FileStore文件恢复到完整有效旧状态，保留当前外部open栅栏与配置epoch。PHP8.5实际旧会话重新通过，准确标记 `UNSAFE_VALID_OLD_COMPLETE_BACKUP_REAUTHENTICATED_REVOKED_SESSION` 后退出255；这是未修复风险的反例，不是正式验收通过。252份运行时代码哈希保持。只恢复SQL并保留当前FileStore的对照退出0，旧会话保持拒绝；不能把该较窄对照用于证明完整备份新鲜度。

最初测试恢复SQL时只将Outbox正文绑定为BLOB，误把Account账本payload写成TEXT，运行时按 `sql.corrupt` 拒绝，没有到达观察点。该测试错误和日志单独保留；修正为按自有SQLite结构恢复每列实际类型后取得上述准确副作用证据。没有修改运行时验证、密钥或生产状态。独立状态见证、未知提交后的明确恢复及安全代际迁移仍在实现，不能据此关闭R1.4／R2.7。


## 独立状态见证隔离原型（2026-10-18，未接入）

候选为 `/tmp/sosecurity-factor-freshness-u4qhnsjx`，主SDK252份运行时代码保持不变。`LocalStateWitness` 把完整操作放在独立本地EX锁与签名检查点下：先核对旧摘要，再同步持久化pending，执行SQL／物理操作，确认事务结束、新摘要和最终预算后持久化current。公开请求预算先于SQL状态读取；晚预算变化后重新检查状态。已有宿主事务不被提交或回滚，异常不自动恢复旧检查点，未决文件不自动重建。尚未实现正式有界状态来源、全部SDK入口强制接入及独立审批恢复／安全代际，原始完整旧备份风险仍未关闭，详细契约见[设计](account-factor-freshness.md)。

已执行并通过：九版PHP7.2—8.5共45条命令，每版核心85、真实进程32、完整备份保护10项及两份语法检查；`matrix-report.json` 全部退出0，`matrix-source.json` 在运行期间保持。所有PHP进程为8MiB限制，实际旧SQL／会话／因子备份在认证回调前被拒绝。每版三个自有子进程实际SIGSTOP，内核状态验证后测试EX锁超时；一例SIGCONT继续成功，提交前／后两例SIGKILL保留pending，即使随后恢复旧SQL状态仍拒绝新写入。超长见证文件由ftruncate生成16MiB，受限读取安全拒绝。

PHP7.2／8.5独立无TCP MySQL各45项通过，控制器handle34086终态0。覆盖原生PDO真实提交、旧SQL恢复拒绝、提交回执丢失、SQL启动的宿主事务与回调遗留未提交事务保持、pending持久化失败及最终预算拒绝；autocommit保持1。专属 `/tmp/sosecurity-mysql-edvuc9er` 已停止且目录删除。`mysql-source.json` 是执行后归档清单，不冒充执行前冻结清单；见证运行时及已有测试同时受九版矩阵的未变清单核对。没有业务库连接配置或生产数据读取。目标PHP7.2的level5静态检查退出0。

`negative/report.json` 两个准确副作用控制通过：正式原型各退出0；仅移除旧状态摘要比较的私有变体实际重新认证已撤销会话，标记 `UNSAFE_WITNESS_STALE_CHECK_BYPASSED_REAUTHENTICATED_REVOKED_SESSION` 后退出255；省略操作前pending持久化的变体，在实际COMMIT后回执丢失、恢复旧SQL后仍提交新写入，标记 `UNSAFE_WITNESS_PENDING_OMITTED_NEW_WRITE_AFTER_UNKNOWN_BACKUP_RESTORE` 后退出255。变体仅在私有类副本。初轮控制因测试把require放在strict_types之前编译失败，不能计为捕获危险副作用；原日志位于 `negative/initial-declaration-error`，修正声明顺序后取得上述结果。

完整备份保护测试最初误把FileStore锁条带命名为64位摘要后缀，按测试自身文件白名单提前拒绝；修正为真实 `lock-0`—`lock-63` 名称并不把锁文件当作认证内容后，通过正式组合。所有测试只涉及自己创建的本地临时数据库／目录／子进程；没有生产恢复、公开HTTP／浏览器或部署验收。


## 上传内容与私有保存路径的导出保护（2026-10-18）

R1.2继续检查其他敏感对象，确认 `Candidate` 正文与 `StoredFile` 完整私有路径会被var_export、print_r及serialize导出；只使用合成标记和虚构路径，原始结果保存在 `/tmp/sosecurity-upload-export-jj1z7j8m/before.log`。两份类使用闭包保存敏感值，普通调试隐藏正文／完整路径，序列化及反序列化明确拒绝；显式访问器、二进制字节数、摘要、克隆及公开元数据保持。依赖序列化传递这两类对象的集成需迁移为可信标识／元数据与当前重新验证，详见[上传指南](upload.md)。

`tests/upload-export.php`新增38项并纳入 `bin/check.sh`。九版PHP7.2—8.5导出38项、原上传84项、公开API共27条命令全部退出0，`source.json`与`report.json`清单保持，强制要求GD／fileinfo以免未执行被计为通过。实际上一版两份源码经独立加载映射执行新测试，在导出断言处按预期退出255，没有修改正式源码来制造反例。211类原有公开成员保持，仅追加两类各三个导出保护方法；初次成员比较脚本误将空JSON列表当字典而未生成报告，修正后 `api-report.json` 通过，不将脚本错误当作产品失败或兼容证明。

PHP7.2目标level5检查Upload通过，Shell语法与修改消费者Python语法通过；两版新Composer消费者及388文件归档通过。消费者新增真实安装包对象的普通／嵌套导出与序列化拒绝断言，两版都退出0，见 `consumer-exports-72.log`／`consumer-exports-85.log`；之前较窄的基线安装日志另保留。`acceptance.json`只证明该专项阶段，不是当前完整SDK门禁、实际扫描服务或生产验收。主SDK仍252运行时PHP／211公开候选。

独立状态见证九版矩阵及恢复接入检查发生在本次两份Upload源码变化之前，不将这些阶段拼成新的整库冻结快照。恢复服务的私有MySQL使用自己的252份冻结源码，当前仍执行，后续主仓库Upload修改未改变该运行时映射。


### 因子物理处置的命名空间绑定修复（2026-10-19）

首版 `/tmp/sosecurity-state-factor-containment-3o4ryas9` 的两版SQLite真实强审批反例实际清空另一命名空间文件，原材料未清理，准确标记为 `UNSAFE_FACTOR_PLAN_NAMESPACE_SUBSTITUTION`；权限策略反例同时证明会话／因子命名空间均未改变策略指纹。首版已有绿色矩阵和原MySQL终态保留，不能作为此缺口的验收。

修正版 `/tmp/sosecurity-state-factor-namespace-y7cn_9mu/acceptance.json` 把因子文件引用纳入清单域2，把会话／因子引用纳入权限策略域3。九版54条全部通过；MySQL十组402项通过，控制器退出0、无TCP私有实例已删除；各145份候选输入保持，46源码PHP70200／level5静态通过。942方法检查仅两处指纹计算改变，其他44源码保持。首次旧工具和静态内存不足失败分别保留，最终单进程／1GiB分析通过，无规则屏蔽。详见[处置指南](account-state-factor-containment.md#命名空间修正版验证)。候选未接入主SDK；未决效果收敛、孤立材料、队列及最终恢复和完整R1—R6继续。


### 固定因子清单与未知物理效果收敛（2026-10-19）

当前候选 `/tmp/sosecurity-state-factor-resolution-sized-p0y63z85/acceptance.json` 新增准确、无旧秘密的持久化效果清单及新的独立近期MFA／重新认证／一次性批准续办。仅把原字节或已完成文件收敛成原签名空封存；部分／再次中断保留pending，成功仍quarantined，不改可信摘要或原未知操作。数组引用不能改变已批准内容。

基版661份输入下117条中109常规通过、六个准确错误写入反例通过、一条Fiber未执行、一条8MiB内存失败；MySQL同样保留失败并清理。当前仅一处文件读取分配改变，其他48源码保持；九版各37项原／新读取对照在8MiB通过，16MiB图集成下两版MySQL四组188项和PHP7.2引用隔离35项通过、实例清理，49源码静态通过。PHP7.2分配保留峰值10MiB，不宣称完整图支持8MiB。最初错误用途测试的预期错误及无文本255退出分开保留；数据限制未放宽。完整说明见[收敛指南](account-state-factor-resolution.md)。SDK整合、全部材料／队列、最终安全代际和完整R1—R6尚未完成。


### 只读快照基础正式并入本地SDK（2026-10-19）

本阶段 `/tmp/sosecurity-snapshot-sdk-fsp9name/acceptance.json` 将九个候选基础源码逐字节并入 `src/Account`，新增八个公开类型、一个内部类型，FileStore仅添加三个纯元数据方法和目录身份采集；原211类公开成员及原读写／清理／锁方法保持。当前261源码、219公开候选。原生组合示例返回构造函数，不自行安装DDL或读取业务；中英文指南、显式示例DDL、常规测试和私有MySQL专项入口同时纳入。

九版159次调用均退出0，无未执行项，包含每版13组快照、API、语法及既有核心／存储检查；两版一万实际文件、全新Composer消费者和412文件归档通过。291份冻结程序输入保持。两版私有无TCP MySQL共20组，各317项、8MiB PHP限制，通过且原97662控制器退出0、实例4hxepoxm清理；280份关联输入保持。261源码PHP70200／level5静态通过，没有新增忽略规则。

可复现命令见[只读快照指南](state-snapshots.md)。本次是已进入SDK的数据能力，摘要不提供独立新鲜度、权限或恢复保证；完整当前SDK的HTTP／浏览器／外部服务／远端CI及生产未执行。其余恢复权威／审批／材料／队列／最终安全代际、原生整合及完整R1—R6继续，不能把本阶段标记为全规划完成。


## 本地ClamAV适配器与上传读取预算（2026-10-19）

`Upload\ClamAvScanner`已接入现有Scanner接口及宿主注入方式，构造不联网。完整INSTREAM二进制内容分块传输，连接／发送／读取共用总期限；响应最多4096字节，读至EOF后只接受单个准确OK。感染、异常、多结果、服务限额及超时均不生成目的文件。私有socket及父目录在交换前后复核；仍由宿主保护全部上级目录、服务账户、引擎配置及签名更新，不宣称密码学服务认证或病毒绝对安全。

本次同时复现并修复已有Validator小文件预分配：PHP7.2在8MiB下读取很小的文件，原实现按5MiB策略请求缓冲而致命退出。新实现先确认打开后的实际大小保持，在策略硬上限内按实际大小加1读取，保留完整大小／时间及超限检查。九版8MiB读取专项各6项通过，包含20MiB策略下的小文件及超过20MiB的稀疏源文件拒绝；不提高运行时内存限制或读取上限。

最终矩阵为 `/tmp/sosecurity-clamav-sdk-wohh5m20/final-transport/report.json`，原30993控制器退出0。九版PHP7.2—8.5协议、既有上传／私有导出／配置／可移植核心、API和593文件语法检查，两版全新Composer消费者、416文件归档及私有真实clamd，共77条常规调用退出0。四个准确反例仅在临时类副本恢复“OK前缀即接受”或“首个NUL即结束读取”，两版均实际错误保存文件并触发危险标记，按预期非零退出；正式实现拒绝同一输入。81条调用全部达到预期，无未执行项，546份程序输入在执行期间保持。既有219个公开类型的成员签名全部保持，仅新增ClamAvScanner，当前262源码／220公开候选。

私有ClamAV1.4.6通过PHP7.2／8.5各12项，覆盖干净数据、合成测试签名命中、引擎与流限额及保存拒绝。只使用测试专用签名库；实例 `/tmp/sosecurity-clamav-real-aochr0cq`已停止并删除，不接管宿主服务或更新系统签名库。本轮未使用任何业务数据库。

首次完整矩阵81条已达到预期，但当时静态分析报告4处流函数类型／可达性问题，未记为阶段完成；探索性桩声明与全限定函数名尝试日志也保留，相关探索文件未纳入SDK。最终本地Unix流仅等待读写事件，使用每次最多1024字节的非阻塞有界读取，保留原失败拒绝及总期限；重跑上述完整矩阵后通过。262源码按PHP70200／level5静态退出0，没有新增忽略规则；可选PHPStan加速扩展因系统GLIBC不匹配未加载，分析本身已执行完成。日志为同目录 `static-final.log`。

阶段汇总 `/tmp/sosecurity-clamav-sdk-wohh5m20/acceptance.json`，接口对照及两行Validator修复差异保存在同目录。测试入口见[扫描指南](upload-scanning.md)。没有执行生产／宿主全入口／本轮浏览器／远端CI或独立审查，没有提交、推送或发布。持久隔离队列、异步重试、管理员处置、扫描后重检及完整R4.4／R1—R6仍未完成。


## 持久上传隔离核心（2026-10-19）

新增公开`Upload\Quarantine`／`QuarantineStatus`及两个内部实现，直接构造接口、示例、中英文指南、常规核心检查、API分类和消费者／归档检查已接入SDK。固定作用域的永久账本最多64项、默认64MiB累计内容预算；预留准确随机文件名后私有写入，扫描绑定内容摘要与状态版本，提供有限重试、管理员重扫／拒绝、不可变可用内容读取和分阶段清理。文件I/O、扫描及随机生成均在可重试原子回调之外。扫描器仍须负责自身传输期限，宿主负责调度、当前权限和CSRF。

原17559控制器终态0，83条调用全部达到预期，无未执行项，620份程序输入执行期间保持，报告为 `/tmp/sosecurity-quarantine-sdk-5mlwkvu_/report.json`，阶段汇总为同目录 `acceptance.json`。九版PHP7.2—8.5各535项核心在8MiB下通过，覆盖实际FileStore重建、正常／拒绝／过期、尝试和总字节／64项容量、等长篡改、权限／硬链接／符号链接、时钟回退、预留及删除确认丢失、失败记录续办和重复执行的纯回调。两版32MiB图片配置各562项通过，验证二进制PNG含NUL、扫描与可用读取的完整相同字节，以及仅允许jpeg时沿用验证器统一保存为jpg的约定；核心8MiB与图片32MiB配置分别报告，不提高图片验证器原预算。

两版真实PHP进程验证管理员拒绝暂停中的扫描后，旧干净结果不能重新放行；真实SIGKILL后任务保持不可用，租约到期后另一个进程接管，尝试继续累计。预留写入期间的清理被目录内永久锁阻止，强制结束预留进程后可明确清理staging，不遗留可用文件。两个准确反例仅在临时类副本移除完成状态／版本／尝试凭据检查，两版均在管理员拒绝后实际读出内容，触发 `UNSAFE_QUARANTINE_LATE_CLEAN_RELEASED_ACTUAL_BYTES` 并按预期非零退出。正式源码不做这一变化；反例不是常规检查失败。

私有无TCP ClamAV1.4.6与实际FileStore隔离流程组合，两版各26项通过，覆盖干净文件入队／扫描／读取、重扫期间拒绝、管理员拒绝／清理和测试签名命中后不可读，包含原同步扫描器与引擎／流上限检查。只用合成测试签名库，实例 `/tmp/sosecurity-clamav-real-93msc52m`已停止并删除，不修改宿主扫描服务或系统签名库，不代表生产病毒覆盖。其他进程测试也只操作自己创建的PHP子进程和临时目录；本轮未接触业务数据库。

两版全新Composer消费者从实际安装包执行私有入队／扫描／读取／重扫拒绝／删除，确认导入示例无初始化；两版423文件归档通过。九版既有上传83项、私有导出38项、读取预算6项、配置42项、可移植核心48项及222类API通过，新增／修改的8份PHP文件在九版语法通过。原220个公开类型成员签名与262份旧源码保持，仅新增4份源码；接口／源码对照在同目录 `compatibility.json`。这不是本轮完整SDK HTTP／浏览器或全部测试门禁的声明。

266源码PHP70200／level5静态退出0，未增加忽略规则；首轮一处realpath判断顺序的静态报错和161项初始检查日志保留，调整判断顺序并补齐累计字节、JPEG规范化及后续内容篡改分类后，以上最终快照重新验证。PHPStan可选加速扩展仍因GLIBC不匹配未加载，分析正常完成。没有生产、远端CI、独立审查、提交、推送或发布。

工厂配置／诊断、原生HTTP／CSRF／浏览器接入、其他真实元数据后端及完整R4.4继续；文件系统和元数据不是同一物理事务，永久锁、私有目录、磁盘配额及备份回滚恢复边界见[隔离指南](upload-quarantine.md)。完整R1—R6目标不变。


## 隔离工厂配置与只读诊断（2026-10-19）

新增独立`upload_quarantine`配置、Config::uploadQuarantine()及Security::quarantine()，不改变原同步upload／uploader()。配置严格校验未知字段、类型及队列／文件预算，禁止关闭扫描；工厂要求显式Scanner和共享持久状态，拒绝已知的MemoryStore／SessionStore，也拒绝原生file配置的元数据位于配置Web根内。按site与固定scope派生逻辑命名空间，自定义存储另保留现有站点包装。诊断检查已有目录、配置服务及实际Web根，不调用扫描器或读取任务，扫描／持久化／工作流保持manual，只返回固定原因码。

原56362控制器退出0，共68条调用全部退出0，没有未执行项；620份程序输入执行期间保持，报告与汇总为 `/tmp/sosecurity-quarantine-factory-0fv6wcnm/report.json` 及 `acceptance.json`。九版PHP7.2—8.5每版86项工厂专项在8MiB下通过：未启用与同步接口独立、无副作用构造／普通及主动诊断、扫描器缺失、非共享存储、公开元数据目录、非法／引用配置、256字节scope与128字节site、站点／scope隔离及实际FileStore完整流程。首轮78项检查后追加公开元数据拒绝及独立接口／主动诊断测试，最终快照完整重跑。

九版既有隔离核心各535项8MiB、通用核心13组195项、配置42项和上传83项均通过，222类API及5份新增／修改PHP文件语法通过。两个新消费者从实际Composer安装包验证直接隔离接口与惰性工厂、只读诊断及正常扫描／读取／拒绝／清理；两版423文件归档通过。266源码PHP70200／level5静态通过，无新增忽略规则；可选加速扩展未加载的环境信息保留，不影响完成分析。

两版私有无TCP ClamAV与原同步保存、直接隔离及正式工厂组合各36项通过，覆盖干净文件读取、合成签名拒绝和诊断保持manual。只使用自建测试签名库，最终实例 `/tmp/sosecurity-clamav-real-psq962hc`已停止并删除，不修改系统扫描服务／签名库，不代表生产病毒覆盖。本轮未接触业务数据库。

当前仍为266源码／222公开候选。既有API成员签名保持，仅Config与Security各追加一个方法，对照见同目录 `api-additions.json`。相对已验收隔离核心阶段仅修改Config／Security／Inspector三份运行时源码，四份隔离内核保持，见 `source-delta.json`。阶段常规入口与配置／中英文指南已更新；原生HTTP／CSRF／浏览器、其他真实元数据后端、全SDK完整门禁、远端CI、生产和独立审查未在此阶段验收。没有提交、推送或发布，完整R4.4及R1—R6继续。


## 原生隔离HTTP／TLS与浏览器接入（2026-10-19）

新增三份原生PHP示例及宿主SQLite DDL，提供真实密码认证／原生Session轮换、受保护的multipart上传、当前状态、本人私有下载、近期认证管理员重扫／拒绝／清理和独立有界CLI工作进程。网页不执行扫描；管理员不能因此读取别人的内容。每个修改要求POST、准确固定来源和单次CSRF；源账号、实际密码哈希、启用／角色及所有权在服务端核对，下载复制后再次检查身份与归属。原生文件Session目录、配置／数据库／隔离／状态目录均显式私有保护。业务SQL字段使用已有SqlSchema受限投影，配额查询最多8行并由SQLite写事务串行化。接入步骤与物理事务边界见[原生指南](upload-quarantine-native.md)。

最终原59836矩阵控制器及96913静态均退出0。39条调用全部达到预期：35条常规退出0，四个准确危险行为反例按预期退出1，无未执行项，656份程序输入执行期间保持。报告与汇总为 `/tmp/sosecurity-quarantine-native-rykoey5t/report.json` 和 `acceptance.json`。SDK266份源码和222类型API候选逐字节保持，九版API也通过，证明本阶段增加的是宿主接入交付物；对应检查为 `compatibility.json`。

九版PHP7.2—8.5真实HTTP每版716项，两版私有CA的TLS各716项通过，使用32MiB PHP配置。覆盖匿名／跨用户／跨站点拒绝、等待扫描不可读、私有服务停用后retry及恢复、正常完整附件／HEAD、Range与重复查询拒绝、角色变化后拒绝、合法301秒前密码会话的近期认证拒绝及真实重新认证恢复、重扫期间不可读、单次CSRF重放、非法状态删除无副作用、含NUL文本与单文件超限拒绝、真实二进制PNG、合成签名命中、8项主体配额、16MiB含NUL的SQLite角色字段安全拒绝，以及保存的密码哈希变化后旧会话失效。历史会话通过真实SDK密码流程及一致的过去时钟注册到专属账本，再装入自己创建的服务器Session文件，没有伪造验证对象或修改生产状态。

两版真实TLS Chromium在390像素宽度下通过密码／Cookie轮换、原生multipart待扫、实际CLI扫描、保存下载文件及SHA-256、管理员不获他人下载权限、重扫／重新认证／拒绝／删除、CSRF重放、退出与无横向溢出。浏览器断言由Node脚本报告，不把控制器的0项HTTP断言解释为未执行浏览器。两版新Composer消费者实际运行安装包HTTP端点、已安装DDL和工作进程，各50项所有权检查通过；导入业务／工作进程文件无输出、会话或扫描初始化。两版429文件归档及九版三份PHP语法／CLI缺失与超限参数检查通过。

四个隔离反例只在临时包中移除准确的一处归属比较或近期认证条件。两版跨用户反例均在真实登录、上传和扫描后读到另一所有者的完整内容，触发 `UNSAFE_NATIVE_QUARANTINE_OTHER_OWNER_READ_ACTUAL_BYTES`；两版过期管理员反例均实际拒绝原可下载文件，并使所有者读取变为409，触发 `UNSAFE_NATIVE_QUARANTINE_STALE_ADMIN_REJECTED_FILE`。最终日志以该预期RuntimeError结束，没有被清理异常覆盖；正式代码在相同场景拒绝。不能把这些预期反例记为正常检查失败。

初轮HTTP355项与扩展658项保留。最初浏览器表单失败后，抓到真实POST的Origin为null，核对MDN后确认no-referrer与普通表单的相互影响；新示例改为same-origin，继续准确来源与单次CSRF，不允许null来源。随后发现浏览器测试在POST响应上reload会重交已消费表单，新增成功HTML提交303回GET，并在真实浏览器核对刷新为GET且200。测试还曾在API反例消费CSRF后继续点击旧DOM的退出表单，现改为获取当前GET表单后继续；所有初始失败日志保留。初次静态argv可未定义问题以明确读取SERVER argv并校验参数修复，没有忽略规则。

SDK266源码及三份新原生示例以PHP70200／level5静态通过；可选PHPStan加速扩展的GLIBC环境警告保留，分析正常完成。每个测试仅创建自己的SQLite数据库、PHP进程、私有无TCP clamd和合成测试签名库；成功控制器及消费者均报告进程停止／目录清理，预期反例正常异常展开也完成相同finally清理。没有下载恶意样本、更新系统签名或停止宿主服务，测试签名不代表生产病毒覆盖。

尚未完成其他真实元数据后端的隔离组合、当前完整SDK门禁、远端CI、使用方／生产恢复和独立审查，没有提交、推送或发布。独立恢复权威、其余账号／状态工作及完整R1—R6仍保留，R4.4不据此提前关闭。可选常规门禁开关为SOSECURITY_REQUIRE_QUARANTINE_HTTP=1，实际安装包原生端点开关为SOSECURITY_TEST_NATIVE_QUARANTINE=1，均只用于明确配置的本地测试环境。

## R6.2 OIDC 阶段性适配（2026-10-20，本地）

Redis后端补验：`python3 integrations/oidc/tests/redis_process.py <独立消费者autoload> php72 php73 php74 php80 php81 php83`退出0，六版各通过联合会话29项和双进程竞态10项。控制器创建私有目录与归属标记，Redis禁用TCP，仅监听Unix socket；每个测试命名空间显式初始化，测试进程结束后关闭服务并清理目录。系统`php82`实际未加载`ext-redis`，Redis专项未执行；不能从该版FileStore／MySQL通过推断Redis通过。测试没有连接宿主Redis，也不覆盖Redis重启恢复或生产环境。

MySQL完整定向补验：同一`--oidc-process`私有无TCP实例在PHP7.2–8.3七版各运行`sessions.php mysql`并通过29项，同时每版双进程竞态10项通过。定向场景覆盖已关联身份签发、独立令牌与本地密码令牌隔离、容量、提供方注销、解除关联、账号版本变化、因子绑定新增后的失效，以及签发后注销交错。测试使用该控制器创建的临时库；默认MemoryStore／FileStore路径在PHP7.2／8.3各56项复验通过。此结果不包含真实第三方发行方、浏览器或生产宿主。

MySQL双进程补验：`SOSECURITY_OIDC_AUTOLOAD=... python3 tests/mysql_check.py --oidc-process php72 php73 php74 php80 php81 php82 php83`退出0，七版各10项。控制器自行创建带归属标记的本地私有MySQL实例，禁用TCP，使用Unix socket和测试账号安装`MySqlStore`结构；两个PHP进程在签发提交后／验证读取后精确交错注销，恢复时均拒绝旧权限，拒绝签发不留联合会话状态。实例由控制器在结束时关闭并随临时目录清理。未连接宿主数据库；不将本地数据库竞态等同第三方提供方或生产验收。

独立进程竞态补验：PHP7.2–8.3七版各执行`integrations/oidc/tests/process_race.py`并通过10项。每组使用新建0700私有FileStore目录和不同PHP进程：一组在联合会话状态提交后暂停签发，另一进程持久记录提供方注销，再释放签发，要求结果拒绝且无残留会话；另一组先签发并正常验证，再在验证读完旧会话状态后暂停，由另一进程持久注销，恢复验证必须拒绝。控制器等待子进程结束并自动清理私有目录。测试使用本地反射构造协议证明对象，不是第三方提供方验签或数据库／生产并发验收；它验证的是共享FileStore下的准确交错。

当前新增独立联合会话后，PHP7.2–8.3七版各执行`integrations/oidc/tests/sessions.php`并通过56项、`fences.php`通过50项；MemoryStore及私有FileStore覆盖关联签发、独立令牌与本地密码凭据隔离、单账号容量、提供方注销后逐请求失效、解除关联、账号版本／因子要求变化、重新打开FileStore，以及会话写入后立即收到注销时拒绝返回可用凭据。本机自建HTTPS发行方测试同七版各86项重新通过：真实签名回调签发独立联合会话，`LogoutProcessor`验证签名并提交回执和栅栏后，匹配的联合会话验证失败，本地密码会话保持。PHP7.2目标可选包PHPStan无错误。此阶段仍没有MFA账号的联合登录、第三方发行方／真实宿主／浏览器及生产验收；注销是逐请求拒绝，不宣称跨数据库原子提交或即时物理枚举清理。

此前仅有注销栅栏的阶段，PHP7.2–8.3七版各执行`integrations/oidc/tests/fences.php`并通过44项：MemoryStore／私有FileStore分别检查`sub`、`sid`、双目标及租户隔离，较旧注销不能降低栅栏，旧外部凭据被拒绝而本地密码会话仍可用，48小时后状态过期，但超过24小时签发窗口的旧凭据继续拒绝，新签发凭据可用。本机HTTPS专项同七版各86项重新通过；有效回调后用本地签名Logout Token验签、记录栅栏并确认旧外部身份无法再次解析。该历史快照尚无联合会话签发；第三方发行方及生产未执行。

独立私有 Composer 消费者锁定 `jumbojett/openid-connect-php` v1.0.2 和 `phpseclib/phpseclib` 3.0.57。PHP7.2–8.3 七版已执行并各通过 `integrations/oidc/tests/claims.php` 43 项声明边界、`links.php` 34 项本地关联检查（仅使用 `MemoryStore` 与私有临时 `FileStore`）、`signed-callback.php` 83 项本地签名回调检查及 `tls_integration.py` 86 项原始客户端本地HTTPS回调／注销令牌／持久回执闭环检查。PHP8.4 已执行并通过两组专项，但上游发出隐式可空参数弃用告警；PHP8.5 已执行并通过声明边界39项；关联测试已执行但在上游 v1.0.2 构造函数隐式可空参数弃用告警处失败，严格错误处理将其转为异常。本地 RSA 签名令牌已走上游验签、授权码回调、PKCE、`state`、`nonce` 和错误路径；测试以模拟端点响应替代网络。原始客户端另在本机自建HTTPS发行方下验证受信测试证书、令牌／JWKS请求、回调凭据中签名`sid`／`iat`与本地账号关联、已消费state不可重放、错误状态在网络请求前拒绝、错误签名／nonce、不受信证书、令牌端点／JWKS重定向及各131073字节超限响应拒绝；签名Logout Token专项验证`sub`／`sid`、显式`null`目标拒绝、单受众`azp`绑定与多受众、错误签名／发行方／受众／时间／事件／类型、禁止`nonce`及16384字节输入上限；私有FileStore回执检查正常完成后重复通知、宿主返回失败／抛异常后的重试、撤销后进程退出7再重试，以及相同`jti`不同内容拒绝；服务只监听127.0.0.1，证书／Session在私有临时目录中生成并清理。第三方发行方、浏览器、宿主登录／实际会话撤销与失联恢复、生产以及完整包门禁未执行。额外将私有消费者临时切换至上游开发提交 `d18f81f`，PHP7.2／8.4／8.5均通过39项声明与34项关联检查；这是探索性结果，发布依赖仍为稳定v1.0.2，PHP8.4／8.5已从可选包Composer范围排除。本地测试用反射构造外部主体，仅检查关联账本；签名回调专项另用真实本地RSA签名、上游验证路径和模拟端点，不证明真实网络发行方。PHP8.2运行PHP7.2目标的可选包PHPStan专项无错误；仅对第三方getter的不准确PHPDoc关闭“注释类型确定”假设，保留运行时类型拒绝。

# R4.6 告警 Outbox 工作者定向验证（2026-10-20，本地）

已执行并通过：`tests/audit-alert-worker.php`在PHP7.2—8.5九版SQLite各40项，覆盖持久接受后确认、可重试失败、异常协议死信和回执未知后按相同投递ID重领；PHP7.2／8.5各在私有、禁TCP MySQL测试实例通过40项。原Outbox输入边界与16 MiB正文预算在PHP7.2／8.5 SQLite各通过243项与986项，包含NUL前缀超限拒绝；私有禁TCP MySQL两端Outbox整组退出0，输入边界各195项、硬上限各8项。九版229类／接口API反射契约、PHP7.2目标PHPStan及636个PHP文件语法检查通过。PHP7.2／8.5当前源码归档各450文件，全新路径Composer消费者实际调用入队与工作者、严格manifest验证通过。真实通知目标、宿主幂等实现、当前源码完整私有门禁和发布未执行。

## R4.6 受权运维诊断定向验证（2026-10-20，本地）

已执行并通过：`tests/audit-diagnostics.php`在PHP7.2—8.5九版各20项，覆盖逐次授权、非严格布尔值与授权异常拒绝、拒绝时不读取故障后端、授权后故障传播、固定字段和敏感对象导出。九版230类／接口反射契约与PHP7.2目标PHPStan通过；PHP7.2／8.5各451文件归档和全新路径Composer消费者通过，消费者实际调用`Diagnostics::inspect()`。本轮诊断专项只使用私有FileStore，未连接业务数据库；前轮Outbox专项使用自建禁TCP MySQL。真实宿主身份权限、近期认证、HTTP请求保护、当前源码完整整版门禁、外部CI及发布未执行。

## R4.6 有限窗口告警补采（2026-10-20，本地）

已执行并通过：新增`MetricsSink`可选`retainedWindows`及`inspectRetained()`，`AlertOutboxPublisher`复用固定消息ID补入窗口；PHP7.2—8.5九版SQLite各18项，覆盖两个漏轮询窗口、同窗重复入队、旧窗口到期清理、70次跨窗后的有界历史，以及新旧模式双向策略拒绝和旧状态过期后启用。PHP7.2／8.5私有禁TCP MySQL各19项通过，另覆盖独立PDO上的`MySqlStore`指标与宿主Outbox事务同库入队；私有Redis／MySQL故障专项各新增2项保留窗口检查并在两版通过。九版230类API签名、PHP7.2目标PHPStan及两端451文件归档／全新路径消费者通过。当前源码完整整版门禁、真实通知目标、长期审计查询、保留期外恢复与发布未执行。

## R4.6 受权近期事件查询（2026-10-20，本地）

已执行并通过：`tests/audit-recent-events.php`在PHP7.2—8.5九版私有FileStore各30项8MiB断言，PHP7.2／8.5在控制器自建私有Redis与禁TCP MySQL各30项。覆盖严格授权和异常授权拒绝、拒绝时不读故障后端、含NUL主体的完整字节假名、按事件／作用域筛选、容量满时不调用下游、过期清理、损坏状态拒绝与敏感对象导出。首次Redis专项因测试时钟停在1970年而由真实Redis按服务器时间立即清理；测试改为未来固定日期后两版复验通过，未改产品过期逻辑。九版231类公开API签名、PHP7.2目标PHPStan、两端452文件Composer归档与全新路径消费者均通过；PHP7.2语法扫描通过。只操作临时私有存储，未接真实宿主授权或持久日志。当前源码完整九版门禁、远端CI、独立审查与发布未执行；本索引不能证明日志落盘、长期保留或不可篡改。

后续有限并发复验已执行并通过：`tests/audit_recent_process.py`在九版PHP的私有FileStore，以及PHP7.2／8.5的控制器自建私有Redis和禁TCP MySQL上，每组启动8个独立工作进程争抢容量3，均恰好3次接受、5次以`audit.recent_capacity`拒绝；独立进程读取到3条不同主体的事件，额外写入继续拒绝。测试已接入常规门禁与两个私有后端控制器。只证明这些本地后端的共享容量原子性，不证明日志接收器和业务操作的跨系统原子提交。

最大配置边界追加4项定向断言：使用64字节事件码、256字节作用域、1024字节主体及三个允许的最宽上下文字段，在8MiB PHP内存限制下写满64条并查询，第65条以`audit.recent_capacity`拒绝，下游接收器仍只调用64次。九版私有FileStore各34项、PHP7.2／8.5私有Redis与禁TCP MySQL各34项通过，控制器退出0并清理临时实例。只修改测试样例，未改运行时代码；上方495行PHP7.2完整门禁在追加这4项之前执行，因此它证明相同运行时代码的整合结果，新增边界用例以本段定向结果为准。

## R2.7 绑定与普通管理余项通知（2026-10-20，本地）

已执行并通过：`tests/account-factor/enrollment-notices.php`在PHP7.2私有sodium启动器与PHP8.5的本地SQLite／控制器自建私有禁TCP MySQL各28项，覆盖真实绑定、取消、普通管理清理及绑定通知发布拒绝后账号状态不变；`resolution-notices.php`同四组各18项，覆盖未知结果放弃成功的加密通知与Outbox引用，以及发布拒绝后的账号、审计、通知、队列回滚。两版全新Composer路径消费者各十四组加通知生命周期检查退出0，从已安装包加载服务，并包含新增两组；私有MySQL控制器退出0并清理临时实例。`git diff --check`、新增测试的PHP7.2／8.5语法及三个Python入口语法均通过。测试只涉及活跃且已验证的本地账号，未执行停用账号邮件、真实SMTP、目标宿主或当前源码完整九版门禁。

## R2.7 正式因子通知本机TLS SMTP（2026-10-20，本地）

已执行并通过：`tests/account_factor_smtp.py`在PHP7.2私有sodium启动器及PHP8.5各运行四个本机回环TLS SMTP情形。`tests/account-factor/smtp-notices.php`先通过真实普通管理服务回调发布一条固定无秘密因子通知，再由原`Dispatcher`、`SendBudgets`和`SmtpTransport`提交；正常接受后队列`sent`，EHLO期间账号停用时正文不上载且队列`dead`，SMTP已接受后账号停用报告`account.delivery_unknown`并保持`leased`待后续状态检查，服务器接受后丢回执时结果`unknown`且队列`dead`。测试复用本机自建TLS测试服务，数据库、证书和预算目录均为临时测试数据；已接入常规本地门禁及全新Composer消费者入口。两版全新Composer消费者各十四组及同一四个SMTP情形退出0，使用安装包源码与消费者目录下的测试文件。外部邮件服务、真实收件箱、目标宿主及当前源码九版完整门禁未执行。

## R2.7 正式通知与Outbox密钥联合退役（2026-10-20，本地）

`tests/account-factor/notice-queue-rotation.php`在PHP7.2私有sodium启动器与PHP8.5的临时SQLite、控制器自建私有禁TCP MySQL各15项通过，MySQL控制器退出0并清理实例：真实普通因子操作产生两条正式通知，通知账本与信封逐页轮换；仅新Outbox密钥在队列仍旧封存时安全拒绝领取；准确`account-factor-notice`队列逐页维护后，仅新密钥可读回并确认两条通知，消息编号、正文摘要、创建时间不变。两版全新Composer路径消费者各十五组加通知生命周期和本机TLS SMTP检查退出0，包含新增轮换专项。新增PHP测试两版语法、Python入口语法及`git diff --check`通过。本关口不覆盖同站点其他Outbox生产者、独立旧备份新鲜度或正式多进程停旧运维。


## 新凭据安装的原因子退役（2026-10-22）

[专项记录](state-installation-retirement-2026-10-22.md)保留首次测试清理失败、初轮四组 16 KiB 容量拒绝及一次只读尺寸诊断。压缩重复坐标后另冻结候选：八条定向命令全部退出 0，PHP7.2／8.5 在 SQLite／私有 MySQL 的五专项与十二次真实 SIGKILL 恢复通过，公开契约／静态／821 文件语法通过，输入未变、四次私有 MySQL 清理。初轮与修后内容不合并为完整十专项或九版本整轮；账号和见证仍禁用／隔离，最终恢复、上组未解释 503 及完整 R1—R6 未关闭。准确结果见[交付核对](state-installation-retirement-evidence-2026-10-22/delivery-check.json)。


## 范围证明代际退役（2026-10-22）

[专项记录](state-proof-retirement-2026-10-22.md)冻结八条命令全部通过：四种 PHP7.2／8.5 与 SQLite／私有 MySQL 组合的恢复／拒绝／续办、五个原生 Grants 及既有 API 退役专项通过，十二次真实 SIGKILL 后新进程／新批准续办通过。SQLite 两端另执行五个 8 MiB 普通／低层专项；两端 263 类契约、静态和 832 文件语法通过。输入未变、四个测试根及两个私有 MySQL 清理。原始 password-reset 路径不能绕过新标记；nonce／普通 CSRF 保持。移除 API 增量后的旧契约摘要准确一致，普通测试未弱化。未执行最终启用、保护 Links／ResetTokens 工厂及 HTTP、当前九版完整门禁与外部验收；旧业务 HTTP 503 未关闭。预检失败及修正单列，见[交付核对](state-proof-retirement-evidence-2026-10-22/delivery-check.json)。
