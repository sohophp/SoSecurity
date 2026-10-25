# 当前1.0.0本地交付入口

限定S范围的本地稳定交付已完成最终管理验收。先读[中文速读：可接组件、S/E边界、最小接入及限制](stable-v1-php-adoption.zh-CN.md)，再按[最小接入/迁移回滚指南](stable-v1-integration.md)与[准确S/E范围表](stable-v1-api-scope.md)接线。最新交付ZIP包含中文说明；准确提交、SHA256和本次最小安装验证由包外交付清单绑定。历史7ad825c包保留追溯，不冒充最新包。

以下是保留的历史开发记录与完整能力导航，不能视为当前稳定范围或未完成任务清单；不扩张首版承诺。

> 2026-10-22 G1 当前：[原生一次性操作与业务事务](state-grants-integration-2026-10-22.md)已接通五个直接入口、真实重新认证、同边界证明消费／SQL 及准确意图；复核中复现并修正字段映射策略被缓存忽略的问题。初轮十条、修后八条定向检查通过，两端 SQLite／MySQL 记录分别绑定内容，六次私有 MySQL 已清理。新入口 HTTP／真实强杀、最终恢复及上组未解释 503 仍开放，完整 F01／R1—R6 不关闭，31 项／80 小时上限保持。

> 2026-10-22 G5 当前：[格式 3 业务宿主、浏览器与真实中断](state-business-host-integration-2026-10-21.md)已接入原生 Bearer 文档更新、联合业务／认证备份回放、四次 Chromium、十二个真实强杀点及四次并发等待后拒绝。初轮 PHP8.5／MySQL 一次所有者拒绝返回异常 503，单次带诊断复验通过但根因未明，整组仍未通过验收；剩余六项通过、资源已清理。SDK src／公开契约与上一组字节一致；不关闭完整 F01／R1—R6，31 项／80 小时上限保持。

> 2026-10-21 G5 当前：[原生 Bearer 与业务 PDO 事务组合](state-business-integration-2026-10-21.md)已将只读准入、服务端对象／字段授权、真实 SQL 提交与最终见证放入同一边界，加入文档版本比较更新示例。固定八条命令全部通过，四个运行时／后端组合通过、输入一致，两个自建 MySQL 已清理；本入口业务 HTTP、真实强杀／并发、格式 3 完整业务流程、其他入口与最终恢复仍开放，不关闭完整 F01／R1—R6，31 项／80 小时上限保持。

> 2026-10-21 G5 当前：[MySQL HTTP 与持续时钟到期](state-http-mysql-integration-2026-10-21.md)已补两端真实 MySQL HTTP／TLS，SQLite／MySQL 均核对请求中实际到期且 pending 前拒绝、旧 SQL／认证文件／PHP 会话回放拒绝。固定 12 条命令全部退出 0，六次 Chromium、八次实时到期检查通过，八个临时宿主和四个临时 MySQL 已清理；业务事务组合、其他入口和最终恢复仍开放，完整 F01／R1—R6 不关闭，31 项／80 小时上限保持。

> 2026-10-21 G5 当前：[原生受保护宿主 HTTP／TLS／Chromium](state-http-integration-2026-10-21.md)已接通同图登录／MFA、真实 CSRF／Origin 与 Cookie／Bearer 隔离，联合恢复旧 SQL、认证文件和 PHP 会话后旧令牌及旧 Cookie／CSRF 均拒绝。固定 11 条命令全部退出 0、输入一致，四个临时宿主已清理；MySQL HTTP／业务事务组合、其他入口及最终恢复仍开放，不关闭完整 G5／F01／R1—R6，31 项／80 小时上限保持。

> 2026-10-21 G1 当前：[账号 API 准确意图与真实中断](state-api-intent-integration-2026-10-21.md)已绑定实际操作者／目标、凭证摘要、标准化参数、身份／范围、完整来源和准确策略，pending／current 保留同一意图。固定 27 条命令全部退出 0、八次真实强杀通过，输入一致、四次临时 MySQL 已清理；其他授权／写入者、宿主 HTTP 与最终恢复仍开放，不关闭完整 G1／G4／F01／R1—R6，31 项／80 小时上限保持。

> 2026-10-21 G1 当前：[账号凭证 API 公开工厂与写入前准入](state-api-entry-integration-2026-10-21.md)已接通准确原生图的八个公开入口；普通拒绝在 pending 前结束，已发生效果的未知结果继续隔离。固定 27 条命令全部退出 0，输入一致、四次临时 MySQL 已清理；精确操作者／目标意图回执、自定义／带审计委托、其他授权及最终恢复仍开放，不关闭完整 G1／F01／R1—R6，31 项／80 小时上限保持。

> 2026-10-21 G4 当前：[账号 API 凭证原生退役与准确边界](state-managed-api-integration-2026-10-21.md)已接入同一实际服务图、八个入口的前置边界检查、固定空账本／代际和新批准续办。固定 25 条检查全部退出 0、12 次真实强杀恢复通过，输入一致、四次临时 MySQL 已清理；公开 API 宿主前置准入及工厂、其他证明和最终启用仍开放，不关闭完整 G4／F01／R1—R6，31 项／80 小时上限保持。

> 2026-10-21 G4 当前：[旧版 API 密钥主体代际处置](state-api-retirement-integration-2026-10-21.md)已接入准确独立批准、固定永久标记及未知效果续办，旧格式／旧代际密钥拒绝，新代际可签发。固定 27 条检查全部退出 0、12 个真实终止恢复场景通过，输入一致、四次临时 MySQL 已清理；受保护 API 工厂、其他授权和最终启用仍开放，31 项／80 小时上限保持。

# 文档导航

初次使用先看README和配置，按实际需要选组件；需求、计划与验证记录分别描述目标、实施安排和已执行证据。

| 要解决的问题 | 入口 |
| --- | --- |
| 生命周期完整 SQL 来源声明与显式外层入口 | [生命周期接入记录](state-lifecycle-integration-2026-10-21.md) |
| 注册／两类恢复的公开请求前置准入与 MySQL 完成确认修正 | [公开请求接入记录](state-request-integration-2026-10-21.md) |
| 已确认无状态变更的账号／最终预算拒绝与底层重放拒绝 | [预算拒绝接入记录](state-budget-integration-2026-10-21.md) |
| 当前完整范围、31 项验收目标和停止条件 | [R1—R6 有限周期执行计划](full-plan-2026-10-21.md) |
| 已交付的三天审查范围及停止条件 | [短期候选审查计划](short-term-plan-2026-10-20.md) |
| 五批审查结论、阻塞项和实际验证证据 | [短期候选审查报告](candidate-review-2026-10-20.md) |
| 幂等元数据读取超限修复与有限验收 | [2026-10-21 修复记录](idempotency-bounds-fix-2026-10-21.md) |
| 完整旧备份风险的入口、存储、恢复权限及验收契约 | [F01 防回滚工作单](auth-state-work-order-2026-10-21.md) |
| F01 共用状态校验的主 SDK 接入及有限验证 | [状态校验接入记录](state-codecs-integration-2026-10-21.md) |
| F01 独立见证、认证边界及隔离恢复的主 SDK 接入 | [边界接入记录](state-boundary-integration-2026-10-21.md) |
| 显式认证配置、准确服务缓存、纯策略工厂与诊断 | [认证工厂接入及有限验收](state-factory-integration-2026-10-21.md) |
| 授权提前拒绝、嵌套保护存储和混合服务图修复 | [入口修复及有限验收](state-entry-fix-2026-10-21.md) |
| 显式认证边界、未知结果及隔离恢复接口 | [使用说明](state-boundary.md)、[English](state-boundary.en.md) |
| 本地测试怎么运行、何时需要外部环境 | [WSL 环境说明](testing-environment-2026-10-21.md) |
| 发行前阻塞项、未覆盖范围及后续门禁 | [发行前置清单](release-preflight-2026-10-21.md) |
| 本地ClamAV扫描、超时拒绝和私有保存 | [扫描指南](upload-scanning.md)、[English](upload-scanning.en.md) |
| 持久上传隔离、后台重试和管理员处置 | [隔离指南](upload-quarantine.md)、[English](upload-quarantine.en.md) |
| 原生隔离网页、受保护索引与CLI工作进程 | [原生指南](upload-quarantine-native.md)、[English](upload-quarantine-native.en.md) |
| 可选ZIP归档路径与解压预算只读检查 | [ZIP检查](archive-inspection.md)、[English](archive-inspection.en.md) |
| 有界SQL／文件摘要与同次分页采集 | [只读快照](state-snapshots.md)、[English](state-snapshots.en.md) |
| 本轮 R1—R6 安全精修范围、实施及验收 | [安全精修跟踪](security-refinement.md) |
| 幂等、消息处理和事务发件箱的完整阶段验收 | [R4.3 验收清单](r43-acceptance.md) |
| 用通用规范指导 PHP 网站自查与 AI 检查修复 | [PHP 网站安全自查规范](php-website-security-checklist.md) |
| 项目要做什么、哪些不属于本次范围 | [产品需求](requirements.md) |
| 现在有哪些能力、演示在哪 | [功能清单](features.md)、[演示说明](demo.md) |
| 少量配置开始使用 | [配置与诊断](configuration.md)、[配置预设](../examples/configuration-presets.php) |
| 在 PSR-15 项目中接入请求预算 | [可选适配包与调用顺序](psr15.md) |
| 验证码类型、交互与第三方验证怎么接入 | [验证码指南](captcha.md)、[类型选择示例](../examples/captcha-types.php) |
| TOTP、恢复码、加密和密钥轮换 | [MFA 与加密](mfa.md)、[宿主接入示例](../examples/mfa-account.php) |
| 认证状态、身份源、共享会话撤销和重新认证 | [认证指南](authentication.md)、[完整示例](../examples/authentication.php)、[远程适配](../examples/identity-providers.php) |
| OIDC 外部身份与本地账号关联（阶段性，尚未提供完整登录） | [可选包边界](../integrations/oidc/README.md)、[R6.2 跟踪](security-refinement.md) |
| 记住登录、原子轮换、重放和设备撤销 | [持久登录指南](remembered-login.md)、[原生示例](../examples/authentication.php) |
| 注册、邮件所有权与双地址变更 | [当前核心接入](account-lifecycle.md)、[完整生命周期契约与进度](account-lifecycle-design.md) |
| 邮箱值、固定通知和用途绑定加密 | [通知基础](account-notifications.md)，完整账号流程见[设计与进度](account-lifecycle-design.md) |
| 密码策略、弱密码表、泄露筛查和成本校准 | [密码指南](passwords.md)、[CLI工具](../examples/password-calibrate.php)、[重置示例](../examples/password-reset.php) |
| 默认拒绝、角色／对象／字段／批量及租户授权 | [授权指南](authorization.md)、[SQL适配](../examples/authorization.php)、[原生接入](../examples/authentication.php) |
| 私有文件、内容版本、会话／签名授权与有界下载 | [下载指南](downloads.md)、[原生页面](../examples/authorized-download.php) |
| CSRF、限流、密码、会话、审计怎么调用 | [组件使用指南](usage.md) |
| 加权成本、令牌桶、滑动窗口、原子／多维预算 | [请求预算](request-budgets.md)、[宿主示例](../examples/request-budgets.php) |
| 并发名额、持有者、续期、崩溃恢复和旧任务隔离 | [并发租约](leases.md)、[SQL示例](../examples/leased-work.php) |
| 高风险动作、参数确认和单次授权 | [操作授权](operations.md)、[SQL事务示例](../examples/operation-work.php)、[原生页面](../examples/operation-authorization.php) |
| 签名链接、资源版本、到期／撤销和一次性策略 | [签名链接](signed-links.md)、[原生页面](../examples/signed-links.php) |
| 如何逐项替换旧代码，保留原业务 | [迁移指南](migration.md)、[独立登录示例](../examples/legacy-login.php) |
| 选择共享存储与维护状态 | [MySQL](mysql.md)、[Redis初始化/恢复](redis-recovery.md) |
| 严格输入验证与错误本地化 | [输入验证](validation.md) |
| 需要用户富文本 | [HTML清理](html-cleaning.md) |
| 无状态CSRF和Cookie双重提交 | [签名CSRF](signed-csrf.md) |
| 上传文件和文件管理器适配 | [上传安全](upload.md) |
| CORS/跳转/权限头、外部URL访问 | [HTTP策略](http-policy.md)、[受限请求](outbound.md) |
| 反向代理可信链、回源、TLS和WAF接入 | [代理与WAF指南](reverse-proxy-waf.md)、[English](reverse-proxy-waf.en.md) |
| API Key、HMAC和重放保护 | [API指南](api.md) |
| 写接口幂等、同事务结果重放与过期墓碑 | [SQL幂等](idempotency.md)、[原生接入](idempotency-native.md)、[页面](../examples/idempotency.php)，R4.3实施中 |
| Webhook持久处理、重试与恢复 | [处理指南](webhook-processing.md)、[独立CLI](../examples/webhook-worker.php)，R4.3实施中 |
| 事务发件箱、领取确认、顺序与恢复 | [Outbox核心候选](outbox.md)、[原生生产／发送／接收方去重](outbox-native.md)、[接收检查点与恢复](outbox-recovery.md)、[超期对账核心](outbox-reconciliation.md)、[审计归档与轮换](outbox-audit-archive.md)、[独立权限源与恢复](outbox-authority.md)，完整阶段继续 |
| SQL事务所有权、加入宿主事务及出站一致性边界 | [内部事务说明](sql-transactions.md)，完整Outbox继续实施 |
| Webhook原始请求验签与持久接收方案 | [协议与实现状态](webhooks.md)、[原生投递与管理](../examples/webhooks.php)，R4.2实施中 |
| 账号级API凭据、服务账号委派、轮换／撤销 | [生命周期指南](api-credentials.md)、[原生页面](../examples/api-credentials.php) |
| 为什么这样设计、保护边界是什么 | [架构决策](architecture.md)、[威胁模型](threat-model.md)、[平台范围](platforms.md) |
| 当前完成状态与后续安排 | [当前状态](execution-status.md)、[总体规划](roadmap.md)、[近期工作](next-steps.md) |
| 如何验证、贡献与报告漏洞 | [验证记录](verification.md)、[贡献指南](../CONTRIBUTING.md)、[安全政策](../SECURITY.md) |
| 私密漏洞处置、独立审查与安全发布 | [漏洞响应与发布门禁](security-response.md)、[English](security-response.en.md)、[发行候选工作单](release-readiness.md) |
| 核心、可选包和开发工具的依赖来源与锁定边界 | [依赖与来源清单](dependency-inventory.md) |
| 昂贵解析、外连、扫描及私有状态的资源与隔离边界 | [昂贵操作与危险功能清单](resource-risk-inventory.md) |
| 公开API与发布验收 | [API提案](public-api.md)、[发布工作单](release-readiness.md)、[变更日志](../CHANGELOG.md) |

示例只使用测试数据和显式部署配置。先验证独立示例，再由宿主选择实际接入点；本库不会扫描并改写其他项目。

密码学维护参考：[用途清单、密钥生命周期与算法迁移](cryptography.md)。

R2.7 的[账号生命周期实现契约](account-lifecycle-design.md)仍记录未完成的流程；四个已纳入SDK的基础类另有[使用说明](account-notifications.md)，不能据此认定完整注册／变更／恢复已交付。

- [密码恢复核心、一次性恢复码与强审批](account-recovery.md)：当前邮箱证明下的改密、MFA保留及提交边界；不代替完整恢复编排。

- [旧邮箱丢失后的强审批地址恢复](account-mailbox-recovery.md)：新邮箱证明与独立强审批，保留密码／MFA及明确提交边界；因子替换和完整恢复运维继续。

- [受管理 MFA 接入](account-factors.md)：显式工厂、登记权威、准确迁移、操作／绑定、历史维护及当前未完成边界；[原生登录样例](managed-authentication-native.md)展示受保护 POST 与本地浏览器验收。
