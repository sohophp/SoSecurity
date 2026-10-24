# 功能与需求覆盖

以2026-10-13重新确认的产品需求为准。下表描述代码中的能力；实际服务、系统和生产验证范围分别见verification.md。当前为未发布候选，不宣称独立安全审计通过。

| 需求 | 现有实现与边界 | 演示 | 示例/指南 |
| --- | --- | --- | --- |
| CAPTCHA | 加减乘除/图片算术、字符/数字/字母PNG、滑块/顺序点选、Turnstile/hCaptcha/reCAPTCHA v2/v3；过期/错误次数/单次消费/场景绑定；真实第三方未配置时未执行 | [验证码](http://72.rocky.wsl/SoSecurity/?module=captcha) | [验证码指南](captcha.md)、[原生登录](../examples/legacy-login.php) |
| CSRF | 有状态多令牌、可选单次消费；绑定已验证登录的签名双重提交；精确路由策略由宿主应用 | [有状态](http://72.rocky.wsl/SoSecurity/?module=csrf)、[无状态](http://72.rocky.wsl/SoSecurity/?module=stateless) | [签名方案](signed-csrf.md)、[独立表单](../examples/signed-form.php) |
| 限流/自动封禁 | 任意IP/账号/组合/路由标识，固定窗口、阶梯/人工封禁、inspect/reset及Retry-After；无系统防火墙或独立AutoBan | [限流与封禁](http://72.rocky.wsl/SoSecurity/?module=rate) | [usage](usage.md)、[登录配置](configuration.md) |
| 加权请求预算 | 整数成本、令牌桶／固定／精确秒级滑动窗口、同主体原子组、跨主体有序预占；拒绝不退款 | [预算演示](http://72.rocky.wsl/SoSecurity/?module=budgets)，仅当前访客测试计数 | [指南](request-budgets.md)、[宿主示例](../examples/request-budgets.php) |
| 并发租约 | 显式账本／永久序号、持有者／期限／有界续期、单键并发名额及SQL业务隔离 | [租约演示](http://72.rocky.wsl/SoSecurity/?module=leases)，仅访客Session | [指南](leases.md)、[SQL示例](../examples/leased-work.php) |
| Session | 显式更新ID、空闲/绝对期限、失效和Cookie；宿主仍管理启动、身份和注销 | [会话](http://72.rocky.wsl/SoSecurity/?module=session) | [迁移](migration.md) |
| 认证／共享会话 | 明确认证状态、凭据／角色／因子版本检查、单会话／全部撤销、重新认证和绝对期限；身份源及请求保护显式注入 | [认证与撤销](http://72.rocky.wsl/SoSecurity/?module=auth) | [指南](authentication.md)、[完整接入](../examples/authentication.php) |
| 业务授权 | 当前身份前后复核、角色／归属／属性、字段白名单、整批预检、默认拒绝及明确租户边界 | 原生示例显式配置私有文档库；常驻演示未配置该数据库 | [指南](authorization.md)、[SQL适配](../examples/authorization.php) |
| 高风险操作授权 | 准备后新近认证、明确确认、动作／资源版本／参数／会话绑定、原子单次消费；SQL唯一执行记录及原始／有效身份版本约束 | 独立原生页面本地验收通过，常驻入口未配置私有数据库／MFA密钥 | [指南](operations.md)、[原生页面](../examples/operation-authorization.php)、[SQL事务](../examples/operation-work.php) |
| 签名链接 | 固定来源／全查询／方法／用途／资源版本绑定、固定期限、共享撤销／查询、可选绑定及原子单次消费 | 独立原生页面本地验收通过，常驻入口未配置私有SQL／密钥 | [指南](signed-links.md)、[原生页面](../examples/signed-links.php) |
| 授权下载 | 当前会话／签名授权、完整摘要绑定的私有匿名快照、读取前后权限复核、单Range／附件头及全源成本／并发组合 | 独立原生HTTP／真实TLS及浏览器本地验收通过；常驻入口未配置私有文件索引与账本 | [指南](downloads.md)、[原生页面](../examples/authorized-download.php) |
| 记住登录 | 显式选择、固定期限、原子轮换与重放撤销、设备查询／忘记、敏感操作重新认证 | 独立原生示例按需配置密钥 | [指南](remembered-login.md)、[完整接入](../examples/authentication.php) |
| 注册／双地址变更核心 | 待验证申请、所有者设密、旧／新邮箱证明、真实会话／操作授权、同库条件更新、清理／轮换 | 注册、双地址、当前邮箱恢复、工厂、正式预算及SMTP工作端已接入；原生HTTP和邮箱丢失恢复继续 | [核心接入](account-lifecycle.md)、[完整契约与证据](account-lifecycle-design.md) |
| 邮箱丢失恢复核心 | 新邮箱证明＋独立强审批、私有审批预览、密码／MFA保留及版本推进、双地址安全通知 | 已接入SDK并通过主工作区专项；因子替换、恢复运维及原生HTTP继续 | [指南](account-mailbox-recovery.md) |
| 邮箱／通知基础 | 有界邮箱、固定通知类型、用途／作用域／编号绑定的认证加密、期限与密钥轮换；需要 sodium | 通知值、当前租约投递、固定模板、有界SMTP和显式CLI已接入；实际本地接收通过，真实收件箱与完整账号流程继续 | [使用说明](account-notifications.md)、[生命周期契约](account-lifecycle-design.md) |
| 密码精修 | 算法匹配、有界全串弱密码表、可选HIBP前缀查询、校准与成本不降级 | 密码页离线策略；校准只用CLI | [指南](passwords.md)、[校准](../examples/password-calibrate.php) |
| TOTP／恢复码／加密 | 新增绑定确认、时间步防重放、共享错误预算、恢复码消费／轮换、因子撤销和密钥重加密；需要 sodium 和共享存储 | [MFA](http://72.rocky.wsl/SoSecurity/?module=mfa)，缺少扩展时明确未执行；受管理登录的原生样例已在本地HTTP／Chromium验证，目标宿主未验收 | [指南](mfa.md)、[受管理接入](account-factors.md)、[原生登录](managed-authentication-native.md) |
| 密码 | bcrypt/可用时Argon2id、验证/参数升级、可信旧哈希回调、策略/泄露检查回调及一次性重置 | [密码](http://72.rocky.wsl/SoSecurity/?module=password)、[重置](http://72.rocky.wsl/SoSecurity/?module=reset) | [SQL版本比较示例](../examples/password-reset.php) |
| HTTP | CSP/Report-Only、显式HSTS、点击劫持/嗅探/Referrer/Permissions策略、CORS、代理与Cookie | [HTTP与代理](http://72.rocky.wsl/SoSecurity/?module=http)、[跨域与目标](http://72.rocky.wsl/SoSecurity/?module=network) | [HTTP策略](http-policy.md) |
| XSS输出与清理 | HTML/普通带引号属性、JSON数据和URL组件编码；HTML Purifier固定基础正文允许列表；不提供万能输入清洗 | [输出](http://72.rocky.wsl/SoSecurity/?module=output)、[HTML清理](http://72.rocky.wsl/SoSecurity/?module=html) | [富文本示例](../examples/rich-text.php)、[清理边界](html-cleaning.md) |
| 输入验证 | 严格类型/范围/格式/Unicode/嵌套结构、白名单、自定义规则和可本地化错误；不替代业务授权 | [输入验证](http://72.rocky.wsl/SoSecurity/?module=validation) | [验证示例](../examples/input-validation.php)、[指南](validation.md) |
| 上传 | 内容/MIME/扩展/大小/像素预算、图片重新编码、私有随机保存、扫描/文件管理器接口；本地ClamAV同步适配及持久隔离核心已接入，支持后台重试、重扫／拒绝及当前版本内容读取；可选ZIP归档只读检查限制路径、条目和解压预算，不自动解压；生产病毒覆盖及真实宿主归档流程未验收 | [上传](http://72.rocky.wsl/SoSecurity/?module=upload)，演示不自动联系扫描服务 | [适配示例](../examples/upload-adapter.php)、[指南](upload.md)、[扫描接入](upload-scanning.md)、[持久隔离](upload-quarantine.md)、[原生接入](upload-quarantine-native.md)、[ZIP检查](archive-inspection.md) |
| URL/SSRF | 固定主机/端口、公开地址检查、DNS/实际连接pin/逐跳重验证、响应/时间预算；自定义适配需满足契约 | [受限请求](http://72.rocky.wsl/SoSecurity/?module=network) | [请求示例](../examples/outbound.php)、[指南](outbound.md) |
| API | 随机Bearer摘要存储及范围/轮换/撤销、RFC9421有界HMAC配置档、时间戳/原子Nonce；不提供OAuth平台 | [API](http://72.rocky.wsl/SoSecurity/?module=api) | [请求示例](../examples/api-request.php)、[指南](api.md) |
| 账号API凭据 | 真实会话／近期认证、显式服务账号委派、命名／范围／期限、代际轮换替换、单项／全部撤销及当前身份复核 | 独立原生HTTP／TLS／浏览器本地验收通过；常驻入口与生产未接入 | [生命周期](api-credentials.md)、[原生页面](../examples/api-credentials.php) |
| Webhook | 固定协议验签与独立封存持久接收；显式处理工厂、独立CLI、同事务业务幂等及强认证失败重试 | 共享事务保护九版基线通过；工厂九版专项、两版最终TLS／CLI／移动浏览器通过，新接入九版专项通过；常驻未接入 | [接收](webhooks.md)、[处理与恢复](webhook-processing.md)、[原生页面](../examples/webhooks.php) |
| 通用写接口幂等 | 同PDO业务／结果提交、当前权限重放、内容冲突拒绝、到期键墓碑及有界维护；显式工厂与诊断 | 最新九版SQLite409／MySQL356、HTTP／TLS各433、API和新消费者专项通过，含24进程／SIGKILL、丢失确认重启及两版TLS移动浏览器；出站消息与完整R4.3继续 | [SQL幂等](idempotency.md) |
| 事务发件箱 | 同事务入队、稳定身份、领取／确认、顺序、有限重试／维护；原生CLI、独立接收账本／检查点及超期处置核心 | 九版对账SQLite274／MySQL268及两后端并发31通过；格式2需停旧进程，公开候选仅追加2方法。接收／原生历史证据、预算调整及最终复验分阶段记录；原生预算后九版适配66／恢复342／TLS318通过；签名证据、取消栅栏、封存审计与 CLI 已实现，本轮专项已通过；完整R4.3继续 | [核心](outbox.md)、[原生接入](outbox-native.md)、[接收恢复](outbox-recovery.md)、[超期对账](outbox-reconciliation.md)、[审计归档与轮换](outbox-audit-archive.md)、[独立权限源](outbox-authority.md) |
| 审计/诊断 | 结构化事件、字段白名单、最多1024字节主体假名化、可选共享事件预算、四类固定标签计数与可轮询告警判定、可选PSR-3适配及配置诊断；可选独立 SQL 持久日志、有界历史查询与独立受权清理；外部告警和全站查询接宿主系统 | [审计](http://72.rocky.wsl/SoSecurity/?module=audit)、[配置](http://72.rocky.wsl/SoSecurity/?module=configuration) | [接入](audit-budget.md)、[SQL日志](audit-sql.md)、[配置诊断](configuration.md) |

封禁查询按已知scope/subject调用inspect；没有全站任意记录扫描或独立管理平台。验证码与限流按宿主业务联动；算术验证码不承诺抵抗自动化。签名无状态CSRF在有效期内可重用，逐令牌撤销/单次使用继续采用原子有状态方案。

存储共用AtomicStore契约：Session用于当前会话挑战，文件用于满足私有权限的本地主机，Redis/MySQL用于经过配置的共享状态。失败抛异常并拒绝敏感操作，MemoryStore只用于测试；命名空间不能替代物理访问隔离。

2026-10-17：用户已确认完整精修路线。R2.1—R2.6身份／MFA／会话及密码、R3.1—R3.6授权／预算／租约／高风险操作／签名链接／授权下载已有本地验收；R4.1账号API凭据也已本地验收；R1复核、R2.7账号生命周期、R4.2—R4.6、R5—R6继续按[逐项跟踪](security-refinement.md)实施，不把已完成子集描述为完整路线已完成。
