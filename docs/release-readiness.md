# 1.0 发布验收工作单

当前基线为未发布候选，核心实现推进至HTTP/API、无状态CSRF和可选HTML清理。本单对应原始产品需求及next-steps.md，确认功能、证据和实际接入后才能冻结/发布；不把已有阶段可用当作完整目标完成。

| 要求 | 现有来源/可检查证据 | 当前验收动作 |
| --- | --- | --- |
| CAPTCHA/场景/刷新/错误次数/一次消费/表单与AJAX | Captcha/Turnstile/ImageRenderer、run.php、demo/captcha、legacy-login.php | 九版本矩阵通过；真实第三方服务未配置时保持未执行；风险由宿主限流结果选择 |
| 有状态/无状态CSRF、期限/范围/多标签/必要重放/路由豁免 | CsrfTokens/SignedTokens/RequestPolicy、session.php、signed-csrf.php及HTTP/TLS/浏览器、signed-form.php | 九版本矩阵通过；真实宿主Session/JTI与路由、Twig自动转义；单次要求使用原子方案 |
| 限流/阶梯/人工封禁/检查与解除/IP规则/并发 | RateLimiter/Policy/Decision、IpRules/ClientIp、真实三驱动及24进程 | 九版本及三驱动并发通过；真实宿主IP/账号/路由组合与入口预算；不自建防火墙 |
| Session/登录提升ID/期限/Cookie/失效与宿主保留 | SessionSecurity、Cookie、session.php/旧登录HTTP | 原生/FPM/HTTPS与真实宿主生命周期，不能接管现有SSO |
| 密码/升级/旧hash/策略/重置一次性 | PasswordHasher/Policy/ResetTokens、SQL版本示例/并发 | 九版本通过，算法可用/不可用分开；真实旧站业务；泄露检查可用可信回调，不默认调用外部服务 |
| HTTP头/CORS/跳转/代理/SSRF | SecurityHeaders/Cors/Redirects/Uri/Outbound、native_outbound.py及浏览器 | 九版本实际cURL、DNS/TLS/IP/预算通过；真实拓扑另审查 |
| 输出/Unicode/严格输入与富文本 | Escaper/Validator、validation.php、HtmlCleaner及实际浏览器 | 九版本通过；普通转义与清理上下文、可选依赖/缺扩展；不批量覆写旧HTML |
| 上传/内容/路径/私有保存/图片及适配 | Upload组件、multipart/并发/部分写/ENOSPC、Scanner接口 | 九版本通过，仍需更多GD差异；真实扫描服务按需配置，不能把未接扫描当无恶意证明 |
| API Key/范围/轮换撤销/HMAC/Nonce/认证区别 | Api模块、独立Python/HTTP/三驱动并发 | 九版本通过；真实密钥/身份/恢复边界；不替代OAuth平台 |
| 日志事件/脱敏/自定义Sink/查看与诊断 | AuditLogger、demo近期事件、Inspector/CLI | 宿主日志设施查询/保留；不让任意敏感对象进入日志；不误报自定义服务已审查 |
| 框架无关Composer、PHP7.2–8.5及可选依赖 | manifest/新消费者/core/可选HTML安装/归档 | 九版本实际完整检查已通过；扩展缺失与驱动差异；公开包安装待授权发布 |
| 旧站少改动、不重构/不强制认证/数据库/路由 | migration.md、旧登录/重置示例 | CoreRepo独立工作区真实组件及测试身份试点通过；原后台完整业务仍待验收，现有改动保持原样 |
| 文档/威胁/限制/贡献/变更/漏洞政策/许可证 | README中英、各功能指南、architecture、SECURITY、CONTRIBUTING、CHANGELOG、LICENSE | 同步当前能力与验收，不能声称未执行平台/独立审计 |
| API冻结/独立复核/发布流程 | public-api.md、候选签名清单 | 独立复核未完成，最终API/默认值与回归冻结；发布需要具体结果批准 |

## 当前环境与待办

本机原有六个CLI加新增PHP7.3.33、8.0.30、8.3.35，共覆盖九个目标版本。新增为Remi并行CLI及所需测试扩展，未安装FPM，原PHP7.2/8.5二进制哈希验证相同，实际演示仍为PHP7.2.34。三新增版本功能、实际命名空间TLS/DoH、消费者/可选HTML安装与小型tmpfs ENOSPC已通过；九版本完整Redis/MySQL/HTTP矩阵已完成，原CLI缺扩展通过临时测试ini补齐且不修改FPM配置，最新证据以verification.md为准。

全版本矩阵可以共享一个新建无TCP私有MySQL实例并顺序运行，避免重复初始化；每个套件仍运行schema/事务/故障/并发，不连接宿主或演示数据库。安全隔离包含独立测试目录、Session、UNIX socket、网络命名空间和测试CA；不能把不同CLI路径当作主机级沙箱。Windows原生7.2.34/8.5.11各472项组件及新Composer消费者已通过；FileStore/上传保存因无法证明POSIX私有权限明确拒绝，不支持原生Windows，其他Windows共享驱动/网络/部署未执行。平台状态及复现见platforms.md。

独立复核方式已询问；没有明确允许子代理前不创建它。旧站先按CoreRepo已提交基线的独立工作区完成组件试点，PHP7.2/7.4各33项真实HTTP通过；实际原后台/SSO/数据库业务仍未执行，见core-repo-pilot.md。用户未回复不代表授权。与此同时继续完成环境、矩阵、文档、API及可审查发布材料。专业第三方审计与独立代码复核仍分别记录，不用测试或作者自检代替。

高级TOTP/恢复码/可信设备/风险策略平台、持久化日志查询平台、完整富文本编辑器/媒体/CDR等保留原路线中的可选后续，不纳入“为了功能数量无限扩展”。必要安全场景与完整1.0验收仍须满足。
