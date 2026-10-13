# 功能与需求覆盖

以2026-10-13重新确认的产品需求为准。下表描述代码中的能力；实际服务、系统和生产验证范围分别见verification.md。当前为未发布候选，不宣称独立安全审计通过。

| 需求 | 现有实现与边界 | 演示 | 示例/指南 |
| --- | --- | --- | --- |
| CAPTCHA | 算术、PNG图片及Turnstile；过期/错误次数/单次消费/场景绑定；真实Turnstile未配置时未执行 | [验证码](http://72.rocky.wsl/SoSecurity/?module=captcha) | [usage](usage.md)、[原生登录](../examples/legacy-login.php) |
| CSRF | 有状态多令牌、可选单次消费；绑定已验证登录的签名双重提交；精确路由策略由宿主应用 | [有状态](http://72.rocky.wsl/SoSecurity/?module=csrf)、[无状态](http://72.rocky.wsl/SoSecurity/?module=stateless) | [签名方案](signed-csrf.md)、[独立表单](../examples/signed-form.php) |
| 限流/自动封禁 | 任意IP/账号/组合/路由标识，固定窗口、阶梯/人工封禁、inspect/reset及Retry-After；无系统防火墙或独立AutoBan | [限流与封禁](http://72.rocky.wsl/SoSecurity/?module=rate) | [usage](usage.md)、[登录配置](configuration.md) |
| Session | 显式更新ID、空闲/绝对期限、失效和Cookie；宿主仍管理启动、身份和注销 | [会话](http://72.rocky.wsl/SoSecurity/?module=session) | [迁移](migration.md) |
| 密码 | bcrypt/可用时Argon2id、验证/参数升级、可信旧哈希回调、策略/泄露检查回调及一次性重置 | [密码](http://72.rocky.wsl/SoSecurity/?module=password)、[重置](http://72.rocky.wsl/SoSecurity/?module=reset) | [SQL版本比较示例](../examples/password-reset.php) |
| HTTP | CSP/Report-Only、显式HSTS、点击劫持/嗅探/Referrer/Permissions策略、CORS、代理与Cookie | [HTTP与代理](http://72.rocky.wsl/SoSecurity/?module=http)、[跨域与目标](http://72.rocky.wsl/SoSecurity/?module=network) | [HTTP策略](http-policy.md) |
| XSS输出与清理 | HTML/普通带引号属性、JSON数据和URL组件编码；HTML Purifier固定基础正文允许列表；不提供万能输入清洗 | [输出](http://72.rocky.wsl/SoSecurity/?module=output)、[HTML清理](http://72.rocky.wsl/SoSecurity/?module=html) | [富文本示例](../examples/rich-text.php)、[清理边界](html-cleaning.md) |
| 输入验证 | 严格类型/范围/格式/Unicode/嵌套结构、白名单、自定义规则和可本地化错误；不替代业务授权 | [输入验证](http://72.rocky.wsl/SoSecurity/?module=validation) | [验证示例](../examples/input-validation.php)、[指南](validation.md) |
| 上传 | 内容/MIME/扩展/大小/像素预算、图片重新编码、私有随机保存、扫描/文件管理器接口；无真实扫描服务证明 | [上传](http://72.rocky.wsl/SoSecurity/?module=upload) | [适配示例](../examples/upload-adapter.php)、[指南](upload.md) |
| URL/SSRF | 固定主机/端口、公开地址检查、DNS/实际连接pin/逐跳重验证、响应/时间预算；自定义适配需满足契约 | [受限请求](http://72.rocky.wsl/SoSecurity/?module=network) | [请求示例](../examples/outbound.php)、[指南](outbound.md) |
| API | 随机Bearer摘要存储及范围/轮换/撤销、RFC9421有界HMAC配置档、时间戳/原子Nonce；不提供OAuth平台 | [API](http://72.rocky.wsl/SoSecurity/?module=api) | [请求示例](../examples/api-request.php)、[指南](api.md) |
| 审计/诊断 | 结构化事件、字段白名单、主体假名化、回调Sink及只读配置诊断；日志持久化/全站查询接宿主日志系统，演示可看近期事件 | [审计](http://72.rocky.wsl/SoSecurity/?module=audit)、[配置](http://72.rocky.wsl/SoSecurity/?module=configuration) | [usage](usage.md)、[配置诊断](configuration.md) |

封禁查询按已知scope/subject调用inspect；没有全站任意记录扫描或独立管理平台。验证码与限流按宿主业务联动；算术验证码不承诺抵抗自动化。签名无状态CSRF在有效期内可重用，逐令牌撤销/单次使用继续采用原子有状态方案。

存储共用AtomicStore契约：Session用于当前会话挑战，文件用于满足私有权限的本地主机，Redis/MySQL用于经过配置的共享状态。失败抛异常并拒绝敏感操作，MemoryStore只用于测试；命名空间不能替代物理访问隔离。

TOTP/MFA、恢复码、签名URL、蜜罐、可信设备及自动风险平台仍是可选后续。没有真实业务需求前不继续扩张；也不把这些可选能力列为当前基础版本失败。
