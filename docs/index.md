# 文档导航

初次使用先看README和配置，按实际需要选组件；需求、计划与验证记录分别描述目标、实施安排和已执行证据。

| 要解决的问题 | 入口 |
| --- | --- |
| 用通用规范指导 PHP 网站自查与 AI 检查修复 | [PHP 网站安全自查规范](php-website-security-checklist.md) |
| 项目要做什么、哪些不属于本次范围 | [产品需求](requirements.md) |
| 现在有哪些能力、演示在哪 | [功能清单](features.md)、[演示说明](demo.md) |
| 少量配置开始使用 | [配置与诊断](configuration.md)、[配置预设](../examples/configuration-presets.php) |
| 验证码类型、交互与第三方验证怎么接入 | [验证码指南](captcha.md)、[类型选择示例](../examples/captcha-types.php) |
| CSRF、限流、密码、会话、审计怎么调用 | [组件使用指南](usage.md) |
| 如何逐项替换旧代码，保留原业务 | [迁移指南](migration.md)、[独立登录示例](../examples/legacy-login.php) |
| 选择共享存储与维护状态 | [MySQL](mysql.md)、[Redis初始化/恢复](redis-recovery.md) |
| 严格输入验证与错误本地化 | [输入验证](validation.md) |
| 需要用户富文本 | [HTML清理](html-cleaning.md) |
| 无状态CSRF和Cookie双重提交 | [签名CSRF](signed-csrf.md) |
| 上传文件和文件管理器适配 | [上传安全](upload.md) |
| CORS/跳转/权限头、外部URL访问 | [HTTP策略](http-policy.md)、[受限请求](outbound.md) |
| API Key、HMAC和重放保护 | [API指南](api.md) |
| 为什么这样设计、保护边界是什么 | [架构决策](architecture.md)、[威胁模型](threat-model.md)、[平台范围](platforms.md) |
| 当前完成状态与后续安排 | [当前状态](execution-status.md)、[总体规划](roadmap.md)、[近期工作](next-steps.md) |
| 如何验证、贡献与报告漏洞 | [验证记录](verification.md)、[贡献指南](../CONTRIBUTING.md)、[安全政策](../SECURITY.md) |
| 公开API与发布验收 | [API提案](public-api.md)、[发布工作单](release-readiness.md)、[变更日志](../CHANGELOG.md) |

示例只使用测试数据和显式部署配置。先验证独立示例，再由宿主选择实际接入点；本库不会扫描并改写其他项目。
