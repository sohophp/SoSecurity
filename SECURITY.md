# 安全政策 / Security policy

当前为未发布开发候选版本，还没有稳定维护分支。正式版本发布后，维护范围、修复版本和迁移路径将在这里及CHANGELOG更新。PHP兼容性与PHP上游安全支持是不同事项。

请勿在公开Issue中粘贴可利用细节、真实账号、凭证、Session ID或敏感数据。优先使用仓库可用的[GitHub私密漏洞报告](https://github.com/sohophp/SoSecurity/security/advisories)；如果仓库尚未启用该入口，先通过不含漏洞细节的Issue请求维护者建立私密沟通渠道。项目不会承诺当前并不存在的邮件地址或响应SLA。

私密报告应包含受影响版本/提交、PHP版本、存储后端、可复现的最小测试样例、预期与实际行为、影响范围及可选修复建议；不要附生产秘密。维护者确认影响后，提供修复、回归测试和迁移说明，协调披露时间。安全敏感默认行为变化会明确记录，不静默放宽策略。

测试通过不意味着完成独立安全审计。当前边界参见[威胁模型](docs/threat-model.md)和[验证记录](docs/verification.md)。

Do not disclose exploitable details or credentials in public issues. Use GitHub private reporting if enabled, or request a private channel without including vulnerability details. Provide a minimal reproducible example, affected commit/runtime/backend and impact. No response-time SLA is currently promised.
