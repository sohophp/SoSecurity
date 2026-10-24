# 当前会话修复后的 OIDC／WebAuthn 消费者复核

针对 [SessionRegistry 返回身份与期限修复](session-current-authority-2026-10-23.md)，对当前核心及适配器重新归档、离线安装到全新非软链接消费者，逐个运行时检查 vendor 来源并核对所有运行时 PHP 文件摘要。没有修改适配器源码或放宽依赖。

- OIDC 声明支持的 PHP7.2—8.3 七版：122/122步骤通过，锁定 jumbojett/openid-connect-php v1.0.2。
- WebAuthn 声明支持的 PHP8.2—8.5 四版：147/147步骤通过，锁定 web-auth/webauthn-lib 5.3.9；包含设备当前权限／宿主绑定／期限检查和四版私有MySQL设备组，共28个MySQL设备场景。

[证据目录](session-optional-evidence-2026-10-23/)保存逐项命令、退出码、日志、依赖版本及运行时摘要；结束时均与当前源码匹配。执行器为 `tests/optional_nondeferred_consumer.py`，使用此前审核的明确非暂缓清单，没有执行可选包完整恢复套件。

本结果不包含真实IdP、实体认证设备、目标宿主、远端CI或新的依赖公告查询。OIDC原有精确锁定告警仍保留，未放宽依赖。默认MySQL原生签发预算、PHP7.2原生流程时钟倒退及其他候选缺口仍开放，goal保持active。
