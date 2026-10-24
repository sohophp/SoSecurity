# 可选包与当前核心独立消费者核对（2026-10-23）

## 验收入口修正

原可选包消费者脚本使用path软链接，部分测试还先加载工作区tests/bootstrap.php，再加载传入的消费者autoload，不能直接据此证明每个核心类型来自实际安装目录。

新增tests/optional_nondeferred_consumer.py：核心和适配器均从Composer ZIP归档安装，path仓库禁用软链接；测试复制到消费者目录，不复制工作区运行时src；每个PHP测试进程预加载消费者autoload，并反射检查核心及适配器代表类来自vendor。安装后逐份比较全部核心和适配器PHP源码SHA-256，输出实际锁定依赖清单。Composer使用离线模式，无插件、无脚本。

此入口显式列出非暂缓场景，不替代原全量消费者脚本。WebAuthn的repository全套包含恢复后的重新注册，因此本次不调用该套及recovery／recovery-race／migration，也没有删除这些测试。私有MySQL新增--webauthn-devices，只运行原有七个普通设备删除权限／故障场景，不进入恢复套件。OIDC普通MFA恢复码是登录证明，不是最终账号恢复启用；失联解绑只撤销关联，不激活账号。

## 实际结果与失败保留

| 检查 | 已执行结果 |
| --- | --- |
| OIDC PHP7.2、7.3、7.4、8.0、8.1、8.2、8.3 | 122/122步骤通过。实际锁定jumbojett/openid-connect-php v1.0.2，不宣称支持8.4／8.5。需要sodium的版本使用既有包装器。 |
| WebAuthn PHP8.2、8.3、8.4、8.5 | 第一份完整非暂缓消费者记录103步骤，99通过／4失败。四项均为authority-time旧断言与当前核心拒绝方式不符，其余检查包括私有MySQL七场景每版通过，共28个MySQL场景。锁定web-auth/webauthn-lib 5.3.9。 |
| WebAuthn纠正时钟断言后的专项消费者 | 11/11步骤通过，含四版authority-time及依赖清单。与前批全部运行时源码摘要完全相同，不重跑未受影响的已通过场景。 |

旧断言在csrf_verify_backwards场景只期待false；当前CsrfTokens已明确抛出StorageException，原因csrf.clock。原运行时保护正确，不应为了测试改变它。本次仅更新测试，严格验证原因码、无previous、证明已消费、后续before／current／return不能授权；没有恢复证明或接受时钟倒退。四版旧失败日志仍保留，不把103步骤历史记录改成全绿。

首次驱动还因临时Composer项目未设置name而在依赖清单生成失败；已补项目名称并另存后续结果，原失败保留在两个证据根目录。所有测试自建消费者目录、数据库实例均已结束并清理，Python入口及PHP8.2测试语法检查通过。没有改动产品运行时源码或公开API，因此不重复无变化的全仓静态/API检查。

## 范围与剩余关口

本轮覆盖普通挑战、输入预算、持久化拒绝、设备删除／通知故障、会话近期认证、OIDC声明／登出栅栏／绑定／批量撤销／签名回调及MFA登录；具体逐项命令见result.json。不是完整可选包、浏览器、实体设备、真实IdP或全项目验收。没有执行恢复激活、跨安全代际交接、未知结果续办或外部投递。

实际安装依赖清单已生成，外部安全公告审计未执行，OIDC精确锁定的历史严格告警未被放宽或关闭。默认MySQL凭据预算、PHP7.2不稳定失败及整体非暂缓候选核对仍开放，goal保持active。未提交、推送或部署。

## 证据

[本轮汇总](optional-current-evidence-2026-10-23/summary.json)、[OIDC当前消费者](optional-current-oidc-evidence-2026-10-23/final/result.json)、[WebAuthn四版初次结果](optional-current-webauthn-evidence-2026-10-23/final/result.json)、[时钟断言修正后](optional-current-webauthn-evidence-2026-10-23/timing/result.json)。每个结果文件含锁定版本、全部运行时摘要、命令、退出码和独立日志名称。
