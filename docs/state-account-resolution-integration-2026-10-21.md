# G4 账号禁用未知结果的独立续办

日期：2026-10-21（Asia/Shanghai）。继续原 P1／G4，不新增阶段、需求或预算。本组修复账号固定禁用事务在提交前后丢失确认、导致隔离恢复无法继续的缺口；它是最终恢复的必要步骤，不能作为重新开放业务或完整 R1—R6 的验收。

## 原始效果先登记

`containAccounts()` 在消耗批准和发布 pending 前采集准确来源，并生成有界行摘要清单；清单随 pending 稳定写入后才允许 SQL 效果。每份最多八个准确账号，绑定来源、SQL 声明、固定计划、原操作随机号和审阅的完整来源摘要，每行只保存变更前／固定禁用后的 SHA-256。密码、邮箱和角色正文不进入清单。行摘要将字符串按原始字节编码，再与整数／NULL 类型一同计算，不依赖 UTF-8 编码成功。

固定禁用效果保持：密码置 NULL、状态 disabled、去除角色及已验证标志、要求 MFA，并按原操作产生新凭据／地址版本。禁止触发器、外键依赖和无法证明元数据可见性的连接，使用准确行比较后更新（CAS）；不支持任意 SQL、任意回调或启用账号。

## 重新审批续办

新增 `StateAccountResolution`、`StateAccountResolutionReview`、`LocalStateWitness::accountResolutionReview()`／`resolveAccounts()`，以及控制器的 `beginAccountResolution()`／`confirmAccountResolution()`。新批准使用独立的 `state.accounts.resolve` 动作、`resolve_accounts` 用途和 `SoSecurity.Account.StateAccountResolutionReview.1` 签名域。宿主须显式配置 `state_authority` 资源、恢复管理员角色及准确字段；字段与现有账号禁用审阅相同。

续办只能从格式 3、quarantined、账号处置 pending 且具有事先封存清单的准确根开始。通过新的独立当前密码／MFA／会话检查、审阅后重新认证和参数绑定的一次性批准后，再持久化本次续办 pending，才允许固定 SQL。原批准、不同清单、不同账号集合或普通业务会话均不授予该能力。

重启时从 `inspect()` 读取已封存清单，以相同来源／账号声明重建 `StateAccountContainment`，再构造 `StateAccountResolution($next, $accounts, $root['remediation']['manifest'])`。观察值只接受各行原 before 或准确 after；未知字节、额外修改和重新计算的伪造清单均拒绝。已完成行不重复更新，未完成行收敛到原来登记的禁用结果，沿用原操作的版本号。每次续办绑定当前完整根、来源观察值、序号、期限和新尝试号；再次未知时必须重新审阅和批准。

续办完成只将 remediation.phase 改为 complete；原可信 digest、隔离代际、原意图和继任回执保持，记录本次审批及完成来源摘要。最终回执已写入但确认丢失时，读取耐久 phase 决定后续步骤，不重放事务。普通 SDK 写入口仍受原来的保护，专用 SQL 续办能力只在准确 PID／Fiber、持锁见证和当前一次性批准的作用域内有效。

## 兼容性和有限验收

已有 252 个公开类型及全部原成员签名保持，新增两个公开类型和一个内部清单校验类，当前为 254 个公开／57 个内部类型。准确新增成员见[接口核对](state-account-resolution-evidence-2026-10-21/api-compatibility.json)。没有 DDL 修改；格式 3 的账号处置合法字段和用途扩展，旧读者可能拒绝新根，不能混用部署。缺少原始清单的历史账号 pending 仍可检查，但不能事后补算清单并调用新续办入口，须保留隔离并另行处理。

固定 13 条检查全部已执行并通过，源码输入保持一致、两次私有 MySQL 实例均已清理；准确命令、退出状态与源码 SHA-256 见[执行记录](state-account-resolution-evidence-2026-10-21/execution.json)。包含两端 PHP 的账号提交前／后未知、重复续办、重启读取、真实重新认证和新批准、受保护 PDO、多账号与范围外账号检查；拒绝检查覆盖伪造清单、无效结构、原始二进制字段、历史清单缺失、来源变化、撤权、过期、预算及完成回执丢失。受影响因子续办和陈旧 current 路径一并复验。

PHP 7.2 使用私有 sodium 和原生单调时钟，不能称为未增强系统 PHP 的通过。MySQL 各由控制器自建独立 Unix socket、禁 TCP 的临时 8.0.46 实例；专用测试账号的全局 TRIGGER 只用于该临时实例的完整依赖元数据检查，不更改宿主 MySQL 或生产授权。MySQL 外层控制器每项上限 600 秒包含多组测试及实例创建／清理，各 SDK 操作和 SQL 的原有 30 秒上限保持。静态分析存在既有可选 turbo 扩展的 GLIBC 启动告警，分析器本身退出 0、无代码错误。固定检查结束后核对输入、接口和清理，停止本组扩测；见[交付核对](state-account-resolution-evidence-2026-10-21/delivery-check.json)。

## 未关闭的完整恢复要求

本组终态仍为 disabled／quarantined。新密码和新因子登记、新凭据登录成功、旧会话／恢复码／API 凭据／一次性授权不复活、工作进程栅栏切换、通知与准确队列对账、完整恢复审计耐久以及最终可信代际提交仍须完成。当前回执保存最新续办及此前根摘要，不代表已经有完整独立耐久的恢复审计链。

其他全部启用入口／后端、真实 HTTP／浏览器、外部 SMTP／OIDC／实体设备／代理 WAF、远端 CI、独立复核及最终同源码九版整轮不由本组专项替代。未提交、推送或发布。原[有限计划](full-plan-2026-10-21.md)的 31 项、80 个有效工作小时上限保持，不因增加测试组自动延期。
