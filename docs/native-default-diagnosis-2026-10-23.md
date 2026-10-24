# 默认原生 MySQL 签发失败定位

前置：[因子账本查询修复](factor-checkpoint-read-2026-10-23.md)。本次使用自有临时 MySQL、全新测试账号和初始 TOTP，仅执行普通凭据签发诊断；不续办未知状态。

在临时目录复制当前 `Deadline`，只在到期抛出前输出固定原因码、是否倒退及不含参数的调用栈；不改变时间、预算、异常或业务行为。源码仓库中的 Deadline 没有修改。脚本与日志见 [native-default-diagnosis-evidence-2026-10-23](native-default-diagnosis-evidence-2026-10-23/)。

已执行，业务失败：约 3.024 秒，`api_credentials.timeout`，`backwards=false`。调用栈定位在 `CredentialRegistry::issueInternal()` 的第二次 `actor()` 内，完成 capabilities 调用后的 tick。外层返回 `account.completion_unknown`、见证 `pending`，`acceptance=false`。诊断驱动退出 0 不代表业务成功。all／rotate 没有执行。

这使默认失败从未定位的 completion_unknown 收敛为本次可观测的 API 凭据总预算耗尽；不能据此解释其他 PHP 7.2 历史失败，也没有证明解决方案。保留原始预算及 pending 限制，不修改恢复逻辑。临时诊断副本和自有数据库进程已清理。
