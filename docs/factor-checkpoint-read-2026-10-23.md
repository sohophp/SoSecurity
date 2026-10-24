# 因子返回校验的账本重复读取修复（2026-10-23）

本批只合并 `FactorRegistry::snapshot()` 返回校验内相邻的检查点与记录读取。此前该阶段连续认证两次完整历史；新增内部 `Ledger::readIfCheckpoint()` 在一次完整历史认证后比较检查点，仅匹配时读取并校验正文。普通 current 的根查询从 4 次降为 3 次，binding 从 8 次降为 6 次。

保留 before/current/return 授权回调、账号指纹复核、完整历史签名与摘要、正文长度与摘要、事务回滚及原资源预算。没有跨调用缓存。初始化写入、恢复相关方法和暂缓链路未改。公开 API 仍为 277 个类／接口，Ledger 原已属于内部清单；没有修改候选契约，无数据库迁移。

## 本地证据

证据目录：[factor-checkpoint-read-evidence-2026-10-23](factor-checkpoint-read-evidence-2026-10-23/)。`runtime.patch` 仅比较本批修改前后的两份源码，`source-hashes.json` 固定当前摘要。

- 修复前 `before85.log` 复现根查询次数为 2 而非预期 1。
- SQLite 账本专项 PHP 7.2—8.5：63/63；覆盖正常、缺失、检查点变化、其他历史损坏、历史删除、正文损坏和分页。
- SQLite 因子专项同九版：45/45；覆盖 current、binding、返回时拒绝、账号变化、正文篡改及事务回滚。测试只使用新建账号及初始 TOTP。
- 私有 MySQL 8.0.46，PHP 7.2／8.5：账本 14/14，因子 10/10。使用自有临时 socket、数据库和进程。
- 离线 Composer ZIP、非软链接全新消费者安装、vendor 来源和运行时摘要：8/8 步通过，其中 MySQL 账本 14 场景、因子 10 场景。见 `archive.json`。
- 进一步补强检查点变化场景：改用仍存在的记录，以排除缺失记录导致空结果的干扰；SQLite 九版 9/9。见 `changed-existing.json`。补充归档消费者 6/6 步通过（其中两端私有 MySQL 14 场景），见 `changed-consumer/archive.json`，确认存在的记录在检查点变化后不会读取正文。
- 测试已接入 `bin/check.sh` 的 SQLite／sodium 分支及 `tests/mysql_check.py` 的两个专项参数；仅检查 shell 语法，没有执行包含暂缓套件的完整入口。
- PHPStan 已执行并通过；API 检查通过 277 类型。见 `static.log`、`api.log`。

## 失败保留与验收边界

因子测试第一版缺少显式初始化，第二版初始化后又重复 adopt，均在目标读取路径前被正确拒绝。最终测试只初始化一次；未修改产品的未初始化或已启用拒绝。原日志、两份失败矩阵及首次消费者失败记录保留，不算通过。

本批为定向回归，不是全项目或稳定版验收。默认 MySQL 原生凭据预算、PHP 7.2 既有未解释失败及其余候选缺口仍需独立判断。跨安全代际交接、未知回执续办、最终恢复启用及依赖它们的 F01 均未测试，外部环境验收未执行。goal 保持 active。

## 默认原生流程诊断

所有本批并行测试结束后，单独执行 `python3 tests/mysql_check.py --native-audit-profile php85`。诊断脚本退出 0，但内部签发失败：3.132706203 秒，`StorageException account.completion_unknown`，见证为 `pending`，`acceptance=false`。后续 all／rotate 未执行；没有续办 pending。见 `default-profile.log`。这不是通过，不能据单次计时与旧环境记录比较宣称稳定性能改善。
