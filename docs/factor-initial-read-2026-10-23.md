# 普通因子目录首次读取合并

2026-10-23。本批仅修改 `Ledger` 和 `FactorRegistry::snapshot()` 的首次读取；初始化写入、恢复、跨代交接等方法未改。前一批[因子返回校验合并](factor-checkpoint-read-2026-10-23.md)处理的是返回阶段，本批处理其之前仍重复认证的首次完整历史，不重复实现该修复。

修复前实际普通 current 根读取为 3 次，预期 2 次的复现失败，见 [before.log](factor-initial-read-evidence-2026-10-23/before.log)。新增内部 `Ledger::readCheckpoint()`，一次完整历史认证同时取得初始检查点和目标记录的签名元数据。SDK 通过其间的回调执行原账号读取，仍使用拥有单元的 `invoke()`；回调后重新完整检查当前 SQL 结构，再读取并校验正文。返回阶段原有 `readIfCheckpoint()`、账号指纹复核和全部 before/current/return 权限回调保留。

有效正常路径的顺序仍为初始历史认证、有效账号检查、当前结构校验、正文认证，以及后续权限和返回复核。没有跨调用缓存，也没有把宿主回调后的结构检查省略。普通 current 根读取由 3 次降至 2 次，binding 由 6 次降至 4 次；旧五场景测试仅更新这两个查询数量断言，未移除安全场景。

## 当前候选的已执行结果

所有下列当前候选结果绑定 [inputs.json](factor-initial-read-evidence-2026-10-23/inputs.json) 中同一运行时、SQL 资源及相关测试摘要。

- PHP 7.2—8.5 SQLite：207 条程序通过，其中新因子 12 场景 × 9、配对账本 6 场景 × 9、原因子返回校验 5 场景 × 9。见 [结果](factor-initial-read-evidence-2026-10-23/sqlite-context-final.json)、[运行器](factor-initial-read-evidence-2026-10-23/verify-context.py)。
- 同九版、私有禁 TCP MySQL 8.0.46：171 条程序通过，新因子另有每版一个账号回调创建临时遮蔽表的场景；两端原因子五场景另外 10 条通过。见 [171条](factor-initial-read-evidence-2026-10-23/mysql-context-final.log)、[原10条](factor-initial-read-evidence-2026-10-23/mysql-existing-context-final.log)。
- 验证停用／未验证账号在正文执行次数 0 时拒绝；账号回调创建临时表后，当前结构校验在正文执行前拒绝；账号回调以真实 HMAC 签名更新相同正文但增加修订号后，完整 before/current/return 回调仍运行，返回拒绝且回滚。还覆盖删除、根／正文损坏、初始损坏、权限拒绝、记录缺失、其他历史损坏及 65 条分页。测试前后账本／账号摘要相同。
- 两端真实 ZIP、离线全新 Composer 非符号链接安装、三个相关类的 vendor 反射来源及全部运行时／SQL 资源摘要核对：10 步通过。其中 MySQL 38 场景，SQLite 正常账本及账号回调有效写入 4 条调用。仅最终这组归档属于当前候选，见 [消费者](factor-initial-read-evidence-2026-10-23/consumer-context-final/consumer.json)；自身临时目录已清理。
- PHPStan 以工具内存 512MB 完成，无错误；可选 turbo 扩展仍因本机 GLIBC 不匹配有启动警告。公开 API 契约检查仍为 278 类型并通过；`bin/check.sh` 仅执行语法检查，新测试已接入其 SQLite／sodium 分支，没有运行包含暂缓套件的完整脚本。见 [静态分析](factor-initial-read-evidence-2026-10-23/static-context-final.log)、[API](factor-initial-read-evidence-2026-10-23/api-context-final.log)。

旧 PHP 缺少 sodium 时使用已有隔离扩展运行时，不修改系统安装。没有提高产品时间、内存或资源预算。静态分析工具的首次 128MB 内存不足保留在 static.log；工具内存调整不属于产品策略变化。

## 开发过程中保留的失败和中间候选

初轮 MySQL 专项因前一测试遗留自身表而中止，后来由新因子场景清理其创建的三张表；首次 SQLite PHP7.3 因系统运行时未加载 sodium 而中止，随后采用已存在的隔离运行时。mysql.log、sqlite.json 和 static.log 均保留，不记为当前通过。

初版合并把正文读取放到账号检查前。复核后恢复原账号检查顺序，并增加停用／未验证账号的正文 0 次断言。之后发现开发候选在账号回调后仍需重新检查结构：临时表只有 x 列的第一版样例在 prepare 阶段失败，不能证明没有尝试读正文；LIKE 同名表样例又遭遇 MySQL 1066，不能算遮蔽场景通过。用具有正文查询所需三列的真实临时表后，实际复现正文执行 1 次，见 [确认失败](factor-initial-read-evidence-2026-10-23/shadow-before-confirmed.log)。最终补回回调后的结构检查，九版 MySQL 均断言临时表创建成功、正文 0 次及只有 before 阶段回调。

这两处是本批开发候选中被纠正的问题，不声称原先源码存在这两个新缺陷。此前 mysql-final、mysql-privacy-final、sqlite-final 和两组较早消费者即使通过，也不替代当前 context-final 证据。诊断临时运行目录已清理，见 [清理记录](factor-initial-read-evidence-2026-10-23/shadow-probe-cleanup.json)。

## 未关闭范围与兼容性

隔离矩阵全部结束后，单独执行真实 SystemClock／原生 PDO 默认首次签发。PHP8.5 仍失败，约 3.278825 秒，原 3000ms 预算，栈仍位于 `issued()` 的第三次 actor 调用；见证 `pending`，外层 `account.completion_unknown`。没有续办。见 [时序](factor-initial-read-evidence-2026-10-23/default-85-timing.json)、[日志](factor-initial-read-evidence-2026-10-23/default-85-run.log)、[输入与清理结果](factor-initial-read-evidence-2026-10-23/default-85-result.json)。查询次数减少不证明整个签发提速；其他八版真实默认签发本批未重复执行。

公开签名、类型数 278、DDL、持久格式及默认预算不变；Ledger 已属内部类型，只新增内部配对读取方法。多处畸形数据同时出现时，拒绝的具体先后可能变化；当前权限、原始检查点、有效账号检查和正文校验仍保留。旧 PHP7.2 时钟及其他历史失败、默认签发性能、非暂缓最终候选核对仍未关闭；暂缓链路、外部环境验收未实现或执行。

当前 goal 保持 active，本批不是完整项目或稳定版验收。未提交、推送、部署、访问生产数据库或外部投递；既有改动保留。[汇总](factor-initial-read-evidence-2026-10-23/delivery.json)、批次前源码备份及增量 diff、[Git 状态](factor-initial-read-evidence-2026-10-23/git-status.final.txt)均保留在本地。
