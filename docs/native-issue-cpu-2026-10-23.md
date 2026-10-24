# 默认签发：实际耗时与PHP进程CPU时间

为判断继续优化哪一层，本轮在临时测试副本中，仅在首次实际默认签发调用前后记录hrtime和getrusage。使用新的自有账号、初始因子及无TCP私有MySQL，保留3000ms凭据预算、全部权限检查和原事务路径。没有修改产品源码、系统配置、原测试文件或旧失败数据，没有续办未知结果。

本次调用失败：墙钟耗时3.814171371秒，PHP用户态CPU约0.515007秒、内核态CPU约0.524285秒，合计约1.039292秒，占调用耗时27.25%。余下约2.774879秒未计入PHP进程CPU，可能包含数据库进程工作、I/O、调度及失败清理；不能把它全部认定为磁盘等待，也不能据此判定环境是唯一根因。

异常栈仍在CredentialRegistry第二次actor中的会话复核后tick报告预算耗尽，最终错误为account.completion_unknown。计时包含失败传播／清理，不能将3.814秒当作恰好触发3000ms预算检查的时间。后续列表、轮换、替换和撤销没有执行。本次只有诊断意义，不是通过验收，也不自动解释其他历史失败。

该样本不支持优先采用小型PHP算术／哈希缓存；后续仍应检查数据库往返和完整状态读取成本，但不以性能为由删除授权、账本或事务检查。默认签发产品缺口继续开放。

证据：[测量](native-issue-cpu-evidence-2026-10-23/timing.json)、[限定分析](native-issue-cpu-evidence-2026-10-23/analysis.json)、[失败日志](native-issue-cpu-evidence-2026-10-23/run.log)、[运行终态](native-issue-cpu-evidence-2026-10-23/result.json)、[源码摘要](native-issue-cpu-evidence-2026-10-23/inputs.json)。输入摘要保持；临时测试副本、私有MySQL及本轮临时资源由运行器清理。无产品／API／兼容性变化，goal保持active。
