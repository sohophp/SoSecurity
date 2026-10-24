# 默认签发的 PDO 阶段测量

本次未修改产品源码。此前仅统计 PDOStatement::execute，无法解释完整数据库调用成本。本次在临时复制的测试入口中使用 PDO 子类，分别测量原生 prepare、exec、query；仍调用原实现，不调整期限、权限、事务或失败处理。只运行自建无 TCP MySQL 上的全新初次签发，失败后停止，没有续办 pending。

PHP 8.5 的诊断观测为 3.145292 秒，返回 account.completion_unknown。prepare 共 1,972 次、约 1.114800 秒，占本次观测约 35.4%；exec 共 1,656 次、约 0.256468 秒。此前遗漏的准备阶段成本足以影响下一步优化选择。各计数器可能嵌套，不把所有时间简单相加；插桩开销也包含在总观测中。这不是正常运行性能验收，也不能据此推算修复后的签发总时间。

原执行阶段画像另记录了 216 次权限／列校验，其中 152 次来自当前工作进程权限读取。代码核对显示该路径包含回调前后账本复核，不能仅凭重复次数删除复核或跨回调缓存权限。下一步评估有界 SQL 分组以减少重复准备和往返，须先验证结果及拒绝条件等价，再决定产品改动。

证据：[运行器](issue-pdo-phase-evidence-2026-10-23/run.py)、[原始日志](issue-pdo-phase-evidence-2026-10-23/run.log)、[结果](issue-pdo-phase-evidence-2026-10-23/result.json)、[分析](issue-pdo-phase-evidence-2026-10-23/analysis.json)及[源码摘要](issue-pdo-phase-evidence-2026-10-23/inputs.json)。运行器退出 0 只表示诊断采集结束，结果明确标记 acceptance=false；产品操作失败。临时资源由本次运行器清理，源码摘要复核一致。Python 语法检查和 git diff --check 通过。

没有公开 API 或兼容性变化；未执行九版产品回归或归档消费者，因为本次没有产品改动。默认签发缺口仍开放，goal 保持 active，暂缓链路和外部验收保持未执行。
