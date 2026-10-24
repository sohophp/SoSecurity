# 默认签发耗时：固定SQL直接读取实验

针对SqlTransaction::query中无参数只读SQL仍使用prepare/execute的情况，本轮在自有无TCP的MySQL实例比较PDO直接query与显式prepare/execute。使用PHP8.5、原生预处理配置、三种固定查询，各进行三轮交替顺序测量，每种方式每轮200次，3600项结果一致性断言通过。

直接读取的改善很小，SELECT 1的三轮均更慢，其他查询有快有慢。不据此修改SqlTransaction，不新增自定义PDO／PDOStatement分支，不再次执行默认签发，也不把微基准结果宣称为业务性能通过。

准确时间、源码摘要及决定见[结构化记录](sql-direct-read-evidence-2026-10-23/decision.json)，[原始日志](sql-direct-read-evidence-2026-10-23/probe.log)和探针保留。自有MySQL进程及临时包装器已退出清理。没有产品、公开API或兼容性变化。

同时核对R4.5：八份配置预设覆盖六类场景，现有configuration-presets测试主要证明配置解析、文件预算和无加载副作用；mysql.php/redis.php有工厂接入但不等于所有预设及真实HTTP业务组合已验收。保留该缺口，不把类或示例存在当作完成。

默认受保护MySQL签发超时、宿主时钟及其他非暂缓组合仍开放；没有执行暂缓流程或外部投递，goal保持active。
