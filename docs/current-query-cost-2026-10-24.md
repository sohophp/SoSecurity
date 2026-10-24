# 当前首次签发的构造及语句池成本诊断

2026-10-24。为了定位默认3000ms缺口，在两份证据目录源码副本中增加只计数的插桩：Ledger只测原生根查询SQL字符串组装语句，SqlStateAccess只统计原有语句池查找的命中／未命中。没有改变SQL、结果、池上限、授权、PDO、Clock或预算。SDK及SQL的367份冻结输入在诊断结束时保持。

只有一次PHP8.5自建无TCP MySQL的全新预设、首次签发尝试；代码在首次签发之后返回，不运行后续管理操作。数据不包括SQL内容、参数、账号或返回行，最多24个已有SQL上下文哈希键的计数。不是默认验收或性能前后对照。

| 实测项 | 结果 |
| --- | --- |
| 根查询SQL组装 | 288次，累计13.803448毫秒，约占3000ms预算0.4601% |
| 语句池查找 | 1132次，1125命中、7未命中，命中率99.3816% |
| 截断／未登记键 | 0次；共11个键，各未命中最多一次，没有观察到重复淘汰导致的低命中 |
| 首次签发尝试 | 约3.020317秒，api_credentials.timeout，采集时current，未返回凭据；随后停止 |

事先冻结的判断条件是：组装成本至少占默认预算5%，才考虑增加固定模板缓存；未命中至少50%且九种键反复未命中，才考虑改变池策略。两项均未达到，因此不实施这两个假设下的优化，不扩大或重复原型。先前策略摘要不足1ms、触发器共享存在预热偏差的实验也没有重做。

[原定条件](current-query-cost-evidence-2026-10-24/criterion.json)、[原始计数](current-query-cost-evidence-2026-10-24/measurements.json)、[判断](current-query-cost-evidence-2026-10-24/decision.json)、[计时与实际依赖类型](current-query-cost-evidence-2026-10-24/default-85-timing.json)、[退出／输入／清理](current-query-cost-evidence-2026-10-24/default-85-result.json)、[输入摘要](current-query-cost-evidence-2026-10-24/inputs.json)均保留。完整服务器、PHP与其他SQL执行成本没有在本次归因，不把这些计数当作完整耗时分类。

本阶段没有SDK修改。后续[队列普通写入清理](queued-write-cleanup-2026-10-24.md)修复了另外两类；本诊断不冒充后续源码的默认验收，也不关闭历史默认失败或goal。
