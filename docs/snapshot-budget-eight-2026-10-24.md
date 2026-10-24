# 八表快照分组原型：未采用

2026-10-24。原型只存在于隔离的源码副本，未修改 SDK。它仅尝试将八张小表放在同组；原有列数、主键数、260列／20键、8槽语句池、摘要格式及默认时间预算不变。

采样前固定标准：两端 PHP7.2／8.5，预热32次、32轮交替 ABBA／BAAB；总耗时和中位数比均不超过0.95，基线首末四分位漂移不超过5%，摘要一致、峰值不超过8MiB。原型须通过功能门禁才能采用。

首次运行的安全检查误将数据字符串 mfa_required 识别为 require，两程序均在采样前失败。改为词法 token 检查后仅执行此前未执行的采样，标准保持：PHP7.2 遇持续时间时钟倒退，未形成完整样本；PHP8.5 程序退出0，摘要一致、峰值4194304字节，总耗时比0.893900687、中位数比0.880144672，但基线漂移6.1035%，不满足固定标准。

结论：未采用，不再重复该假设；采用前的功能门禁未执行，不宣称性能验收通过。两轮失败、实际样本及自身资源清理记录均保留，SDK输入未改变。

证据：[预定标准](snapshot-budget-eight-evidence-2026-10-24/criterion.json)、[首轮预设错误](snapshot-budget-eight-evidence-2026-10-24/setup-failure.json)、[更正后的控制器](snapshot-budget-eight-evidence-2026-10-24/corrected/prototype.json)、[8.5样本](snapshot-budget-eight-evidence-2026-10-24/corrected/result-85.json)、[最终决定](snapshot-budget-eight-evidence-2026-10-24/decision.json)。默认预算、历史时钟／依赖错误及最终非暂缓整合仍开放。
