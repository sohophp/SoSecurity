# 当前普通组件候选复验

> 后续逐日志更正：本批855条命令虽均退出0，但PHP8.2和8.4的storage-failure日志明确为NOT RUN（缺POSIX扩展），所以实际为853项通过、2项未执行。下文“未发现NOT RUN”的历史判断错误；原始日志和旧汇总保留，不改写成绿色结果。新批次按输出内容分类并使未执行导致整批不通过，见ordinary-final-core-evidence-2026-10-23。

上一份普通组件828项快照之后，运行时变化集中于SessionRegistry、HtmlCleaner、MySqlStore。本批针对这些变化后的同一源码，执行原92条普通组件命令并加入当前会话返回校验与两条HTML错误／输出测试；每版95条，PHP7.2—8.5九版合计855条均退出0，日志未发现SKIP、NOT RUN、FAIL或Fatal error。运行前后输入摘要一致。使用真实PHP运行时及既有Sodium包装器，不注入单调时钟替换PHP7.2默认时钟。

本地原生认证HTTP及凭据TLS在PHP7.2、8.5共4条命令通过：每版认证192项、凭据TLS600项。只使用自有临时数据、进程和本地端点，包含普通恢复码登录，不含账号最终恢复启用、跨代工作交接、未知结果续办或完整F01。

[命令清单](ordinary-candidate-evidence-2026-10-23/cases.json)、[汇总](ordinary-candidate-evidence-2026-10-23/summary.json)、[HTTP结果](ordinary-candidate-evidence-2026-10-23/http.json)、[准确运行时身份](ordinary-candidate-evidence-2026-10-23/candidate.json)均保留。这是当前普通组件整批复验，不是所有非暂缓功能的完整门禁；MySQL存储专项、可选包、浏览器和归档仍分别按各自证据范围解释，不能拼成一次全项目验收。

当前运行时代码未新增修改。公开API对应上一批同源码检查为277类／接口；兼容变化见[当前说明](current-compatibility-2026-10-23.md)，本批没有新增兼容变化。

同时为默认签发的查询成本进行一次临时SQL探针：增加库名等值筛选，六种外键情形／普通及只读账号共630项等价断言通过，但候选总查询时间0.135秒、现行0.139秒，差异约2.4%，各场景有快有慢。单次混合差异不足以证明有效优化，未采纳、未更改仓库查询、未再次执行默认签发。见[探针与决定](native-query-profile-evidence-2026-10-23/lookup-decision.json)。自有数据库及探针临时目录已清理。

仍未关闭：默认受保护MySQL凭据签发总预算失败、PHP7.2时钟倒退及其他历史未解释失败、原生功能组合与全部适用后端最终门禁。暂缓能力和外部验收不在本批验证范围，不写为完成。goal保持active，不提交、推送或部署。
