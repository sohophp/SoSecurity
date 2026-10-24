# SQL快照数据库身份与上下文游标处理

2026-10-24。本批在核对默认预算路径时发现并复现两项独立产品缺陷，优先修复；没有扩大或执行暂缓链路。仅修改运行时`Account\SqlStateSnapshot`，保留其他既有改动。

## 确认的问题

1. SQL快照仍把普通DATABASE()结果写入摘要。两个自建Unicode库包含相同的单行整数表；在UTF8结果字符集下摘要不同，改用latin1后两个库名都变成相同问号文本，摘要也错误地相同。同一库仅改变结果字符集也会改变摘要。这是本地数据库身份混同，不代表已确认生产攻击或完整F01风险已关闭。
2. 隔离级别及数据库名的两条上下文查询使用临时Statement直接fetchColumn，没有显式观察closeCursor结果。模拟关闭返回false或抛出私有异常时，旧实现仍返回有效摘要。

PHP7.2和8.5修前均复现上述四个失败场景。另一个隔离级别用例最初只捕获SecurityException，未捕获已有的ConfigurationException，属于测试错误，不能计为产品缺陷。见[修前结果](sql-snapshot-context-evidence-2026-10-24/probe.json)、[PHP8.5原始记录](sql-snapshot-context-evidence-2026-10-24/php85-context.log)、[PHP7.2原始记录](sql-snapshot-context-evidence-2026-10-24/php72-context.log)。

## 实际修复与兼容性

上下文改为一条新鲜查询，同时取得隔离级别和数据库名，使用现有SqlTransaction::metadataRows完整获取并关闭游标。数据库名以CAST(DATABASE() AS BINARY)返回；结果必须为一行、两个字段，隔离级别仍须REPEATABLE-READ，数据库仍为1至64字节。清理失败使SQL单元拒绝继续，不读取业务行；异常链仅允许已脱敏的SDK错误，不保留模拟私有异常。组合查询不进入预备语句池，不缓存上下文、权限或摘要。

[源码增量](sql-snapshot-context-evidence-2026-10-24/source-change.diff)只涉及上述上下文观察；SQLite路径、完整字段／字节摘要、选取结果、事务边界、结构前后观察及预算保持。公开API清单仍为278类／接口，没有公开签名、DDL或存储格式变化。相对于本批开始，[367份最终摘要](sql-snapshot-context-evidence-2026-10-24/final-inputs.json)仅SqlStateSnapshot变化，其余366份保持。

两端均核对普通ASCII库及正常UTF8结果下的Unicode库，摘要与修前逐字一致；latin1结果现在得到同一库的正确UTF8身份摘要，且不同库保持不同。见[摘要兼容对照](sql-snapshot-context-evidence-2026-10-24/digest-compatibility.json)。过去按有损结果字符集计算的错误摘要将不再匹配；不自动转换、接受或重建已有见证，不绕过隔离。大于64字节但MySQL允许创建的Unicode库名仍拒绝，没有放宽原输入／资源预算。

## 本地验证及失败保留

| 已执行并通过 | 范围 |
| --- | --- |
| 新增专项 | PHP7.2、7.3、7.4、8.0—8.5，九个程序、72个场景，每版54个断言；覆盖跨库区分、字符集稳定性、ASCII兼容、原64字节限制、隔离级别、无默认库及两类关闭失败 |
| 既有MySQL | 九版各5个快照程序，共45/45：完整SQL摘要、选取、提交后结果隔离、组合视图与分页 |
| SQLite回归 | 同五类程序，九版45/45 |
| API／静态 | 九版API均为278，静态分析通过；与SQLite共55/55程序 |
| 全新消费者 | 实际ZIP、离线安装且不使用符号链接，两端12个MySQL和10个SQLite程序共22/22，流程7/7步骤；反射来源和367份SDK／SQL摘要一致，自建资源已清理 |

证据：[新增补测](sql-snapshot-context-evidence-2026-10-24/supplement.json)、[既有MySQL主轮](sql-snapshot-context-evidence-2026-10-24/first-matrix.json)、[SQLite／API／静态](sql-snapshot-context-evidence-2026-10-24/local-checks.json)、[消费者](sql-snapshot-context-evidence-2026-10-24/consumer/consumer.json)、[消费者逐程序记录](sql-snapshot-context-evidence-2026-10-24/consumer/test-rows.json)。MySQL仅使用测试框架自建无TCP实例；没有访问生产数据库。

主轮原结果为45/54程序通过，九个新增程序因测试要求getPrevious必须为null而失败。实际拒绝已发生，链中只有已脱敏的SDK清理错误；现修正为逐层检查异常类型、链深和整个异常文本，禁止原始异常或私有内容。随后只补跑新增九个程序，SDK摘要保持，没有重跑45个已通过程序或删除保护。原始失败与测试源文件分别保留，补测不覆盖主轮失败。新入口已接入mysql_check.py和check.sh；本批没有运行完整check.sh。

## 当前默认调用与剩余范围

最终功能验证及消费者均结束后，单独检查一次PHP8.5默认正常管理流程，使用新测试预设环境、真实SystemClock和PDO、纯来源守卫、策略提示1及原3000ms预算。首次签发约3.064789秒以api_credentials.timeout拒绝，见证current；堆栈在audit_check的auditCurrent首次tick，尚未返回凭据。后续查询、轮换、替换、撤销及拒绝场景均未执行，未重试或续办。[计时](sql-snapshot-context-evidence-2026-10-24/workflow/default-85-timing.json)、[运行结果](sql-snapshot-context-evidence-2026-10-24/workflow/default-85-result.json)、[原始失败](sql-snapshot-context-evidence-2026-10-24/workflow/default-85-run.log)。其他八版的默认流程本批未重复执行；上批九版默认结果属于此前的SqlStateSnapshot摘要，不能作为本批候选通过证据，其失败及PHP7.2时钟倒退记录继续保留。

默认预算在全部支持版本和正常管理入口稳定通过，以及最终非暂缓候选验收仍未完成，goal保持active。跨安全代际工作进程交接、未知回执续办、最终账号恢复启用、依赖完整F01及外部验收未执行。只清理自建进程和临时数据；未提交、推送、部署或修改内部任务数据库。
