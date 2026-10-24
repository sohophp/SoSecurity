# SQL审计读取、写入与清理的完成检查

2026-10-24。核对现有SQL审计实现后，修复独立的关闭失败与零行问题；未重做审计功能，也未运行未知回执续办或完整F01。

## 实际复现与修复

PHP7.2／8.5原始代码均复现：初始化根读取、追加INSERT、历史读取和清理DELETE的closeCursor返回false仍返回成功；初始化／追加／清理还提交了对应变化。修后均sql.cleanup拒绝，初始化根保持0条、追加记录保持0条、清理记录恢复1条，历史不返回数据。

[修前7.2](audit-sql-cleanup-evidence-2026-10-24/before72.log)、[修前8.5](audit-sql-cleanup-evidence-2026-10-24/before85.log)、[修后](audit-sql-cleanup-evidence-2026-10-24/after85.log)保留。

另由测试语句回调在SDK实际DELETE前删除自建记录、在实际UPDATE前删除自建根，构造实际影响0行。冻结修前类副本按原始摘要加载，其余366份运行输入保持，未切换或撤销工作树：旧实现仍返回purged=1，或留下无根的追加记录并返回成功；修后拒绝，事务回滚并恢复原记录／根。证据：[修前7.2](audit-sql-cleanup-evidence-2026-10-24/zero-before72.log)、[修前8.5](audit-sql-cleanup-evidence-2026-10-24/zero-before85.log)、[修后7.2](audit-sql-cleanup-evidence-2026-10-24/zero-after72.log)、[修后8.5](audit-sql-cleanup-evidence-2026-10-24/zero-after85.log)、[两端MySQL](audit-sql-cleanup-evidence-2026-10-24/zero-mysql-result.json)。

SDK只改SqlSink。根、计数、历史、清理页及prepareState预观察使用已有metadataRows；DML使用已有execute完成方法，失败单元不可继续。插入／选中删除要求恰好1行，根更新拒绝超过1行；MySQL同值UPDATE合法返回0时读回核对，不把0一律当错误，也不把根消失当成功。两个聚合计数要求唯一整数结果，去掉原site计数的宽松int强制转换。根单行SQL显式LIMIT 1；其他SQL、参数、排序和锁保持。

读取页仍SQL限制100条、每条4096字节；先有界消费并关闭，再校验和返回。权限的请求／提交两阶段检查、根锁、当前锁定容量读取、独立审计事务、单次预备写入、规范JSON、保留期及输入／内存／时间预算保持，存储格式和公开API278类／接口保持，候选契约未修改。[源码增量](audit-sql-cleanup-evidence-2026-10-24/source-change.diff)和[冻结输入](audit-sql-cleanup-evidence-2026-10-24/final-inputs.json)可逐项核对。

## 实际本地验证

PHP7.2、7.3、7.4、8.0—8.5九版，SQLite／API36/36及MySQL27/27通过。每版每后端42场景、461断言，共756个新增场景：630个关闭／结果／零行故障，126个正常／撤权／最大页检查。验证事务回滚、根和记录摘要保持、失败单元拒绝继续、SDK异常链不带私有驱动消息、分页游标、容量释放、顺序号持续递增、请求和提交阶段撤权。每个程序都实际读取100条最大页；18个程序峰值均2097152字节，未提高8MiB测试限制。

首轮新测试34/42通过，8处错误地期望内部execute的sql.unavailable；原有外层run在单元被标记不可用后返回sql.cleanup。纠正为实际外层契约，并保留事务／数据／异常链／不可继续检查，未改SDK来迁就测试。原失败和初始测试源码保留：[首轮](audit-sql-cleanup-evidence-2026-10-24/first85.log)、[更正说明](audit-sql-cleanup-evidence-2026-10-24/test-expectation-correction.json)。

实际ZIP、离线全新消费者安装7步及两端两后端12个功能程序通过；367份SDK／SQL和实际安装来源核对一致，无符号链接，自身临时资源清理完成。两个端点两后端另4个实际零行程序、8场景通过。旧audit-sql.php／audit-sql-history.php随影响范围复验，未执行包含未知处理路径的audit-sql-pipeline.php或完整check.sh。18项PHP语法、Python／Shell语法和静态分析通过；静态可选turbo扩展的GLIBC_2.32启动警告保留，最终No errors，未修改环境。

证据：[SQLite／API](audit-sql-cleanup-evidence-2026-10-24/local-result.json)、[MySQL](audit-sql-cleanup-evidence-2026-10-24/mysql-result.json)、[消费者](audit-sql-cleanup-evidence-2026-10-24/consumer/consumer.json)、[消费者MySQL逐程序](audit-sql-cleanup-evidence-2026-10-24/consumer/test-rows.json)、[交付核对](audit-sql-cleanup-evidence-2026-10-24/delivery.json)、[语法](audit-sql-cleanup-evidence-2026-10-24/syntax.json)、[静态](audit-sql-cleanup-evidence-2026-10-24/static.log)。

## 当前PHP8.5默认受保护审计流程

在其他控制器全部结束并清理后，只执行一个全新MySQL测试环境，实际SystemClock／原生PDO，主凭据保留默认3000毫秒；原有对象拒绝专用预设仍30000毫秒，不冒充默认验收。

首次签发2.964701秒成功，当时见证current；查询、轮换、替换、撤销完成。第二次签发在审计append阶段超时，最终抛出account.completion_unknown，程序退出1；没有续办，revoke-all未执行，最终见证状态未另行采集，不能将首次current写成最终状态。因此该程序不通过，完整默认流程仍未完成。另八版默认流程本批未执行，也不把此前源码的通过移作本候选通过。

[预定范围](audit-sql-cleanup-evidence-2026-10-24/default-85/scope.json)、[首次实际计时](audit-sql-cleanup-evidence-2026-10-24/default-85/default-85-timing.json)、[原始失败](audit-sql-cleanup-evidence-2026-10-24/default-85/default-85-run.log)、[控制器与清理终态](audit-sql-cleanup-evidence-2026-10-24/default-85/default-85-result.json)保留。

默认性能、PHP7.2历史时钟倒退与未解释依赖失败、最终非暂缓整合仍开放；本专项不代表全项目或稳定版验收，goal保持active。跨代工作进程交接、未知回执续办、最终恢复启用及完整F01保持暂缓；未定义OIDC关联迁移按授权跳过，真实IdP／设备、生产代理／WAF和外部投递未验收。未提交／推送／部署，未访问生产数据库，既有环境、数据及其他未提交改动保留。
