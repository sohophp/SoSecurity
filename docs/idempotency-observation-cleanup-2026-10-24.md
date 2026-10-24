# 原生幂等准入的只读观察清理

2026-10-24。本批继续修复非暂缓的初始化／首次执行／维护准入观察，没有恢复未知执行、交接或最终账号启用。

## 实际问题与修复

PHP7.2／8.5均复现：根容量COUNT、请求容量COUNT和维护预观察分页没有显式关闭游标，关闭失败未被观察，仍返回观察结果；初始化孤儿检查经精确探针也复现同一遗漏。首轮孤儿探针误命中更早的SQLite结构SELECT 1，不能作为该读取证据；原日志保留，另用完整表名、namespace与LIMIT匹配，仅补证此前未命中的目标。

证据：[初轮两端之一](idempotency-observation-cleanup-evidence-2026-10-24/before72.log)、[探针范围更正](idempotency-observation-cleanup-evidence-2026-10-24/probe-scope-correction.json)、[精确修前7.2](idempotency-observation-cleanup-evidence-2026-10-24/orphan-before72.log)、[精确修前8.5](idempotency-observation-cleanup-evidence-2026-10-24/orphan-before85.log)、[修后四入口](idempotency-observation-cleanup-evidence-2026-10-24/after85.log)。修后均关闭一次即sql.cleanup拒绝，不返回准入事实。

SDK仅修改SqlExecutor：四处读取接入已有metadataRows；两处COUNT共用私有entryCount，使用已有单行通道，要求唯一聚合列并保留原SqlSchema::integer范围校验。SQL、参数、LIMIT、排序及锁逐字保持，既有权限／事务／输入／内存／时间预算及存储格式保持。观察失败后，原执行器单元与observing标志仍在finally恢复；失败的只读SQL单元禁止继续。公开API仍为278类／接口，候选契约未修改。

## 本地专项与实际原生流程

新增每后端每版26场景、364断言：16个关闭false／异常；10个正常／跳过／孤儿拒绝，覆盖空与有记录页面、其他命名空间容量、已有根和已完成请求跳过COUNT。测试读取实际私有观察方法，核对原根／记录／业务摘要、业务处理次数、事务退出、只读单元失败后拒绝继续、原单元／标志恢复、SDK异常链和私有消息不泄露。该故障专项不代替公开原生流程验收。

九版本SQLite／API36/36通过。MySQL九版本27/27通过。当前输入共468个新增场景（288关闭故障、180正常／跳过／孤儿拒绝）及972个相关读取／分页场景通过，见[MySQL终态](idempotency-observation-cleanup-evidence-2026-10-24/mysql-result.json)及[交付核对](idempotency-observation-cleanup-evidence-2026-10-24/delivery.json)。归档实际ZIP、离线新消费者安装7步通过，PHP7.2／8.5两端SQLite／MySQL共8个功能程序通过；367份运行输入、安装来源和无符号链接核对通过，自身临时资源清理完成。

另用未改的native-maintenance.php，明确只选idempotency／idempotency_request各自normal模式，执行两端两后端8个公开原生功能程序。初始化／维护两端两后端4/4通过；首次执行／结果查询仅PHP8.5两后端2/2通过，PHP7.2两个后端均遭遇真实持续时间时钟倒退失败，后续未执行，没有续办未知结果或重复覆盖失败。因此原生专项为6/8，两个控制器均退出1，不写成全绿。测试使用原有30000毫秒普通集成预设，不冒充默认预算验收。

证据：[SQLite／API](idempotency-observation-cleanup-evidence-2026-10-24/local-result.json)、[消费者](idempotency-observation-cleanup-evidence-2026-10-24/consumer/consumer.json)、[消费者MySQL逐程序](idempotency-observation-cleanup-evidence-2026-10-24/consumer/test-rows.json)、[原生SQLite](idempotency-observation-cleanup-evidence-2026-10-24/native-sqlite-result.json)、[原生MySQL](idempotency-observation-cleanup-evidence-2026-10-24/native-mysql-result.json)、[PHP7.2原生SQLite失败](idempotency-observation-cleanup-evidence-2026-10-24/72-native-sqlite-idempotency_request.log)、[PHP7.2原生MySQL失败](idempotency-observation-cleanup-evidence-2026-10-24/72-native-mysql-idempotency_request.log)、[18项PHP语法](idempotency-observation-cleanup-evidence-2026-10-24/syntax.json)、[静态](idempotency-observation-cleanup-evidence-2026-10-24/static.log)、[源码增量](idempotency-observation-cleanup-evidence-2026-10-24/source-change.diff)、[冻结输入](idempotency-observation-cleanup-evidence-2026-10-24/final-inputs.json)。静态最终No errors，可选turbo扩展的GLIBC_2.32启动警告保留，未修改环境。

## 未关闭条件

本批未重跑默认九版本管理流程；[前批冻结结果](queued-read-cleanup-2026-10-24.md)仅8.4／8.5完整通过，是此前源码证据，不作为本候选整轮通过。默认预算缺口、PHP7.2时钟及此前未解释依赖错误、最终非暂缓整合仍开放，goal保持active。没有重复已经否决的性能原型，没有放宽预算或安全保护。

跨安全代际工作进程交接、未知回执续办、最终恢复启用及完整F01保持暂缓；未定义OIDC关联迁移按用户授权跳过。真实IdP／设备、生产代理／WAF、外部投递及独立外部验收未执行。未运行完整check.sh，未提交／推送／部署或访问生产数据库；既有数据与其他未提交改动保留。
