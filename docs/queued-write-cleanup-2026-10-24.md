# 事务发件箱及幂等首次写入清理

2026-10-24。在[当前查询成本诊断](current-query-cost-2026-10-24.md)排除两项低收益假设后，继续处理可独立复现的普通写入缺陷。

## 实际修复与范围

PHP7.2和8.5的真实SQLite探针分别在SqlOutbox首次入队、SqlExecutor首次执行的记录INSERT上令closeCursor返回false。两者仍返回成功并留下记录；没有进行外部投递。见[7.2修前](queued-write-cleanup-evidence-2026-10-24/before72.log)、[8.5修前](queued-write-cleanup-evidence-2026-10-24/before85.log)。修后相同探针均以sql.cleanup拒绝，记录数为0，见[修后](queued-write-cleanup-evidence-2026-10-24/after85.log)。

只修改SqlOutbox和SqlExecutor各两处共享写入，使用上一批已加入内部SQL单元的execute方法，检查影响行数并明确完成游标清理。关闭false／异常、行数异常／负值均使SQL单元不可继续；保留原有读回、签名和完整历史认证。SQL、绑定参数、事务及宿主提交归属、存储格式、策略和预算不变，公开API278类／接口及候选契约不变。原维护／未知处置分支没有改动。

新增测试只覆盖初始化、首次入队／首次执行、首次完成响应及准确首次领取，不测试未知回执续办、跨代交接、最终恢复启用或外部发送。失败后直接核对自建数据库中的根、记录与业务数据全部保持，并验证同一SQL单元拒绝继续。八个正常场景验证实际提交结果，避免以全面拒绝获得通过。

## 本地测试与发行验证

PHP7.2、7.3、7.4、8.0—8.5九版本：SQLite／API矩阵45/45、MySQL矩阵36/36通过，均核对成功标记且无跳过、PHP警告或弃用提示。每版两后端新增40个故障、8个正常场景，合计720个故障和144个正常场景；另有准确首次领取、发件箱输入边界及幂等输入边界的既有回归。没有运行未知续办或外部发送。

实际ZIP、离线全新安装且不使用符号链接；367份SDK／SQL内容和实际加载来源均匹配。两端SQLite／MySQL共16个消费者功能程序以及归档／安装、来源检查通过，自建资源已清理。相关27条PHP语法、Shell／Python语法检查和静态分析通过；静态工具启动仍有原可选turbo扩展要求GLIBC_2.32的警告，日志保留，没有修改环境。

证据：[SQLite／API](queued-write-cleanup-evidence-2026-10-24/local-result.json)、[MySQL](queued-write-cleanup-evidence-2026-10-24/mysql-result.json)、[消费者](queued-write-cleanup-evidence-2026-10-24/consumer/consumer.json)、[消费者MySQL逐程序](queued-write-cleanup-evidence-2026-10-24/consumer/test-rows.json)、[静态](queued-write-cleanup-evidence-2026-10-24/static.log)、[最终SDK输入](queued-write-cleanup-evidence-2026-10-24/final-inputs.json)、[四个写入增量](queued-write-cleanup-evidence-2026-10-24/source-change.diff)、[交付汇总](queued-write-cleanup-evidence-2026-10-24/delivery.json)。本批SDK仅这两类改变，其余365份输入保持。

最初测试把getPrevious必须为null当作断言，40个实际已拒绝的场景在该断言处失败。既有SQL单元在异常清理时可以链接已脱敏的SDK错误；现改为检查整个异常文本不含私有消息，并逐层限制为StorageException、深度不超过8。原[初轮日志](queued-write-cleanup-evidence-2026-10-24/first85.log)和[初轮测试](queued-write-cleanup-evidence-2026-10-24/test-before-chain.php)保留；没有删除保护、修改SDK错误来适配断言或覆盖失败。

本批没有把上述定向验证称为全项目验收，也没有重新运行含暂缓功能的完整check.sh。默认性能、PHP7.2时钟及未解释权威依赖错误、最终非暂缓整合仍开放；以前的完整默认流程有各自输入，不直接认定为当前候选通过。真实IdP／设备、生产代理／WAF和外部投递未验收，暂缓范围保持。goal保持active；没有提交、推送、部署或访问生产数据库，只清理自建测试资源。
