# 2026-10-22 审计记录预算及传输异常隐私修复

本批针对独立审计入口，不依赖暂缓的工作进程交接、回执未知续办、最终账号恢复或完整F01。保留现有源码、环境、数据与未提交改动；不提交、不推送、不部署、不外部投递。

## 已复现和修复

1. `BudgetedSink`、`MetricsSink`、`RecentEvents`及`SqlSink`对结构化记录先调用`array_keys()`再拒绝非法形状，异常大数组会在错误处理前耗尽进程内存。新增五字段数量检查，在复制前拒绝；正常记录协议、字段顺序及既有副作用顺序不变。四项均有8MiB进程的旧实现内存耗尽日志。
2. `AlertOutboxWorker`将宿主传输异常作为`DependencyException`的previous返回，调用方记录异常字符串时可泄露传输凭据或端点详情。现保留固定`audit.alert_delivery`错误码，去除原始异常链；失败仍落为原来的可重试状态，消息ID不变，成功后正常确认，不增加自动重试。测试以合成私密标记复现，再检查异常链、队列状态及下一次正常投递。

仅修改上述五个运行时文件及相应测试。`tests/audit-record-budget.php`接入`bin/check.sh`；告警失败场景扩展已有`tests/audit-alert-worker.php`，因此既有私有MySQL入口自动覆盖。

## 当前证据

证据目录：[audit-boundary-evidence-2026-10-22](audit-boundary-evidence-2026-10-22/)。`before.json`为本批前源码摘要，`baseline.json`和原始日志记录修复前失败。SQL测试最初没有启用PDO异常模式，先被构造保护拒绝；更正后的`sql-configured-baseline.json`及日志才是实际SQL审计字段内存缺陷证据。前两份测试配置失败不冒充产品复现。

`matrix.json`记录PHP7.2、7.3、7.4、8.0、8.1、8.2、8.3、8.4、8.5的99次定向执行，均退出0。每版包括四个内存拒绝模式，以及告警worker、预算、指标、近期事件、SQLite审计写入、历史读取和SQL告警组合七套回归。新增预算测试确认拒绝前未调用下游writer或创建新存储文件。此为相关模块回归，不是全项目九版验收。

私有MySQL两端各三套、各107项断言通过；PHPStan退出0（环境原有可选turbo扩展GLIBC加载警告保留），九版API检查均确认268类／接口且签名不变。准确命令及结果见`checks.json`；11条命令全部退出0。`bin/check.sh`语法检查通过。MySQL仅使用控制器拥有的无TCP临时实例，不访问现有业务库。未改SQL语句或表结构，无数据迁移。发行行为与包清单没有改变，本批不重复上一批ZIP消费者门禁，也不把上一批消费者证据算作本批重新安装。

## 兼容与剩余范围

公开API签名不变；告警异常的`getPrevious()`现在为null，是有意的隐私收紧。宿主应依据固定reason及自身受保护的传输监控排障，不依赖SDK暴露原始传输错误。既有容量、授权、租约和重试保护未放宽。

本批没有关闭整个计划。全入口／写入者、容量及维护闭环、通知对账、关联批量操作和自定义提供器余项仍须依照实际依赖逐项推进；暂缓项及真实宿主／外部验收保持未完成。goal维持活跃。

English compatibility note: Audit record sinks reject non-five-field input before allocating the key list. Alert delivery errors keep their fixed reason and retry settlement but no longer expose the transport exception as a previous exception. Public method signatures and database schema remain unchanged. These targeted checks do not establish full-project acceptance.
