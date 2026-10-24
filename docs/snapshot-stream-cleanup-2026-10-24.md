# SQL 快照流式读取的游标清理

2026-10-24。本批修复快照读取的独立错误处理缺口，不涉及暂缓能力。

## 实际问题与修复

两端真实 SQLite 复现：列结构、对象结构、数据行扫描的 closeCursor 返回 false 被忽略，digest 仍返回摘要；SQLite 的 pragma_table_info 同名对象检查没有显式关闭游标。获取／校验与关闭同时失败也没有统一的清理错误。见[PHP7.2修前](snapshot-stream-cleanup-evidence-2026-10-24/php72-reproduce.log)、[PHP8.5修前](snapshot-stream-cleanup-evidence-2026-10-24/php85-reproduce.log)。每端24场景中17项未满足预期，正常读取及单独获取失败记录同时保留。最初测试误用了内存SQLite及遗漏自定义Statement构造函数，预设阶段失败另存，未用这些失败判断产品状态。

仅修改 SqlStateSnapshot：四处显式关闭游标，false／异常均以 sql.cleanup 拒绝，不返回摘要或数据采集结果；成功关闭后才传播原获取／校验错误。保持逐行处理，未改成完整结果集缓冲。SQL、参数、排序、分页、行／字段／内存预算、事务边界、公开API和摘要格式均保持。当前公开清单实际为278类／接口，SDK／SQL367份中其余366份保持。

初版辅助函数接收原始异常作为参数。在开启 zend.exception_ignore_args=0 后，异常转储仍可通过调用参数取得原错误，即使 previous 为 null；新增转储断言在PHP8.5复现16项失败，见[实际失败](snapshot-stream-cleanup-evidence-2026-10-24/php85-private-trace.log)。最终辅助函数仅接收语句；原异常留在调用者，清理完成后才单独传播，不把异常传入清理函数。静态检查原有的shadow可能未初始化诊断也已通过明确初始化及异常路径修正，未忽略诊断或放宽类型。

[最终源码增量](snapshot-stream-cleanup-evidence-2026-10-24/final/source-change.diff)、[最终367份摘要](snapshot-stream-cleanup-evidence-2026-10-24/final/final-inputs.json)、[测试输入摘要](snapshot-stream-cleanup-evidence-2026-10-24/final/test-inputs.json)。兼容变化：原本被忽略的关闭失败现在拒绝，并采用sql.cleanup；正常摘要与公开签名不变。快照仍只在自己完整观察事务内运行，拒绝借用宿主事务；失败后检查事务已退出，数据未变，独立重读正常。

## 当前验证

最终源码已执行并通过：PHP7.2、7.3、7.4、8.0、8.1、8.2、8.3、8.4、8.5的MySQL相关45/45程序；SQLite36/36、API9/9、静态1/1共46/46程序；新增故障与正常场景SQLite648、MySQL162共810项全部通过。PHPStan仍报告本机可选turbo扩展缺GLIBC版本的启动警告，但分析完成且无错误，未修改环境。

实际ZIP离线全新消费者在PHP7.2／8.5运行MySQL10、SQLite8程序共18/18通过（其中新增场景180项），7/7准备与验证步骤通过；367份SDK／SQL摘要与原包一致，四个关键类反射来源均为消费者vendor，不使用源码符号链接。最终各控制器均已正常终止，自己的MySQL及临时资源清理完成。

[最终MySQL主轮](snapshot-stream-cleanup-evidence-2026-10-24/final/matrix.json)、[SQLite／API／静态](snapshot-stream-cleanup-evidence-2026-10-24/final/local-checks.json)、[消费者](snapshot-stream-cleanup-evidence-2026-10-24/final/consumer/consumer.json)、[消费者逐程序](snapshot-stream-cleanup-evidence-2026-10-24/final/consumer/test-rows.json)、[统计范围](snapshot-stream-cleanup-evidence-2026-10-24/final/counts.json)。这是一批定向回归，不能代替全项目或最终稳定版验收。

测试覆盖摘要和数据采集两种入口；SQLite四处读取、MySQL数据行读取；正常、关闭false／异常、获取失败、非法数据及组合故障。开启异常参数记录，检查字符串、var_export、print_r及JSON转储无私有错误；要求每次故障显式关闭一次、无返回值、事务结束、表中数据不变，并能独立正常重读。相关既有测试覆盖完整有界SQL快照、二进制／NULL／空值、超大字段和8MiB约束、数据采集及173行分页。原断言保留。

前一版九版本MySQL45程序通过；本地45程序通过、静态1项失败；消费者18程序通过，但其测试尚未覆盖异常参数泄露，不能作为最终源码通过。全部记录保留在证据目录顶层，最终源码的结果单独位于final子目录。

默认签发预算和最终非暂缓验收仍未完成。本批仅改变游标清理及失败路径，没有为求绿色重复默认流程；最近实际失败仍是[约3.124884秒的account.operation_timeout／current](fixed-variable-format-evidence-2026-10-24/workflow/default-72-timing.json)，未返回凭据，后续操作未执行，不推定当前候选通过。完整check.sh、跨代际worker交接、未知回执续办、最终恢复启用、依赖完整F01及外部验收未执行。goal保持active，不宣称稳定版或全项目验收。保留原环境、数据和全部未提交改动，未提交、推送、部署或修改内部任务数据库；仅清理自己的临时测试资源。
