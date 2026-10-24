# 普通账本写入完成与游标清理

2026-10-24。上一批普通读取清理已完成，本批继续核对同一账本的普通写入，先复现再修改。仅修改`Account\Ledger`和`Support\SqlTransaction`，不新增恢复、交接或未知结果续办能力。

## 实际缺陷与修改

修前PHP7.2和8.5的真实SQLite探针均观察到：记录INSERT的closeCursor返回false一次，Ledger::put仍返回成功，事务committed=true，记录实际保留。见[7.2修前](ledger-write-cleanup-evidence-2026-10-24/before72.log)、[8.5修前](ledger-write-cleanup-evidence-2026-10-24/before85.log)。修后同一8.5探针拒绝返回、committed=false、记录数0，见[修后](ledger-write-cleanup-evidence-2026-10-24/after85.log)。

内部SQL单元新增execute：只接受显式INSERT／UPDATE／DELETE，沿用原query的准入、预算、绑定及只读保护；观察影响行数，并在返回前显式关闭游标。影响行数复用现有SqlSchema::integer规则，规范为非负整数。行数异常、负值或关闭失败均令当前SQL单元不可继续；即使宿主捕获错误，也不能查询或提交。行数异常仍尝试关闭，组合失败优先报告sql.cleanup，原始驱动异常不进入错误链。

普通账本根写入、记录写入、重新签名及显式删除改为该完成方法，原有CAS行数、读回认证、完整历史及正文检查保持。SQL、参数、事务边界、存储格式和预算不变；权威变更方法未修改、未测试。[本批最终增量](ledger-write-cleanup-evidence-2026-10-24/validated-source-change.diff)只有上述两类，其他365份SDK／SQL文件保持。

Ledger和SqlTransaction均在现有internal.json中明确分类为内部类。实际公开清单仍为278类／接口，候选契约未改写；新增方法不是公开候选API扩展。兼容行为变化是普通写入的清理或结果不确定现在拒绝成功，当前SQL单元不可复用；正常返回和持久化内容保持。

## 最终本地验证

| 已执行并通过 | 范围 |
| --- | --- |
| 最终SQLite | 九版每版写清理、读清理、正常值、普通账本四程序，共36/36 |
| 最终MySQL | 同四程序九版，加两端完整原生／自定义／锁组合，共38/38 |
| 新增专项 | 九版两后端18程序、540个故障场景，每程序428断言；六类写入×五类故障，含业务写入与账本整体回滚、捕获后拒绝继续、禁止提交、隐私、零行及只读／非写入拒绝 |
| 正常值 | 九版两后端18程序的检查点／记录摘要一致，也与上一批实际修前对照摘要逐字一致，未重跑旧对照 |
| 全新消费者 | 实际ZIP、离线无脚本／插件安装，367份SDK／SQL逐字核对；两端SQLite／MySQL共20个功能程序、2个来源检查及安装流程通过，资源已清理 |
| API／静态 | 九版API278按初轮四版和补充五版取得通过；最终静态分析通过，27条PHP语法及Shell／Python语法通过 |

证据：[最终SQLite](ledger-write-cleanup-evidence-2026-10-24/validated/local-result.json)、[最终MySQL](ledger-write-cleanup-evidence-2026-10-24/validated/mysql-result.json)、[正常值兼容](ledger-write-cleanup-evidence-2026-10-24/values-compatibility.json)、[最终消费者](ledger-write-cleanup-evidence-2026-10-24/validated-consumer/consumer.json)、[消费者MySQL逐程序](ledger-write-cleanup-evidence-2026-10-24/validated-consumer/test-rows.json)、[API补充](ledger-write-cleanup-evidence-2026-10-24/api-supplement.json)、[最终静态](ledger-write-cleanup-evidence-2026-10-24/validated-static.log)、[367份最终输入](ledger-write-cleanup-evidence-2026-10-24/validated-inputs.json)。

初轮SQLite／API矩阵67/72通过，五版API扫描因运行器把原32MiB预设误设16MiB而耗尽内存；失败保留，仅这五项恢复既定扫描预设后补测通过，未改变SDK保护。初轮MySQL65/65通过。初轮静态两条错误来自PDO注解认定行数已非负，而直接防御检查被判为重复；随后复用已有非负整数验证器，保留负值／异常拒绝。最终对实际改变的写入处理重新执行上述36＋38及消费者20程序，没有把各轮写成一次全绿。

PHPStan启动仍有本机可选turbo扩展要求GLIBC_2.32的警告，分析最终退出0、No errors；原警告保留，未修改运行环境。测试仅使用自建无TCP MySQL及私有SQLite，不代表生产数据库或整个项目验收。新用例及精确MySQL检查选项已登记，未运行包含暂缓链路的完整check.sh。

## 当前默认流程与剩余条件

本次修改后，两端按顺序各运行一次全新隔离正常管理流程，保持原生PDO／SystemClock、原持续时间时钟和正常凭据3000ms预算：

- PHP8.5完整流程84断言通过：首次签发约2.725737秒，随后列表、轮换、替换、撤销、第二次签发、全部撤销及已有对象／容量拒绝均通过。原负面对象实例的独立30000ms配置保持，不能将其宣称为默认3000ms验证。
- PHP7.2在签发前发生mfa.authority依赖异常，最终在见证未知完成分支中止；没有首签计时，签发及后续操作未执行。不能将其记成3000ms签发失败，也不能直接归因为本次修复或时钟。
- 一次新预设的独立诊断仅对证据目录中的FactorAuthority源码副本增加最多四条错误类别／白名单原因／时钟倒退布尔计数；未记录参数或私有消息，SDK源文件未变。该次更早在预设阶段明确发生持续时间时钟倒退，计数为空，未重现原authority异常，因此不能解释原失败。acceptance=false。未再重跑失败或续办未知结果。

证据：[7.2原结果](ledger-write-cleanup-evidence-2026-10-24/default-72/default-72-result.json)、[7.2原日志](ledger-write-cleanup-evidence-2026-10-24/default-72/default-72-run.log)、[8.5结果](ledger-write-cleanup-evidence-2026-10-24/default-85/default-85-result.json)、[8.5首签计时](ledger-write-cleanup-evidence-2026-10-24/default-85/default-85-timing.json)、[8.5完整日志](ledger-write-cleanup-evidence-2026-10-24/default-85/default-85-run.log)、[诊断结果](ledger-write-cleanup-evidence-2026-10-24/diagnostic-72/default-72-result.json)、[诊断类别](ledger-write-cleanup-evidence-2026-10-24/diagnostic-72/faults.json)。所有入口摘要保持、自建临时入口已清理。

其他七版默认完整流程本批未执行；较早九版2/9结果有独立准确输入，不能拼成当前候选九版通过。默认稳定预算缺口、PHP7.2时钟与未解释依赖失败、最终非暂缓整合仍开放。真实IdP／设备、生产代理／WAF及外部投递未验收；跨代交接、未知续办、最终恢复启用及其依赖的完整F01继续暂缓。goal保持active，未标记整个目标或稳定版完成；没有提交、推送或部署。
