# 原生快照先锁定结构，再复核完整列权限

2026-10-24。本批继续处理默认MySQL凭据签发预算，不涉及暂缓功能。

## 修前依据与实现

对当时实际源码做了一次原生方法计数采样：1302次元数据读取，SqlStateSnapshot::mysqlSchemas调用120次、累计约0.541秒。采样首次签发约3.233秒超时，current、未返回凭据，只诊断首次调用，不续办或执行后续。插入计数的代码不是发行候选，不能当作性能验收。见[方法开销](native-current-cost-evidence-2026-10-24/cost.json)、[计时](native-current-cost-evidence-2026-10-24/default-85-timing.json)、[输入摘要](native-current-cost-evidence-2026-10-24/default-85-inputs.json)。

两端实际预设确认每组每次快照读取两次完整目录。新增次数断言修前均得到2而非1：[PHP7.2](snapshot-locked-schema-evidence-2026-10-24/php72-locked.log)、[PHP8.5](snapshot-locked-schema-evidence-2026-10-24/php85-locked.log)。修前程序原逐程序记录及控制器／PHP日志保留；主轮控制器复用了matrix.json汇总路径，原汇总被覆盖，另据未覆盖的matrix-rows.json生成[派生索引](snapshot-locked-schema-evidence-2026-10-24/probe-before-derived.json)，不把派生文件当原始回执。最初预验证脚本生成时匹配失败，尚未执行产品，另存启动失败日志。

仅修改SqlStateSnapshot。严格原生、SystemClock及纯守卫路径先执行原有零行双别名访问，取得真实表的元数据锁后才读取完整目录；结构验证、数据扫描都在同一完整观察事务内。最后改为新准备的零行访问，明确引用每张表的全部声明列。它重新检查当前列读取权限，不能用SELECT 1替代，也不进入语句池。临时表的双别名拒绝保持。元数据锁阻止结构变更；外部权限变化不会被缓存的结构证明替代。

自定义PDO、Statement或非纯守卫保留原来两次目录观察及逐表解析，宿主事务仍被快照拒绝。未缓存跨快照的结构、行值或授权；SQL参数、行／字段／分页／内存预算、摘要格式和默认3000ms预算保持。SDK／SQL367份中仅此内部类改变，其余366份保持；公开API实际278类／接口，没有增加公开签名或调整候选契约。

[源码增量](snapshot-locked-schema-evidence-2026-10-24/source-change.diff)、[最终运行摘要](snapshot-locked-schema-evidence-2026-10-24/final-inputs.json)、[测试输入](snapshot-locked-schema-evidence-2026-10-24/test-inputs.json)。现有语句池测试仅按新行为将原生两次digest的完整目录执行次数4改为2，未注册连接准备次数4改为2；自定义路径原4次和全部当前数据、权限、错误清理断言保持。原测试副本保留。

## 已执行的本地验证

新增14场景覆盖1—5张表分组、原生目录次数、自定义依赖降级、事前／事后撤销单列及全部列读取权限、临时表、目录读取前的真实DDL阻塞、完整列访问关闭false／异常。两端预验证6程序全部通过，九版主轮68程序67通过、1项PHP7.2游标测试时限失败。新增14×9共126场景全部通过，已有双端四表DDL锁测试也通过。SQLite36／API9／静态1共46/46通过。PHPStan可选turbo扩展仍有本机GLIBC启动警告，实际分析无错误，没有改环境。

主轮PHP7.2的capture/rows/fetch原期望sql.unavailable，实际sql.timeout，完整原日志保留；同源码、同测试的全新消费者PHP7.2该18场景通过，作为独立覆盖，不把主轮改写成全绿。消费者实际ZIP／离线全新安装共24程序23通过、1项PHP7.2池测试在fetch-close场景遇持续时间时钟倒退；之前17场景及其余15个MySQL、8个SQLite程序通过，步骤6/7。该场景的主仓两端预验证与其余七版均通过，但消费者失败仍不关闭。未延长预算、替换时钟、删断言或重复跑整套求绿。

[主轮](snapshot-locked-schema-evidence-2026-10-24/matrix.json)、[两端预验证](snapshot-locked-schema-evidence-2026-10-24/probe-after.json)、[SQLite／API／静态](snapshot-locked-schema-evidence-2026-10-24/local-checks.json)、[消费者](snapshot-locked-schema-evidence-2026-10-24/consumer/consumer.json)、[消费者逐程序](snapshot-locked-schema-evidence-2026-10-24/consumer/test-rows.json)、[范围统计](snapshot-locked-schema-evidence-2026-10-24/counts.json)。消费者367份SDK／SQL摘要及四个关键类vendor反射来源核对通过，没有使用源码符号链接，自身临时资源清理完成。

另外在同一自建MySQL上加载本批修改前的快照类副本（仅改类名以并存），对1—5表、空表／二进制与NULL和空值／二进制过滤三类状态，比较修改前后的真实fingerprint和digest。两端30场景全部相同，见[兼容验证](snapshot-locked-schema-evidence-2026-10-24/compat.json)。该项仅比较摘要，不将旧类当作消费者实现。

补充验证新增加的完整列访问宽度：两端原生PDO在4表×64列、64字节列名及实际数据下连续生成相同摘要，峰值分别4MiB／2MiB，原8MiB限制保持，见[宽度边界](snapshot-locked-schema-evidence-2026-10-24/width-fixed.json)。最初补充脚本中的命名空间转义错误在进入SDK前失败，保留原脚本和日志；只修正该预设后验证，没有变更SDK或增加预算。该补充在默认流程之后执行。

## 默认流程与剩余事项

上述主轮、兼容与消费者程序结束后，串行执行一次实际PDO／SystemClock／纯来源守卫／策略提示1／原3000ms预算的PHP8.5正常管理流程，未加载方法计数副本。首次签发约2.883595秒成功，实际凭据、审计记录和current见证均通过；随后的查询、轮换（generation2）、替换（generation3）、撤销断言也通过。之后同一正常流程中的第二次issue在管理会话复核处报告api_credentials.identity_unavailable，并被边界以account.completion_unknown停止；完整流程退出1，未执行后续revokeAll、对象拒绝或容量拒绝场景，没有续办、重试或最终恢复。最终见证状态未另行采集，计时中的current仅属于首次签发完成时，不混用于后续失败。

[首次签发计时](snapshot-locked-schema-evidence-2026-10-24/workflow/default-85-timing.json)、[完整流程结果](snapshot-locked-schema-evidence-2026-10-24/workflow/default-85-result.json)、[失败堆栈](snapshot-locked-schema-evidence-2026-10-24/workflow/default-85-run.log)、[失败行定位](snapshot-locked-schema-evidence-2026-10-24/workflow/failure-location.json)。按生成脚本的原文定位，失败行63的唯一issue位于轮换／替换／撤销之后；该定位只解析字符串，没有执行PHP。自己的测试环境已清理，全部输入摘要保持。

本批其他八版默认流程未重复执行；不能用一次首次签发成功证明稳定性能，也不能将第二次签发失败改写为完整正常管理通过。正常摘要经实际兼容对比保持；无权限／缺表等非法输入可能在提前的物理解析处拒绝，错误先后及原因可能与原先先读目录时不同。

完整check.sh、跨代际worker交接、未知回执续办、最终恢复启用、依赖完整F01及外部验收未执行。最终非暂缓候选验收仍未完成，goal保持active。保留全部原环境、数据、未提交改动、失败及审批记录；未提交、推送、部署或更改内部任务数据库，只清理自己创建的测试进程和临时资源。
