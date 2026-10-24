# 普通账本读取游标清理

2026-10-24。本批先完成[默认九版本流程固定快照验证](default-frozen-2026-10-24.md)，确认完整流程只有PHP8.4／8.5通过，七版失败仍保留。随后独立复现并修复普通账本读取的游标清理遗漏，没有扩大到暂缓的交接、未知续办或恢复启用。

## 问题与修复

修前PHP7.2和8.5均实际读取根记录、返回检查点，但没有调用显式closeCursor；测试预置的关闭失败因此根本没有被观察。见[7.2修前探针](ledger-read-cleanup-evidence-2026-10-24/before72-final.log)、[8.5修前探针](ledger-read-cleanup-evidence-2026-10-24/before85-final.log)。原探针的PHP7.2方法签名警告和首个失败断言另行保留，没有覆盖成通过。

仅修改`Account\Ledger`一类：根记录、历史页、记录元数据、正文、最近记录、管理页、完整正文检查和孤立历史探测统一走现有SqlTransaction::metadataRows。这个通道显式检查关闭false／异常并将SQL单元标为不可继续，宿主捕获错误也不能随后查询或提交。异常不携带原始关闭错误。原生MySQL已使用该通道的合并首屏保持。

单行读取统一获取结果后，最终候选额外在根记录、精确记录和精确正文SQL中明确`LIMIT 1`，防止把主键约束当作物化结果的资源预算；最近记录及孤立探测原本已有LIMIT，历史和管理页上限保持。私有单行辅助方法仍拒绝异常的多行结果。见[本批最终源码增量](ledger-read-cleanup-evidence-2026-10-24/bounded-source-change.diff)。初轮未加三处LIMIT的结果单独保留，不能冒充最终候选。

正常返回结构、签名认证、完整历史检查、时间及输入限制、权限复核、锁与事务归属、DDL、存储格式和默认预算保持。公开清单仍为278类／接口，没有公开签名变更。兼容行为变化是：读取游标清理不确定现在返回sql.cleanup，当前SQL单元不可再用；不再返回检查点或数据。

## 本地结果

- 最终九版SQLite／API矩阵54/54通过；最终MySQL矩阵46/47通过。PHP7.2账本组合测试在callback-write场景预设阶段检测到持续时间时钟倒退；原失败保留，未重跑该场景。它之前的13个组合场景通过，后续6个场景未执行。
- 新增关闭失败专项在九版SQLite和MySQL均通过：18程序、252场景，每程序168断言，覆盖关闭false／抛私有异常、捕获后拒绝继续、禁止提交、原状态保持，以及实际SQL读取上限。
- 正常返回值专项九版两后端18程序通过，另以修前源码在两端两后端运行4个对照；22个程序的实际检查点／记录摘要完全一致。覆盖完整正文检查、正文页、批量读取、最近记录、空页、未初始化及容量观察，均使用8MiB限制。没有调用权威变更方法。
- 最终实际ZIP和离线全新消费者12个SQLite／MySQL功能程序、2个源码来源检查及归档／安装流程通过。367份SDK／SQL摘要完全一致，没有符号链接；12个功能程序不等同于全项目验收。自建临时资源已清理。
- 静态分析最终退出0、No errors；工具启动时仍有本机可选PHPStan turbo扩展要求GLIBC_2.32的警告，原日志保留，未修改环境来掩盖。Shell／Python语法另行检查。

证据：[最终SQLite／API](ledger-read-cleanup-evidence-2026-10-24/bounded/local-result.json)、[最终MySQL](ledger-read-cleanup-evidence-2026-10-24/bounded/mysql-result.json)、[正常值及修前对照](ledger-read-cleanup-evidence-2026-10-24/bounded-values/values-result.json)、[消费者](ledger-read-cleanup-evidence-2026-10-24/bounded-consumer/consumer.json)、[消费者MySQL逐程序](ledger-read-cleanup-evidence-2026-10-24/bounded-consumer/test-rows.json)、[静态日志](ledger-read-cleanup-evidence-2026-10-24/bounded-static.log)、[最终367份输入](ledger-read-cleanup-evidence-2026-10-24/bounded-inputs.json)。初轮108程序通过和22个值对照保存在同一证据目录的原始文件中；补充LIMIT后重新取得上述结果，没有混写成原批次全绿。

仅补验原中断之后未执行的6个PHP7.2兼容场景，6/6通过；分别为自定义时钟、PDO适配、语句适配、不透明守卫及两种锁行为。[独立补充结果](ledger-read-cleanup-evidence-2026-10-24/missing/result.json)保留实际退出与清理记录。没有重跑已经通过的13个组合场景，也没有将失败的callback-write场景补写为通过。

新增用例及两个精确MySQL选项已加入本地检查入口，本批没有运行包含暂缓功能的完整check.sh。SDK其他366份输入保持；没有提交、推送、部署、访问生产数据库或外部投递，只清理本次创建的资源。

默认预算缺口、历史时钟倒退和最终非暂缓组合验收仍未关闭。默认九版流程结果绑定本批修复前的准确输入，不能称为当前最终候选的整轮结果；本批没有再次运行它覆盖失败。真实IdP／设备、生产代理／WAF及外部环境仍未验收；跨代交接、未知续办、最终恢复启用和依赖它们的完整F01仍暂缓。goal保持active，不能标记稳定版或整个目标完成。
