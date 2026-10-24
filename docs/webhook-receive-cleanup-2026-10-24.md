# Webhook普通接收的语句完成与准入观察清理

2026-10-24。继续修复现有普通接收路径，没有实现或测试未知回执续办、跨安全代际交接或最终恢复启用。

## 修前证据与实际修改

PHP7.2／8.5均实际复现两项写入关闭返回false仍返回Receipt并提交1条接收记录；两项读取没有显式关闭，关闭探针命中0次，仍返回Receipt。不能把这两项读取写成已观察到false。修后四处都显式关闭一次，以webhook.inbox_cleanup拒绝，不返回回执，新增记录回滚为0条。

证据：[修前7.2](webhook-receive-cleanup-evidence-2026-10-24/before72.log)、[修前8.5](webhook-receive-cleanup-evidence-2026-10-24/before85.log)、[修后](webhook-receive-cleanup-evidence-2026-10-24/after85.log)。

SDK仅修改SqlInbox：普通接收的插入、元数据读回、更新、正文一致性检查和MySQL元数据锁读取检查关闭。写入还检查rowCount异常、负数及不可能的过大值；保留重复插入／同值UPDATE合法零行，以原有HMAC、身份、正文及最终读回验证成功，未一律要求1行。失败结果或关闭不确定会标记当前接收器不可复用；再次accept在密钥回调前拒绝。

读取错误先捕获，关闭后再抛出，避免组合故障把私有驱动错误接入清理异常链。原生接收的只读准入提取为私有observation方法，使用现有SQL单元metadataRows并检查唯一聚合整数；关闭不确定也使接收器拒绝继续，普通只读失败保留原SQL单元的sql.unavailable。该方法不执行映射、业务操作或未知续办。两处主键元数据SQL显式LIMIT 1；其余绑定、锁、期限交集、事务归属、签名与关联回调和提交／完成阶段复核保持。

存储格式、输入／正文／时间预算和公开API278类／接口保持，候选契约未改。共享InboxSchema和处理器不是本批修改范围，不能由本专项关闭其全部复核。见[源码增量](webhook-receive-cleanup-evidence-2026-10-24/source-change.diff)和[冻结输入](webhook-receive-cleanup-evidence-2026-10-24/final-inputs.json)。

## 九版本覆盖及原失败

每个SQLite程序49场景、593断言，每个MySQL程序51场景、621断言；MySQL另覆盖两种元数据锁读取关闭故障。九版累计900场景，其中738个关闭／读取／结果故障、162个正常／撤权场景取得通过。覆盖首次接收、只对已确认成功回执进行重复接收、实际INSERT忽略／UPDATE同值零行、无映射／坏签名／关联拒绝、提交前撤权、证明到期回滚、只读观察空／有记录／容量、私有错误消息及SDK异常链、失败接收器快速拒绝。

原批次SQLite／API15/18、MySQL6/9：PHP8.0—8.5功能及九版API通过，PHP7.2—7.4模拟对象在声明时中止，没有执行场景。最初PHP8.5缺失PDO返回类型兼容声明；其后4处期望错误地使用普通接收错误码，而原生观察实际使用SQL单元的sql.unavailable，均保留日志与初始源码。随后一次仅改默认参数的旧版声明修正仍失败，也没有执行场景。

最小声明探针以E_ALL和异常化错误处理核实：旧PDO要求显式保留fetchAll三个可选参数槽位，之后才能接可变参数；最终声明九版本通过。修正只涉及测试声明与参数转发，没有修改生产代码或断言、没有降低错误报告。只补执行此前未执行的PHP7.2—7.4两后端6个程序，全部通过；已通过的PHP8.0—8.5结果按相同SDK367份摘要复用，所覆盖fetch模式均显式传入，转发参数及断言保持。[最终测试差异](webhook-receive-cleanup-evidence-2026-10-24/final-test-declaration-change.diff)由收集器按允许的两处方法差异逐字核对。

证据：[初轮PHP8.5声明错误](webhook-receive-cleanup-evidence-2026-10-24/first85.log)、[兼容后首轮4个期望失败](webhook-receive-cleanup-evidence-2026-10-24/first85-compatible.log)、[错误码更正](webhook-receive-cleanup-evidence-2026-10-24/test-expectation-correction.json)、[原SQLite／API](webhook-receive-cleanup-evidence-2026-10-24/local-result.json)、[原MySQL](webhook-receive-cleanup-evidence-2026-10-24/mysql-result.json)、[未奏效的声明修正](webhook-receive-cleanup-evidence-2026-10-24/legacy/local-result.json)、[最终旧版声明核对](webhook-receive-cleanup-evidence-2026-10-24/legacy-signature-correction.json)、[九版声明探针](webhook-receive-cleanup-evidence-2026-10-24/signature-results.json)、[旧版SQLite补充](webhook-receive-cleanup-evidence-2026-10-24/legacy-final/local-result.json)、[旧版MySQL补充](webhook-receive-cleanup-evidence-2026-10-24/legacy-final/mysql-result.json)。不把原批次改写为全绿。

## 原生组合、重签名与发行

直接执行未改的fresh-webhook-shared.php，两端两后端4/4程序、每程序25断言通过，覆盖真实StateWebhookConnection接收、初始空权威、新账号、工厂登录／会话／撤销。这里只做首次工作进程根初始化及全新账号激活，不执行恢复账号启用、旧代交接或处理器未知状态续办。另对已确认回执进行完整密钥重签名、淘汰旧密钥后读取，两端两后端4个程序、每程序7断言通过。

实际ZIP与离线全新消费者核对367份SDK／SQL、安装来源及无符号链接。原消费者5/7外层步骤，PHP8.5两后端功能通过，PHP7.2因测试声明错误在场景前失败。修正后新建PHP7.2消费者，两后端功能及5个所选步骤全部成功；其控制器误沿用双端点7步计数而退出1。已只修复该计数，并独立核对既有终态，不重跑已经成功的功能，不将原退出码写成0。覆盖两端两后端4个消费者功能程序，原失败完整保留。

证据：[原生SQLite](webhook-receive-cleanup-evidence-2026-10-24/native-sqlite-result.json)、[原生MySQL](webhook-receive-cleanup-evidence-2026-10-24/native-mysql-result.json)、[重签名MySQL](webhook-receive-cleanup-evidence-2026-10-24/rotation-mysql-result.json)、[原消费者](webhook-receive-cleanup-evidence-2026-10-24/consumer/consumer.json)、[最终PHP7.2消费者](webhook-receive-cleanup-evidence-2026-10-24/consumer72-final/consumer.json)、[消费者计数修正](webhook-receive-cleanup-evidence-2026-10-24/consumer-count-correction.json)、[交付核对](webhook-receive-cleanup-evidence-2026-10-24/delivery.json)、[最终18项PHP语法](webhook-receive-cleanup-evidence-2026-10-24/syntax-final.json)、[静态](webhook-receive-cleanup-evidence-2026-10-24/static.log)。Python／Shell语法通过，静态最终No errors，保留可选turbo扩展GLIBC_2.32启动警告，未修改环境。所有测试仅使用自建私有SQLite、无TCP MySQL和自身临时资源，清理终态已核对。

## 尚未关闭

没有运行含未知结果路径的完整webhook-inbox.php、处理器套件或check.sh。本批没有重复默认凭据管理流程；[上批SQL审计](audit-sql-cleanup-2026-10-24.md)的第二次签发完成未知失败仍保留，不作当前候选通过。默认性能、PHP7.2历史时钟与未解释依赖失败、共享检查复核及最终非暂缓整合仍开放，goal保持active；本专项不是全项目或稳定版验收。

跨代交接、未知回执续办、最终恢复启用及完整F01保持暂缓；未定义OIDC关联迁移按授权跳过，真实IdP／设备、生产代理／WAF及外部投递未验收。既有环境、数据和其他未提交改动保留，未提交／推送／部署，未访问生产数据库。
