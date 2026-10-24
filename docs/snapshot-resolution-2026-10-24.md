# SQL快照组内名称解析与关闭失败处理

2026-10-24。本批根据当前原生路径的方法画像定位重复数据库往返，并确认名称解析语句忽略closeCursor返回false的问题。实际只修改SqlStateSnapshot，保留既有环境、数据、源码及未提交改动；goal保持active，不是稳定版或全项目验收。

## 定位与修前证据

临时计时副本保持实际PDO、PDOStatement、SystemClock及原3000ms预算，原生账本资格为true；只记录固定方法名、调用数和包含／排除子调用的时间，不记录参数、SQL文本、账号或凭据。未修改SDK文件。约3.004秒时返回account.completion_unknown，pending，未续办；这是一份有额外计时开销的截断画像，不是性能验收。

记录到SqlStateAccess::metadataRows共1106次，排除已计时子调用后约1.594秒；SqlTransaction::query575次约0.355秒，witness933次约0.269秒，now9872次约0.128秒。各方法的包含子调用时间不能相加。SqlStateSnapshot::mysqlSchemas执行96次；每组最多4张表仍逐表执行零行物理名称解析。见[画像摘要](native-cost-evidence-2026-10-24/summary.json)、[方法数据](native-cost-evidence-2026-10-24/cost.json)、[原生资格与失败](native-cost-evidence-2026-10-24/default-85-timing.json)、[来源清单](native-cost-evidence-2026-10-24/inputs.json)。首次诊断启动器引号错误导致Python语法失败，尚未执行产品调用；修正后单独采集，原始错误日志保留。

修前两端均确认：解析语句关闭返回false时，SDK仍返回摘要；关闭抛出异常时原实现已拒绝，但映射为sql.unavailable。后者不是“旧实现错误放行”的证据。见[修正预设后的复现](snapshot-resolution-evidence-2026-10-24/probe-corrected.json)、[PHP7.2日志](snapshot-resolution-evidence-2026-10-24/php72-corrected-resolution.log)、[PHP8.5日志](snapshot-resolution-evidence-2026-10-24/php85-corrected-resolution.log)。

最初预设使用服务器默认认证插件，PHP7.2不支持，另有BIGINT返回整数／字符串及PDO属性0／false的测试预期差异。已改为测试框架同用的mysql_native_password私有测试用户，并规范化测试比较；没有改变SDK连接策略、服务器全局设置或放宽权限检查。初始失败保留，PHP7.2修前group模式的0／false断言失败不计为产品缺陷。

## 实际修复

同一组内超过一张表且满足严格原生门槛时，用一条零行SELECT解析所有表，每张表仍有两个独立别名。每次仍实际解析并检查访问，不缓存结果、元数据或授权。查询输出必须为空；完整获取和关闭统一经过SqlTransaction::metadataRows，关闭返回false或抛出异常均以sql.cleanup拒绝，停止业务行读取。

自定义PDO、Statement或非纯入口守卫继续逐表执行，保留原有观察和回调机会；单表仍保留原解析SQL，只增加受控清理。原生门槛包括准确PDO／Statement类型、原生预处理、异常模式、SystemClock、自然列名及纯入口守卫。原有表名检查、最多4表、双别名遮蔽保护、事务见证、期限及清理失败传播保持。

[源码增量](snapshot-resolution-evidence-2026-10-24/source-change.diff)仅涉及MySQL结构采集后的名称解析；摘要输入、字段／行／页预算、持久格式、DDL和公开签名不变。公开API实际278类／接口；[367份最终摘要](snapshot-resolution-evidence-2026-10-24/final-inputs.json)中仅SqlStateSnapshot相对于本批开始变化，其余366份保持。兼容变化是过去忽略的关闭false现在拒绝，关闭异常明确归类sql.cleanup；不会自动重试或放宽保护。

## 验证结果

| 已执行并通过 | 范围 |
| --- | --- |
| 九版主轮 | PHP7.2、7.3、7.4、8.0—8.5，共63/63程序；含每版14个新增解析场景、此前8个数据库上下文场景及五类既有MySQL快照回归 |
| 兼容补测 | 九版自定义PDO、Statement、入口守卫各一个独立程序，共27/27；保留逐表路径，自定义Statement四表前后共8次关闭 |
| 元数据锁 | PHP7.2／8.5各一程序；通过真实生产解析方法和原生只读观察事务，独立连接对4表分别ALTER均因元数据锁超时，数据及摘要保持 |
| SQLite／API／静态 | 九版五类SQLite回归45程序、API9程序及静态1程序，共55/55 |
| 归档全新消费者 | 实际ZIP与离线安装，不使用符号链接；两端14个MySQL、10个SQLite程序共24/24，流程7/7，反射来源及367份摘要核对通过，自建资源已清理 |

本批新增场景为九版17项合计153项，加两端元数据锁2项，共155项；中间七版未单独运行元数据锁并发用例。九版主轮及兼容补测按各自测试源文件保留，不把不同脚本版本伪装成一次完整套件。

证据：[主轮](snapshot-resolution-evidence-2026-10-24/matrix.json)、[兼容补测](snapshot-resolution-evidence-2026-10-24/compat.json)、[锁验证](snapshot-resolution-evidence-2026-10-24/mdl.json)、[SQLite／API／静态](snapshot-resolution-evidence-2026-10-24/local-checks.json)、[消费者](snapshot-resolution-evidence-2026-10-24/consumer/consumer.json)、[消费者逐程序记录](snapshot-resolution-evidence-2026-10-24/consumer/test-rows.json)。MySQL仅使用本地自建无TCP实例，未访问生产数据库。只清理自己的测试表、用户、进程和临时目录。

两端固定计数方法下，1／2／3／4表的Com_stmt_prepare增量从11／14／17／20变为11／12／13／14，净减少0／2／4／6次。增量包含相同的状态读取开销，不等于完整请求的SQL条数；不能由此直接推导端到端耗时收益。见[预处理计数对照](snapshot-resolution-evidence-2026-10-24/prepare-comparison.json)。

## 默认流程与剩余范围

所有功能测试、消费者和锁检查结束后，串行检查一次PHP8.5默认正常管理流程，使用新测试预设、实际SystemClock／PDO、纯来源守卫、策略提示1及原3000ms预算。首次签发约3.019248秒以api_credentials.timeout拒绝，见证current，未返回凭据。堆栈到auditCurrent中credentialPair完成后的预算检查；后续查询、轮换、替换、撤销及拒绝场景未执行，未重试或续办。见[计时](snapshot-resolution-evidence-2026-10-24/workflow/default-85-timing.json)、[运行结果](snapshot-resolution-evidence-2026-10-24/workflow/default-85-result.json)、[失败堆栈](snapshot-resolution-evidence-2026-10-24/workflow/default-85-run.log)。本批其他八版默认流程未重复执行。

默认预算仍未稳定通过，最终非暂缓候选验收未完成；历史PHP7.2时钟及其他失败保留。跨安全代际工作进程交接、未知回执续办、最终账号恢复启用、依赖完整F01及外部验收未执行。未运行完整check.sh，不把专项称为全项目验收。goal保持active；未提交、推送、部署、改动内部任务数据库或清理其他任务资源。
