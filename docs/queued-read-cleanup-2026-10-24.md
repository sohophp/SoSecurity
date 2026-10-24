# 事务发件箱与幂等服务的普通读取清理

2026-10-24。继续补齐非暂缓范围，先复现再修复；没有执行跨代交接、未知回执续办、最终恢复启用及完整F01。

## 根、历史、记录、正文与初始化

PHP7.2／8.5原始初始化读取根记录时未显式关闭游标，测试设置的关闭失败未被观察，仍返回成功并写入根。修后关闭失败返回sql.cleanup，根保持为空。证据：[修前7.2](queued-read-cleanup-evidence-2026-10-24/before72.log)、[修前8.5](queued-read-cleanup-evidence-2026-10-24/before85.log)、[修后](queued-read-cleanup-evidence-2026-10-24/after85.log)。

SqlOutbox／SqlExecutor共享的普通根、完整历史、记录、正文和初始化孤儿检查接入已有SQL单元的metadataRows，由拥有该语句的单元消费并检查关闭，失败后拒绝继续使用。六处单行SQL显式LIMIT 1，锁、字段投影、HMAC、CAS、权限及事务边界保持。准确首次领取的前序检查也观察关闭结果；通用过期租约领取和未知处置分支未修改。

新增测试每个后端每版30场景、341断言，包括26个关闭false／异常及4个正常／撤权场景。验证根和记录不变、业务处理不重做、不返回正文、SQL单元拒绝继续、完整SDK异常链不泄露私有消息及事务退出。只使用普通首次入队／首次领取和已完成幂等结果查询。

当前第一阶段SQLite／API九版54/54通过；全新归档离线安装7步、两端两后端16个功能程序通过，367份SDK／SQL与来源核对一致且自身资源清理完成。MySQL九版45/45通过，共540个新增场景（468故障、72正常／撤权）。[MySQL终态](queued-read-cleanup-evidence-2026-10-24/mysql-result.json)及[交付核对](queued-read-cleanup-evidence-2026-10-24/delivery.json)保留。PHP语法27项、Python／Shell语法及静态分析通过；静态工具保留可选turbo扩展GLIBC_2.32启动警告，最终No errors，未修改环境。

证据：[SQLite／API](queued-read-cleanup-evidence-2026-10-24/local-result.json)、[消费者](queued-read-cleanup-evidence-2026-10-24/consumer/consumer.json)、[源码增量](queued-read-cleanup-evidence-2026-10-24/source-change.diff)、[第一阶段输入](queued-read-cleanup-evidence-2026-10-24/final-inputs.json)、[语法](queued-read-cleanup-evidence-2026-10-24/syntax.json)、[静态](queued-read-cleanup-evidence-2026-10-24/static.log)。

本批不把专项称为全项目或稳定版验收。默认预算、PHP7.2历史时钟／依赖错误及最终非暂缓整合仍开放；[八表分组原型](snapshot-budget-eight-2026-10-24.md)未达到预设标准，未采用。API实际278类／接口，不改历史候选契约；存储格式、输入／内存／时间预算保持。没有提交、推送、部署、生产数据库访问或外部投递，goal保持active。

## 普通分页的后续修复

进一步在PHP7.2／8.5复现四处普通分页遗漏关闭：候选页、发件箱维护页、仅密钥重新签名页及幂等维护页。修前均返回成功，显式关闭次数0；修后均一次关闭即sql.cleanup拒绝。SqlOutbox新增私有pageKeys，保留逐行键检查，缺失投影列不得静默缩短页面；SqlExecutor的普通维护页使用同一已有元数据通道。SQL／绑定／排序／LIMIT／锁均保持，未改过期租约领取、未知处置或受保护管理目标生成分支。

新增每版每后端24场景、237断言，16个故障覆盖四入口的空页／有记录页及false／异常，8个正常／撤权检查保留原状态。测试原始版本的16个预期失败及三处管理权限预设错误留证；纠正为撤销相应管理权限，没有放宽产品规则。另以独立普通测试核对两页实际密钥重新签名、淘汰旧密钥后的读取及已完成幂等正文到期压缩，完全不进行交接或未知回执续办。

九版SQLite／API36/36通过。MySQL九版26/27程序通过；PHP7.2已确认消息清理的commit-deny场景遭遇真实持续时间时钟倒退（sql.timeout），只取得11/12场景通过，失败原样保留，未重跑覆盖。新增分页18个程序全部通过，共432场景；同候选读取回归另540场景通过。默认流程已完成本轮执行，结果见下节。归档消费者12个功能程序均通过，但原外层7步只有6步成功：新增测试分派缺少continue，随后误调用另一个入口，严格运行器拒绝。原日志保留；只修复分派并单独验证控制器，不重跑已经通过的功能程序。普通行为补充两端两后端4个程序均通过；其MySQL外层也受同一分派错误影响，不写成原控制器成功。

证据：[两端修前](queued-page-cleanup-evidence-2026-10-24/before72.log)、[修后](queued-page-cleanup-evidence-2026-10-24/after85.log)、[SQLite／API](queued-page-cleanup-evidence-2026-10-24/local-result.json)、[消费者原终态](queued-page-cleanup-evidence-2026-10-24/consumer/consumer.json)、[消费者MySQL程序](queued-page-cleanup-evidence-2026-10-24/consumer/test-rows.json)、[分派修正](queued-page-cleanup-evidence-2026-10-24/controller-correction.json)、[普通MySQL行为](queued-page-cleanup-evidence-2026-10-24/ordinary-mysql-result.json)、[增量](queued-page-cleanup-evidence-2026-10-24/source-change.diff)、[本轮输入](queued-page-cleanup-evidence-2026-10-24/final-inputs.json)。第一阶段源码及结果单独冻结，后续结果不能倒填为此前候选通过。


[第二阶段交付核对](queued-page-cleanup-evidence-2026-10-24/delivery.json)确认：36/36 SQLite／API、26/27 MySQL、12/12消费者功能程序、6/7原消费者外层步骤；[修正后的分派专项](queued-page-cleanup-evidence-2026-10-24/controller-dispatch.json)通过，未重执行已通过功能程序。[最终静态](queued-page-cleanup-evidence-2026-10-24/static.log)及27项PHP语法通过。两阶段实际SDK只改同两类，当前公开API仍278，367份运行输入保持；最终候选972个新增读取／分页场景通过，不能据此覆盖另一项时钟失败或宣布整轮通过。

## 当前源码的默认管理流程

在其他测试全部终止并完成自身资源清理后，串行运行九版，每版一个全新私有测试环境。主凭据保持实际SystemClock、原生PDO及默认3000毫秒；失败立即停止该环境，不续办未知结果，不运行恢复或交接。原有对象拒绝测试仍使用30000毫秒专用预设，不将其称为默认预算验收。

| PHP | 首次签发秒数 | 当前流程结果 |
| --- | ---: | --- |
| 7.2 | 3.051746 | api_credentials.timeout；后续未执行 |
| 7.3 | 3.066291 | api_credentials.timeout；后续未执行 |
| 7.4 | 3.048865 | api_credentials.timeout；后续未执行 |
| 8.0 | 3.034668 | account.operation_timeout；后续未执行 |
| 8.1 | 3.033181 | api_credentials.timeout；后续未执行 |
| 8.2 | 3.453253 | account.operation_timeout；后续未执行 |
| 8.3 | 3.038181 | api_credentials.timeout；后续未执行 |
| 8.4 | 2.641887 | 完整普通管理通过（84断言） |
| 8.5 | 2.916133 | 完整普通管理通过（84断言） |

只有8.4／8.5两版完成查询、轮换、替换、撤销、再次签发及全部撤销；其余七版首次签发失败，状态检查均为current，没有返回凭据。控制器终态退出1，不写成九版整轮通过。原PHP7.2时钟倒退及此前未解释依赖失败各自保留，本轮超时不解释或覆盖它们。

证据：[预定范围](default-queued-final-evidence-2026-10-24/scope.json)、[九版终态](default-queued-final-evidence-2026-10-24/summary.json)。本轮SDK与SQL367份输入摘要始终一致，自建临时资源清理完成。默认性能及最终非暂缓整合仍未完成；真实IdP／设备、生产代理／WAF、外部投递及独立外部验收不在本地通过结论内，未定义OIDC关联迁移按用户授权跳过。跨代交接、未知回执续办、最终恢复启用和完整F01保持暂缓，goal继续active，不宣称稳定版完成。
