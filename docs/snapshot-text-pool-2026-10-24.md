# 旧驱动固定快照元数据语句复用

2026-10-24。本批修复无法读取STRINGIFY_FETCHES的原生PDO驱动反复准备同一快照元数据语句的性能缺口。保留当前环境、数据及未提交改动；没有放宽预算、连接模式、权限或隔离要求，goal继续active。

## 修前确认

先用真实SDK、实际PDO和新建的四表快照观察两次完整摘要。PHP7.2的元数据执行4次、准备4次，STRINGIFY_FETCHES getter不可用；PHP8.5执行4次、准备1次，getter可用。后者本来已经复用，不能把裸SQL原型的性能差值当作PHP8.5产品收益。见[修前SDK核对](snapshot-pool-prototype-evidence-2026-10-24/sdk.json)、[PHP7.2观察](snapshot-pool-prototype-evidence-2026-10-24/php72-sdk.log)、[PHP8.5观察](snapshot-pool-prototype-evidence-2026-10-24/php85-sdk.log)。

原型仅验证固定文本投影、重新绑定和每次新鲜数据库探测的可行性；不是端到端或稳定版验收。PHP7.2原型首次因没有hrtime而在计时器处失败，SDK未被修改；后续真实SDK观察独立取得。修后第一份计数探测仍只匹配旧SQL前缀，PHP7.2报告0／0不能作为准备次数结论；正式测试同时分别统计原SQL和文本SQL前缀，没有用该记录宣称通过。

## 实际改动与保护

SqlSchema新增内部纯SQL生成器，最多保存1至4张表、普通／文本两种形式的8个固定代码模板；不保存表名值、数据库、行或权限结果。原生驱动无法读取获取格式时，SqlStateSnapshot对固定查询中的ordinal、position、SUB_PART及NON_UNIQUE投影为文本，NULL保持；排序仍依据原始数值，避免10排在2之前。支持getter的路径及自定义依赖继续使用原SQL。

SqlStateAccess只有在严格原生门槛、完整SQL及完整规范参数均一致时，才按已知文本／NULL格式复用已关闭语句。每次仍新读二进制数据库身份、绑定全部参数并执行查询；权限撤销、结构改变、临时表遮蔽和切库均重新观察。其他SQL保留原获取格式检查；非精确SQL或参数不取得这一例外。原有8槽语句池、关闭失败处理、异常模式、原生预处理和期限检查保持。

[源码增量](snapshot-text-pool-evidence-2026-10-24/source-change.diff)涉及SqlSchema、SqlStateAccess及SqlStateSnapshot三类。公开API仍为278类／接口，没有修改公开签名、DDL、摘要／存储格式或默认预算。内部SQL生成器不属于公开API。支持getter及自定义路径的SQL和参数在1至4表逐字相同，见[原SQL兼容核对](snapshot-text-pool-evidence-2026-10-24/original-sql.json)。[最终SDK／SQL摘要](snapshot-text-pool-evidence-2026-10-24/final-inputs.json)仍为367份；其余364份相对于本批开始保持。

## 本地检查

PHP7.2、7.3、7.4、8.0—8.5九版主轮72/72程序通过，包含新增18场景／版共162场景、账本语句回归、数据库上下文及五类MySQL快照回归。SQLite45程序、API9程序及静态检查共55/55通过。实际ZIP离线全新消费者在两端执行16个MySQL与10个SQLite程序，共26/26，流程7/7；反射来源及367份SDK／SQL摘要一致，自建资源清理通过。[MySQL主轮](snapshot-text-pool-evidence-2026-10-24/matrix.json)、[本地检查](snapshot-text-pool-evidence-2026-10-24/local-checks.json)、[消费者](snapshot-text-pool-evidence-2026-10-24/consumer/consumer.json)、[消费者逐程序结果](snapshot-text-pool-evidence-2026-10-24/consumer/test-rows.json)。这不代表全项目验收。

新专项共18种场景：正常复用、STRINGIFY切换、未注册连接、自定义PDO／Statement／守卫、未知自定义getter、Unicode切库、临时表遮蔽、结构变化、撤权、非精确SQL、非规范参数、代码模板和输入预算、13列数值排序与NULL／文本结果、关闭false、关闭异常及获取／关闭同时失败。正式日志分别记录准备／执行数；通用降级行为按各驱动实际属性能力判断，不把未知属性当作已知。当前环境7.2—8.1使用文本分支且准备1次、执行4次；8.2—8.5保留原SQL，仍准备1次、执行4次。分支选择依据能力，未硬编码PHP版本。见[九版正常观察](snapshot-text-pool-evidence-2026-10-24/normal-observations.json)。

全部功能和消费者程序结束后，针对实际改变的PHP7.2路径串行检查一次默认正常管理流程。使用既有只加载Sodium的包装器，保持真实SystemClock、PDO、纯来源守卫、策略提示1及原时长时钟；没有注入hrtime或提高3000ms预算。首次签发约3.005316秒返回account.completion_unknown、见证pending，未返回凭据；外层堆栈在issued的actor认证，内层原因未由该脱敏异常确认。后续查询、轮换、替换、撤销及拒绝场景未执行，未重试或续办。其余八版默认流程本批未重复执行，旧失败继续保留。[包装器及配置摘要](snapshot-text-pool-evidence-2026-10-24/default-runtime.json)、[计时](snapshot-text-pool-evidence-2026-10-24/workflow/default-72-timing.json)、[运行结果](snapshot-text-pool-evidence-2026-10-24/workflow/default-72-result.json)、[原始失败](snapshot-text-pool-evidence-2026-10-24/workflow/default-72-run.log)。

完整check.sh、跨安全代际工作进程交接、未知回执续办、最终账号恢复启用、依赖完整F01及外部验收未执行。默认预算稳定通过及最终非暂缓验收仍开放，不宣称稳定版完成。只清理自建进程和临时资源；未提交、推送、部署或更改内部任务数据库。
