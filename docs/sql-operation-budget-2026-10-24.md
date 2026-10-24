# 原生活跃作用域的SQL预算传递

本批修复活跃原生作用域中的InnoDB行锁／SQLite忙等待预算传递，以及嵌套短预算过期后仍正常返回的问题。默认预算、DDL和持久化格式不变。真实签发还发现并纠正了中间候选把审计子预算错误用于完整执行的退化；最终候选仍有明确失败，不能称为稳定版验收。

## 修复与兼容

外层1000ms预算下，修前SQLite忙等待仍为10000ms，MySQL锁等待仍为10秒，见[SQLite修前](sql-operation-budget-evidence-2026-10-24/before-sqlite.log)和[MySQL修前](sql-operation-budget-evidence-2026-10-24/before-mysql.log)。执行状态现在保留当前截止时间，经准确绑定的原生SQL守卫传入SQL单元，在归属探测、等待设置及后续检查中与原预算取交集，不重启计时。

作用域离开时清除预算；嵌套预算在正常返回及异常时均恢复外层。回调在200ms预算内运行250ms的[修前用例](sql-operation-budget-evidence-2026-10-24/before-inner-timeout.log)原本成功返回，修后在返回前拒绝。预算传播本身不检查是否到期，因此不会阻止回滚和等待配置恢复。调用者显式共享的Deadline只会收紧。MySQL仍有最小1秒及向上取整限制，不承诺毫秒级中断PDO或任意回调。

协议只用于经身份核对的原生守卫；不透明自定义守卫没有收到新增参数，其调用者仍须显式传递共享预算。观察在作用域之外仍可执行，写入仍拒绝。连接注册表只保留小型执行状态，没有新增权限、行结果或完整来源图缓存。

### 审计准入与完整执行的区分

审计准备会主动把准入Deadline收紧至SQL审计子预算。中间候选错误地把这个较短期限也用于完整执行，导致[一次默认签发约1.387秒失败](sql-operation-budget-evidence-2026-10-24/default-before-scope-split/default-85-timing.json)。该失败及中间源码／测试记录保留，没有把专项通过当作完整签发通过。

`StateBoundary::run()` 新增第六个可选参数 `?Deadline $executionDeadline=null`。省略时沿用第五参作为执行预算；显式提供时，准入预算仍与完整执行预算取交集，较短审计准入限制不会放大，执行阶段使用独立的完整预算。`CredentialRegistry` 明确传入原有准入与完整请求两个Deadline。没有提高任何策略默认值，也没有改变已过期准入必须在发布pending前拒绝的规则。

这是本批唯一公开签名变化，原五个参数、默认值及所有其他签名保持，公开类型仍为278。先生成临时候选并逐项比较，确认只新增该可选参数才更新清单，见[契约审核](sql-operation-budget-evidence-2026-10-24/api-review.json)和[精确差异](sql-operation-budget-evidence-2026-10-24/api.diff)；不是忽略差异直接重新冻结清单。

## 最终专项

- [MySQL九版](sql-operation-budget-evidence-2026-10-24/mysql-matrix.json)、[SQLite九版](sql-operation-budget-evidence-2026-10-24/sqlite-matrix.json)：PHP7.2—8.5各180场景全部通过。每版20场景覆盖事务入口、借用读取、观察、无预算、嵌套长短／异常／超时、后续新作用域、作用域外读写、自定义守卫、真实锁竞争，以及分开的准入／执行预算。较短准入在pending前拒绝，执行预算较短时也不被准入预算延长。
- 实际锁竞争：PHP8.5 SQLite约0.965秒、MySQL约1.005秒返回，配置分别约961ms和1秒，见原两端smoke日志。均拒绝并保留pending失败证据，未续办；只释放自建持锁连接及临时资源。
- [九版公开契约](sql-operation-budget-evidence-2026-10-24/api-matrix.json)全部通过；[静态分析](sql-operation-budget-evidence-2026-10-24/phpstan.log)无错误，既有可选turbo扩展GLIBC警告保留。完整检查脚本仅验证Shell语法。
- 参数拆分前的[九版36条预算及归属程序](sql-operation-budget-evidence-2026-10-24/related-runtime-before-scope-split.json)全部通过，包括fork／Fiber、嵌套恢复、截止时间交集及无效／倒退时钟。其StateExecutionContext／Deadline等实际依赖的源码摘要保持，未为未使用的边界可选参数变化重复执行；PHP7.2—8.0没有Fiber，对应项目明确未运行。
- 参数拆分前[相关SQL回归](sql-operation-budget-evidence-2026-10-24/related-mysql.json)中入口／游标／锁等待组通过；PHP7.2当前工作进程前19项后，最后一项初始化遇时钟倒退失败，原日志保留。此前未执行的[PHP8.5完整20项](sql-operation-budget-evidence-2026-10-24/related-current-worker-context-85-unexecuted.log)通过。相关SQL单元、守卫和工作进程代码在参数拆分中保持，没有重跑失败项，不把补验算作原命令通过。

较早16场景候选的PHP7.2 SQLite初始化时钟失败也保留在 `sqlite-php72-before-scope-split.log`；对应后五个未执行项目曾独立补验通过。最终20场景矩阵是在修正真实签发发现的范围错误后重新执行，不抹掉旧失败或声称时钟问题已经解决。

## 消费者与原生组合的失败

[最终归档／离线消费者](sql-operation-budget-evidence-2026-10-24/consumer/consumer.json)8步骤7通过／1失败。实际安装的367个运行时／SQL文件逐一摘要一致，无符号链接，反射确认vendor来源；两端SQLite及PHP8.5 MySQL各20场景通过。PHP7.2 MySQL前五项通过，第六项observation出现未知完成、pending，原因未解释，不能擅自归为时钟问题。其后未执行的14项在[独立重建消费者](sql-operation-budget-evidence-2026-10-24/consumer-supplement/consumer.json)中逐项通过，4步骤通过，不替代原聚合失败。两次自身资源均已清理。

[原生审计组合](sql-operation-budget-evidence-2026-10-24/native-integration.json)中，两端普通委托及最终撤权／过期／范围／故障组通过。审计截止组在PHP7.2预算场景遇时钟倒退失败；[仅执行未运行项目](sql-operation-budget-evidence-2026-10-24/unexecuted-native.json)后，PHP7.2 normal及PHP8.5截止组三项通过。

晚返回组尚未通过：PHP7.2有时钟倒退及未解释的身份依赖失败；PHP8.5延迟成功／延迟撤权场景先触发整体超时，post-audit-timeout也在预期完成阶段之前失败，audit-admission-timeout通过。全部原断言及预算保持。补执行只选择原先未运行的独立预设环境，不续办任何未知回执，也不把失败改为通过。

## 时钟诊断

一次有限诊断仅在新建子进程及其持久化助手中观察真实gettimeofday返回值，原值、SDK时钟和拒绝分支不变。实际300次持久化完成，主进程观察8019次调用，未捕获倒退，见[诊断日志](sql-operation-budget-evidence-2026-10-24/clock-persistence-probe.log)及[观察记录](sql-operation-budget-evidence-2026-10-24/clock-observation.json)。诊断有额外开销，不作为正常验收，也不能解释或关闭历史失败。初次本地ABI编译及诊断文件权限预设错误的记录保留，修正测试预设后才执行有效观察；没有放宽持久化权限检查。临时观察库已清理，没有修改系统时间或持久环境。

## 剩余范围

最终PHP8.5原生时钟／PDO、3000ms首次签发约3.008720秒失败，状态pending、原因为account.completion_unknown；其他八版默认签发本批未执行。见[时序](sql-operation-budget-evidence-2026-10-24/default/default-85-timing.json)、[日志](sql-operation-budget-evidence-2026-10-24/default/default-85-run.log)及[输入与清理](sql-operation-budget-evidence-2026-10-24/default/default-85-result.json)。不续办未知结果，不将较早的1秒错误候选当作最终测量。

本修复限定为显式预算下的原生活跃SQL作用域。未传入作用域期限的入口、准入前／完成后的来源观察仍需继续核对预算传播。另在相同最终源码上[独立复现元数据等待超预算](sql-metadata-wait-evidence-2026-10-24/reproduction.json)：单元预算1000ms、InnoDB行锁限制1秒，但lock_wait_timeout仍为4秒，实际约4.011秒才失败；尚未修复，不能将当前行锁限额称为完整MySQL等待保护。默认签发可用性、晚返回失败、消费端未知错误、历史时钟倒退及最终非暂缓候选核对仍开放，goal保持active。这不是全项目或稳定版验收。

最终输入、归档及各组状态见[交付记录](sql-operation-budget-evidence-2026-10-24/delivery.json)和[374文件摘要](sql-operation-budget-evidence-2026-10-24/inputs.json)。跨安全代际交接、未知回执续办、恢复账号最终启用及完整F01未实现或测试，原有源码、审批和失败证据保持。没有访问生产数据库、外部投递、提交、推送或部署；只清理自行创建的资源。
