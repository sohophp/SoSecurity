# 地址变更的显式捕获策略与返回复核

本批实现不依赖暂缓链路的地址申请／双邮箱确认／已登录账号改址。它不属于最终账号恢复启用，不运行跨安全代际工作进程交接、未知回执续办或完整F01。

## 已确认的问题与修复

现有原生地址入口只接受纯 `RolePolicy`，不能使用已经实现的 `SnapshotPolicy`。修前 [before-policy.log](address-captured-policy-evidence-2026-10-23/before-policy.log) 在配置准入处明确拒绝，不能用其他业务入口的支持记录代替地址功能。

新增显式 `$sdk->addressChange($statePolicy)`，适配准确的普通 `Grants` 对象，使地址内部消费与 `$sdk->operations($statePolicy)` 的准备／重新认证／确认使用相同的存储、身份、来源和策略。工厂配置不执行策略或审计回调；不同身份提供器、不同SQL来源、普通任意PolicyProvider及有副作用的审计组合继续拒绝。无参工厂的原有RolePolicy路径保留，无参SnapshotPolicy不会自动获得权限。

权限数据必须属于准确的完整 `SqlStateSnapshot`，写入者共享状态边界。沿用既有 `SnapshotEvaluator` 约定：selectors仅声明准确行，decide只使用捕获事实和静态配置；最多8行、每行16列／64KiB、合计256KiB，拒绝分页／计数。配置摘要绑定实际实现与静态配置。回调必须纯计算、只读、可重复；测试中的写入、异常、等待与重入是故障注入，不能用于生产策略。

准入和凭据消费前后均核对当前权限、真实会话、原始意图及有效期。消费桥与返回检查受同一个边界级重入锁保护，另一个适配器也不能重入消费；新建Deadline会与最初根期限取交集，不能延长期限。账号默认10000ms没有提高；默认凭据3000ms、审计预算及存储格式均未改变。

只读复核还发现晚期撤权缺口：凭据消费完成后，在地址请求的 `before` 守卫撤销捕获权限，旧实现仍正常返回。修前 [before-late-revocation.log](address-captured-policy-evidence-2026-10-23/before-late-revocation.log) 为明确反例。现在在地址业务SQL单元结束后、原状态边界返回前再次完整捕获并求值；请求阶段继续匹配真实当前会话，改址完成阶段以无旧令牌的捕获重建当前账户，并匹配业务已确认的实际身份。原始Intent不被改写，旧会话按设计保持失效。

原状态边界内的复核拒绝、异常或到期不返回成功；已提交修改保留，凭据不恢复，见证保持pending，不自动重试。晚期权限变更的测试覆盖申请与完成各自的before／commit／complete，并断言最后一次捕获确实读到allowed=0，避免将任意SQL超时当作撤权通过。现有完整快照必须拥有独立观察事务，不能把求值塞入beforeCommit而借用任意宿主事务；事务内最终权限、唯一约束与条件更新仍由原请求守卫／账号适配契约负责。提交后的复核不是提交前回滚保证。

随后还复现了最终预算回调撤销宿主守卫后仍返回成功的窗口，见[反例](address-captured-policy-evidence-2026-10-23/guard-probe-result.json)。四个原生入口现在在外层边界结束后执行只读返回检查：重建当前真实账户，复核完整来源与最终 `complete` 守卫，并在前后检查原始期限。这里使用真实数据库凭据版本，兼容密码绑定身份版本及既有SMTPUTF8设置。拒绝发生时外层见证已完成，保留current；不会人为改成pending或重放效果。守卫须支持重复只读调用，不应在 `complete` 阶段写入数据或外部投递。异常脱敏、跨适配器重入拒绝及默认预算保持。

重发申请复用旧流程期限，可能早于新批准的一次性许可。修前[流程期限反例](address-captured-policy-evidence-2026-10-23/before-flow-final-expiry.log)确认遗漏；申请和完成现在都取原始认证期限、许可期限与实际业务结果期限的最小值。当前工作进程只读检查的独立优化见[专项记录](current-worker-read-2026-10-23.md)，没有改变恢复或交接流程。

## 兼容性与公开契约

公开清单仍为277个类／接口，没有新增类型。原有参数不删除，`Security::addressChange` 仅增加可选的nullable StateAccountPolicy参数。显式新增的6个方法为StateAccountPolicy.activePolicyDigest、StateBoundary.withAddressConsumption、Grants.forAddress／consumeForAddress／addressCompletion及StateAccountConnection.addressReturn；它们提供准确上下文下的观察与内部桥接，不单独授予业务权限。

[首次API审查](address-captured-policy-evidence-2026-10-23/api-review.json)、[策略返回方法审查](address-captured-policy-evidence-2026-10-23/api-late-review.json)与[最终守卫方法审查](address-captured-policy-evidence-2026-10-23/api-guard-review.json)分别验证差异；不是用自动生成结果整份覆盖候选。classes.json和internal.json本批未改；历史268类型记录保留为历史。[7个运行时文件审查](address-captured-policy-evidence-2026-10-23/final-source-review.json)另有准确摘要。

## 本地验证

固定清单已结束：1124个外层命令，1117通过、7失败、0未执行，源码及其他冻结输入保持；见[终态](address-captured-policy-evidence-2026-10-23/current-verified/summary.json)、[逐项结果](address-captured-policy-evidence-2026-10-23/current-verified/verification.json)及[输入](address-captured-policy-evidence-2026-10-23/current-verified/inputs.json)。本次新执行782项，复用342项本轮早先执行且输入相同的结果，不是1124次新执行。

最初运行在344项后停下，只修正独立工作进程测试结束SQLite事务的写法：SQL启动的事务用SQL `COMMIT` 结束，不降低原来的事务丢失断言。此前两项失败保留；修正后所有直接依赖该测试的命令重新执行，其余结果按[逐文件影响核对](address-captured-policy-evidence-2026-10-23/current-verified/reuse-review.json)复用。编排器曾把超时秒数与超时布尔字段混为一项，造成一次0命令的比较断言失败；原记录保留，随后按原命令计划比较。上述测试与编排修正没有改变产品事务保护。

| 最终源码上的范围 | 已执行结果 |
| --- | --- |
| PHP7.2—8.5九版普通组件 | 981/981通过，其中327项为上述准确输入复用 |
| SQLite地址捕获策略及原有RolePolicy路径 | 110项，104通过／6失败；失败均为PHP7.2 |
| 普通操作授权、公开API反射 | 操作授权9/9、API反射9/9通过，每版本各1项；实际277类／接口 |
| 当前工作进程读取 | 九版SQLite各12场景及PHP7.2／8.5私有MySQL各12场景均通过 |
| 私有MySQL地址捕获策略 | 两个外层命令1通过／1失败；PHP8.5为20/20，PHP7.2为12/20，不能把部分PASS称整组通过 |
| PHPStan及shell语法 | 2/2通过 |
| 实际归档及全新消费者 | 14个外层步骤12通过／2失败；失败均为PHP7.2，详见下文 |
| 控制器数据库隔离 | 20次真实SQL探测通过，不计为地址产品用例 |

SQLite的6项失败中，5项原始日志明确记录持续时间时钟倒退；旧正常地址流程在首条old证明返回 `account.completion_unknown`，底层原因未记录。MySQL的8个失败子场景中，6项fatal正文明确记录倒退，另2项仅有脱敏的认证依赖错误，不能归因于时钟。原先73条及99条阶段验证属于较早源码，保留而不拼入当前结果；也不以本轮通过关闭历史未解释失败。

实际后端为SQLite3.26.0及MySQL8.0.46，见[版本记录](address-captured-policy-evidence-2026-10-23/database-versions.json)；没有宣称额外服务器版本矩阵或全项目验收。[统一终态汇总](address-captured-policy-evidence-2026-10-23/delivery.json)重新核对真实日志、全部冻结输入、14文件改动清单、7份运行时审查及API增量；汇总器不启动测试，因保留失败而退出1。

## 归档、隔离与单次诊断

[实际归档／离线消费者记录](address-captured-policy-evidence-2026-10-23/archive.json)包含真实Composer ZIP、独立安装、vendor来源、全部产品PHP文件及15份SQL资源摘要。14个外层步骤12通过／2失败；将两个控制器展开为其实际子程序后是20个去重程序17通过／3失败，两种统计不能相加。三个失败为PHP7.2 SQLite正常地址、MySQL正常地址、MySQL最终完成期限；前两项明确时钟倒退，后一项仅有脱敏认证依赖错误，原因未解释。PHP8.5消费者全部通过；四组SQLite／MySQL消费者的工作进程各12场景均通过。

[控制器隔离](address-captured-policy-evidence-2026-10-23/gate-isolation.json)使用两层真实私有MySQL及真实嵌套控制器，20次专用探测分别执行当前库名与 `SELECT 1`，验证独立socket、所有者、服务器及父进程；外层两表各一条标记及完整摘要保持。探测器没有加载产品PHP代码，不能把它称为又一轮地址产品测试。

原SQLite旧正常路径的未知错误仅追加[一次全新首条old证明诊断](address-captured-policy-evidence-2026-10-23/legacy-proof-diagnostic-result.json)：该次返回true、old=true／new=false、流程pending、见证current，随后停止。没有确认new证明或完成改址，也没有续办原未知记录。此次未复现，原失败原因仍未知，保持未关闭。临时副本只在原异常即将丢失时记录脱敏原因，原异常行为、时钟与预算不变；该副本不是候选验收代码。

以上运行均核对原始输入保持，并完成自身资源清理；没有提交、推送、部署、生产数据库访问或外部投递。此前失败日志和较早快照未删除。

## 仍开放的事项

本批是地址及普通组件定向验证，不是全项目验收。默认MySQL首次签发最近一次为3.028782581910491秒并返回account.completion_unknown／pending，见[当前代码证据](current-worker-read-evidence-2026-10-23/default-85-timing.json)；[上一批3.168616305秒失败](mysql-resolved-table-evidence-2026-10-23/default-timing.json)保留，不能用截断于预算附近的时间比较宣称性能提升。显式30000ms正常配置的通过不能关闭默认3000ms问题。PHP7.2时钟倒退及其他未解释失败保持原记录，不能从本批通过推断它们已解决。

固定普通组件及受影响组件清单已收口，但不能因此关闭完整非暂缓候选或稳定版关口。默认签发属于本地产品性能缺口，现有调用画像已充分，不再重复等价采样；尚无已证实的下一处安全去重修复，不能归为外部依赖或提高预算替代修复。PHP7.2墙钟限制及未解释的证明／认证依赖失败保持开放。

外部IdP、实体设备、生产代理／WAF、外部投递、CI和独立人员审查未执行。OIDC未定义的关联迁移按用户许可跳过。跨安全代际交接、未知回执续办、最终账号恢复启用及完整F01均未执行。当前goal保持active，本批结束不等于上述goal范围完成。
