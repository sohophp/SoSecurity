# 幂等原生初始化与维护（2026-10-22）

## 当前实现

上一批只修复了未接入工厂的默认拒绝。本批继续实现 `SqlExecutor::initializeFor()`、`maintainFor()` 以及对应目标准备方法，公开工厂接受末尾可选的准确 `StateAccountConnection`。已有真实会话／账号／因子权限、完整SQL来源和独立见证共同决定准入；这两个原生入口不要求宿主自行包裹通用外层操作。

连接要求同一PDO、站点、范围、代际、时钟；组合来源必须包含完整 `sosecurity_idempotency_roots` 和 `sosecurity_idempotency_records` 定义，正文声明为 `blob:1048576`。实际宿主权限通过 `StatePermission` 指定准确操作、目标、当前会话、所需角色、强度和时效，不能从调用者给出的subject推导权限。原管理回调仍须明确允许实际scope／subject／operation，并在最终返回时复核。

在pending前，通过只读SQL事务验证原格式／封印、完整永久键历史、分页记录与正文。初始化发现既有合法根返回false，不推进见证；发现孤立历史或根表容量不足则拒绝。维护发现正在执行的未知记录保持拒绝，不提供续办。开始实际SQL效果时要求第一笔根读取与准入时完全相等；真实写入、到期正文压缩、重新签名及事务处理复用原状态机，永久键历史保留。

原生调用共享最初的I/O预算，观察事务不会延长预算。管理回调只能只读且可重复；按引用修改参数不会改写实际选择。观察、效果、最终返回之间检查业务时钟不回退，同一执行器禁止原生重入。独立见证完成后再复核宿主管理权限及真实会话权限，失权／过期不返回成功；已经完成的状态不退款、不回滚、不恢复旧权威。

## 兼容与尚缺功能

公开类型保持275个，未新增类型。`Security::idempotency()` 和 `SqlExecutor` 构造器仅末尾追加默认null的状态连接；已有参数和返回值保持。新增目标／原生管理方法及连接校验方法经逐项比较，见 `api-review.json`。普通模式的初始化、执行、查询及维护保持；保护模式不传准确连接继续拒绝。原 `initialize()` 的重复调用可能触碰根修订，而新 `initializeFor()` 对既有合法根直接返回false，不产生新的见证修订。

**首次业务执行和已知结果查询的原生入口仍待接入。** 当前不能把整个幂等保护模式写为完成；`execute()`／`lookup()` 的原始SQL保护不会因构造了带连接的执行器而绕过。测试为维护准备既有已知结果时使用自建的可信外层边界，只用于测试数据准备，不作为原生执行业务完成的证据。未知提交结果续办、跨安全代际交接和最终恢复启用继续暂缓。

Native initialization and maintenance bind the exact SQL graph, current session permission and existing host management callback. Denials and capacity checks happen before pending; permanent key history survives compaction and re-signing. Existing signatures only gain optional final connection parameters. Native business execution and result lookup remain unimplemented.

## 验证记录

九版专项覆盖无角色／管理拒绝、回调隐私、参数引用修改、同实例重入、首次初始化、重复初始化、实际根容量、原始入口拒绝、已知结果到期压缩和重新签名。另覆盖默认10秒预算、观察期间时钟回退、最终宿主撤权及最终会话到期。仅使用自建SQLite和私有禁TCP MySQL；PHP7.2的MySQL包装使用真实单调时钟，不能关闭默认时钟下的历史失败。

首轮静态检查发现重复的空值默认表达式，以及对宿主权限回调纯度的错误推断；分别移除重复表达式并明确该回调不纯，没有抑制诊断。最终静态、矩阵、SQL及消费者结果见 [result.json](native-idempotency-maintenance-evidence-2026-10-22/result.json)。PHP7.2矩阵的最终会话到期场景在约2.927秒触发SQL提前超时，消费者同场景约3.079秒亦失败；原始日志保留，不放宽预算、不重跑覆盖，不以使用另一时钟的通过关闭默认失败。

证据：[native-idempotency-maintenance-evidence-2026-10-22](native-idempotency-maintenance-evidence-2026-10-22/)。本批不是全项目九版门禁或稳定版验收。原有未提交改动、环境、数据及失败记录保留，没有提交、推送、部署、生产SQL或外部投递。goal继续active，其他非暂缓功能仍需继续补齐。

最终结果：九版定向62/63、两端私有MySQL10/10、归档／消费者13/14、两端语法12/12；全量PHPStan通过。两个默认PHP7.2提前超时保留，未重跑覆盖。四个运行时文件的归档安装摘要与当前源码一致，临时消费者及自建MySQL已清理。

> 幂等原生首次执行及已知结果查询已继续接入，见[本批实现与定向证据](native-idempotency-request-2026-10-22.md)。此前“首次执行／查询待接入”为历史状态；默认PHP7.2时钟失败、暂缓功能和外部验收保持开放。

> 最终管理回调的跨执行器重入已复现并修复，见[连接级重入保护](idempotency-maintenance-reentry-2026-10-22.md)。不关闭历史超时和整体验收。
