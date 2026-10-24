# 上传隔离原生准入（2026-10-22）

## 实际缺口与实现

此前 `Security::quarantine()` 没有状态连接参数，只能在宿主显式提供外层边界时使用受保护文件；[文件来源专项](quarantine-state-source-2026-10-22.md)仅完成底层保护，其 `before.json` 保留工厂零参数记录。本批增加 `StateQuarantineConnection`，把公开工厂、入队、指定／自动选择扫描、查询、读取、重新扫描、拒绝和终态清理接入原生准入。

连接要求同一边界、见证、完整组合来源、准确元数据 FileStore、准确文件来源、实际时钟和扫描器实例。工厂要求站点共享命名空间一致，上传策略和文件容量与来源一致，实际元数据及临时目录均不得位于 Web 根目录内。连接不创建初始权威、不迁移现有来源、不自动接管工作进程。

宿主提供无业务副作用、可重复执行的授权回调：`guard(action, authorityScope, queueScope, targetId, descriptor)` 返回实际当前操作者，或 `null`／`false` 拒绝。首次调用描述为空，用于在读取上传输入之前授权；后续以实际条目编号、代次、状态和内容摘要授权。自动选择扫描必须对选中的实际条目重新授权。队列级查询由宿主显式授权，不自动推导账号角色。回调按引用修改参数不会改变已选操作或资源。异常转换为固定错误，不附带原始异常链。

元数据只读捕获、格式／到期检查、容量和普通状态拒绝均在 pending 前进行；第一笔实际写入还要求原始账本完全相等。只读查询和无候选结果不消耗见证修订。真实效果复用既有业务状态机；原生连接阻止扫描器重入公开管理操作。效果后和最终见证完成后均检查当前权限、预算、时钟及内容期限，失权／过期不返回文件。最终拒绝不撤销已经完成的状态，也不恢复原权限。

扫描中失权或内容到期会保留 pending。过期 `scanning`、`deleting` 等未知进行中状态不通过原生入口恢复或续办；自动扫描仅选择 pending 或既有明确 retry 条目。本批没有执行未知结果续办、跨安全代际交接或最终账号恢复。扫描适配器仍是可信宿主代码，SDK 不能抢占不返回的同步回调；宿主仍须设置实际引擎的进程／网络超时。

## 兼容变化

公开类型由274增至275；新增连接及 `StateOperation::quarantine()` 描述方法。`Security::quarantine()` 和 `Upload\Quarantine` 构造器末尾仅追加默认 `null` 的可选连接，原有参数、返回类型和普通模式行为保持。候选逐项比较记录在 [api-review.json](native-quarantine-evidence-2026-10-22/api-review.json)，没有盲目沿用用户最初的268个类型。新原生入口要求显式权限和完整来源，不允许通过原始文件存储绕过。

Native quarantine requires the exact metadata/content graph, scanner and current host authorization. Existing calls remain valid; the native connection is an optional final parameter. Authorization is repeated before input access, against the selected entry, and before returning. Unknown scan outcomes stay isolated; this change provides no takeover or recovery continuation.

## 本地测试与限制

- PHP7.2—8.5九版首轮定向63/63命令通过：五类原生场景、普通工厂回归和275类型反射检查；追加时钟隐私、扫描异常、扫描期间到期27/27命令通过，另记 `extra-matrix.json`。
- 两端私有、禁TCP MySQL的10/10场景通过。PHP7.2使用既有独立单调时钟包装；这不能关闭其他专项在默认时钟下未解释的提前超时。
- 实际ZIP归档、离线全新Composer安装、vendor来源核对及两端消费者14/14命令通过；五个运行时文件的安装包摘要与源码一致，消费者目录已清理。
- 两端语法12/12通过；PHP7.2目标全量PHPStan通过。现有可选turbo扩展GLIBC加载警告保留。
- 初始静态检查发现闭包外初始化为null造成控制流推断问题，改为显式非空检查方法；随后删除未使用捕获。测试首次读取了错误的自建见证文件名，改用只读 `inspect()` 检查pending。原始失败日志保留，不计为通过，不涉及放宽产品保护。

准确脚本、日志、摘要及汇总见 [证据目录](native-quarantine-evidence-2026-10-22/) 和 [result.json](native-quarantine-evidence-2026-10-22/result.json)。本批是定向验证，不是冻结候选九版全项目验收。真实生产扫描引擎、外部平台、远端CI和独立审查未执行。历史失败、其他未核对产品入口及暂缓功能均未据此关闭，goal继续active。没有提交、推送、部署或访问生产数据。

## 完整认证工厂组合补充

另将上传隔离加入已有认证、SQL账号、因子文件、工作进程栅栏及独立见证的同一完整来源，验证未传连接默认拒绝、准确连接的正常入队／扫描／读取／拒绝／清理。只初始化自建的首次根，不执行恢复或安全代际交接。九版SQLite9/9和两端新归档消费者均通过，两端私有MySQL2/2通过，结果见 `protected-mysql.log`；补充归档／消费者6/6、测试语法4/4通过。测试首次遗漏被包含PHP文件的命名空间别名，以及新增自建目录的清理分支；失败保留 `protected-initial.log`，修复测试并仅删除该失败日志标识的自建临时目录，没有更改运行时保护。
