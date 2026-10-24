# 幂等及Outbox工厂保护边界（2026-10-22）

## 已复现的问题

启用认证 `state_boundary` 后，`Security::idempotency()` 仍可用完全独立的PDO构造执行器，未核对其是否进入完整来源；`Security::outbox()` 未传原生连接时也能这样构造服务。底层SQL保护绑定的是准确PDO，不能假定另一条连接会自动受保护。它们与其他受保护工厂的默认拒绝不一致。

使用已有完整认证／账号／因子／栅栏测试图，另外创建空的私有SQLite连接，两个工厂修复前均违反“必须拒绝”断言。记录为 `before.log` 和 `before-outbox.log`。测试不访问真实账号、不初始化外来数据库结构、不执行未知结果续办。

## 修复与当前功能边界

本批运行时仅改 `src/Security.php`：

- 认证保护模式的幂等工厂在原生准入尚未实现时明确抛 `configuration.state_entry_unsupported`。
- 认证保护模式的Outbox工厂要求非空且属于准确认证边界的 `StateAccountConnection`；构造器继续核对准确PDO、站点、代际及实际时钟。已有 `outbox($connection)` 原生轮换等入口保持可用。
- 普通模式两工厂保持原有行为；没有修改SQL状态机、原子事务、权限回调或未知结果处理。

公开API仍为275个类型，签名／候选字节未修改。使用认证保护模式的宿主不能把工厂构造成功当成完整来源已接入；不应通过删除保护配置或换PDO绕过新拒绝。直接实例化服务仍属可信宿主代码，不是PHP进程级沙箱；这次修复的是共享Security工厂的配置契约。

**幂等原生功能仍未完成。** 后续需接入准确完整SQL来源、真实当前权限、写入前只读准入、命名空间／永久键历史容量、同PDO业务提交以及最终返回复核。首次执行、已知完成结果查询及普通维护可独立实现；未知提交结果的续办继续暂缓。拒绝未接入服务只是默认保护修复，不能计为该产品功能已完成，也不能据此关闭goal。

## 验证

证据目录：[idempotency-factory-boundary-evidence-2026-10-22](idempotency-factory-boundary-evidence-2026-10-22/)。准确阶段结果见 `result.json`；运行时摘要、逐条命令、首次失败和修后日志分别保存。九版检查覆盖两个保护拒绝、普通工厂及API；两端另覆盖传入准确原生连接的Outbox轮换，SQLite／私有禁TCP MySQL及ZIP全新消费者分别记录。

首次新增的普通模式对照删除了authentication，却仍留下需要authentication的一次性操作配置，导致对照构造失败；初始矩阵、MySQL和消费者失败全部保留。修正测试为只包含site及两个SQL组件配置，重新执行受影响项；没有放宽产品检查，没有删除测试。PHP7.2私有MySQL仍使用既有单调时钟包装，不能据此关闭历史默认时钟超时。

这是工厂安全边界的定向验证，不是全项目或稳定版验收。暂缓功能、外部环境、历史失败和幂等原生缺口继续开放；无提交、推送、部署或生产数据库操作。

Protected authentication now rejects unconnected idempotency factories and requires the exact native account state connection for Outbox. Ordinary factories and public signatures are unchanged. Native idempotency admission remains an implementation gap; this default-deny fix does not complete it.

> 幂等原生初始化／维护已继续接入，见[当前实现](native-idempotency-maintenance-2026-10-22.md)。此前“幂等原生全部未实现”为历史状态；首次执行与结果查询仍开放，不能据此关闭整个缺口。
