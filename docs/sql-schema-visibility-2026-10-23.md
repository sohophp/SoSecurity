# 通用 SQL 表结构校验的触发器可见权限（2026-10-23）

本批修复 SqlSchema 的 MySQL 私有表校验：缺少 TRIGGER 可见权限的普通数据账号，原先可能从 information_schema 得到空触发器列表。独立两列表的真实事务已复现校验放行、业务回调执行一次、触发器副作用提交一条；见 [before.log](sql-schema-visibility-evidence-2026-10-23/before.log)。本测试不涉及账号恢复、未知回执续办或工作进程交接。

新增私有 triggerVisibility 方法，在 MySQL 结构校验前证明当前账号具有该表／库的直接 TRIGGER 权限，或 partial_revokes=OFF 时的全局直接权限。权限证明与触发器存在状态在同一 SELECT 读取，覆盖表／库撤权检查间隙。保留原有元数据预算、列／引擎／索引／外键及原触发器检查，不缓存账号权限、不提高任何预算。SQLite 分支和公开 API 不变。精确变化见 [runtime.patch](sql-schema-visibility-evidence-2026-10-23/runtime.patch)。

## 兼容与边界

采用通用 SqlSchema 的 MySQL 私有组件账号现在需要可证明的直接 TRIGGER 可见权限；仅角色授予、无法解析的账号身份或其他无法证明情形默认拒绝，原因码为 configuration.sql_schema。SDK 不自动授予权限、不建触发器、不迁移数据；规范 DDL、存储格式及公开 API277 保持。实际验证数据库为 MySQL8.0.46，其他 MySQL／MariaDB 版本没有通过结论。

结构查询测试原先只计一次带触发器检查的语句；新增权限证明后应为两次，tests/sql-schema-queries.php 按实际查询更正为2，列结构查询仍为1，没有删除任何拒绝断言。

本轮另验证 MySqlStore／Webhook 的全局授权与 partial_revokes 切换假设，两者均拒绝，副作用为零。未复现绕过，因此没有据此改动两份运行时代码。见 [观察记录](mysql-global-visibility-evidence-2026-10-23/observation.json)；测试保留为权限变化回归保护，不能把这次未复现扩大为任意管理员并发操作的保证。

## 验证证据

已执行并通过：九版 SQLite／MySQL 结构、复用与依赖54项程序／6534项断言；九版权限9项／585项断言；九版全局切换18项／126项断言；PHP7.2／8.5 SQL审计与独立账本4项／194项断言；归档与新消费者6步；静态分析和API277。静态分析可选turbo扩展的GLIBC加载警告保留，普通分析完成。以上均为定向范围。

[verification.json](sql-schema-visibility-evidence-2026-10-23/verification.json)记录逐项退出状态；inputs.json绑定运行时源码。[archive-fixed.json](sql-schema-visibility-evidence-2026-10-23/archive-fixed.json)记录归档、离线新消费者、来源检查及消费者实际MySQL权限测试。新增权限测试包含缺少权限、有／无触发器、直接表／库／全局授权、仅角色、撤权及表／库检查间隙，验证拒绝时回调不执行、状态和副作用均不写入、自有事务正确退出。

默认签发已用全新测试账号串行复验，3000ms预算保持。调用耗时3.353871495秒，PHP用户态／内核态CPU约0.446812／0.426316秒，首次actor在CredentialRegistry第109行期限检查失败，最终account.completion_unknown。后续列表、轮换、替换及撤销未执行，没有续办未知结果。计时包含失败传播与清理，不能解释为精确超出预算353ms，也不构成前后性能对照。新增权限证明增加查询开销；默认签发仍是本地产品缺口，不以安全专项通过掩盖它。见default-result.json／default-timing.json／default-run.log。历史PHP7.2墙钟失败、其他未齐门禁、外部验收及暂缓链路仍保留。goal保持active，没有提交、推送、部署或生产数据库操作。
