# MySqlStore 私有表触发器拒绝

默认凭据预算排查期间发现独立缺口：MySqlStore 核对外键、字段和索引，却允许私有状态表存在触发器。触发器可改变写入内容或产生规范外副作用。自有 MySQL 上，INSERT／UPDATE／DELETE 触发器分别配合构造、复用对象事务、清理共9个拒绝场景全部失败；规范表3个对照通过。原始 [before.log](mysql-store-triggers-evidence-2026-10-23/before.log) 保留。

修复为 verifySchema 增加当前库、固定表名、LIMIT 1 的触发器存在性查询；发现即返回 configuration.schema。复用对象仍在事务内锁定表后完整检查，拒绝发生在业务回调和删除之前。不修改触发器、不迁移数据、不放宽权限或预算。元数据可见性仍遵循宿主部署契约，不能把受限账号看见的空列表解释为完整数据库审计。

已执行并通过：PHP7.2—8.5九版真实 MySQL 108个触发器／规范表场景；PHP7.2与8.5每版41项原有驱动断言，以及合计12个真实宿主事务所有权场景。归档、离线全新消费者安装、来源定位及两端消费者合计6步骤通过，消费者24个同类场景通过。PHPStan通过（可选turbo扩展存在既有GLIBC加载警告），公开API清单277类／接口通过。见 [汇总及源码摘要](mysql-store-triggers-evidence-2026-10-23/summary.json)、[矩阵日志](mysql-store-triggers-evidence-2026-10-23/matrix.log)、[归档记录](mysql-store-triggers-evidence-2026-10-23/archive.json)。

兼容变化：带触发器的 sosecurity_state 表现在拒绝构造／写入／清理；规范DDL和公开签名不变。仅改 MySQL 存储路径，未执行SQLite或全项目测试，不声称最终稳定版验收。自有数据库和消费者临时目录已由运行器清理，没有提交、推送、部署或访问生产数据库。

默认MySQL凭据签发尚未修复。本轮为诊断增加有界、无参数的代码调用路径计数，单次全新隔离运行约3.060秒后仍返回account.completion_unknown，见证pending，未续办。热点是FactorWorkerAuthority中的账本检查和SqlStateSnapshot；存在热点不代表可以删除校验。见 [结构化诊断](native-query-profile-evidence-2026-10-23/profile.json)。这些诊断时间包含观测开销，不用来宣称性能达标或解释全部历史失败。暂缓和外部验收保持，goal为active。
