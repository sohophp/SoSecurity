# MySqlStore构造锁等待与宿主事务（2026-10-24）

本批关闭此前独立复现的构造阶段缺口：`lockWaitSeconds=1`时，结构验证仍按会话元数据锁配置等待约4.007秒。构造现在先完整读取并关闭策略游标，再以原策略与既有`lockWaitSeconds`较小值验证结构，最终恢复原配置；不启动、提交或回滚调用方事务。初步修复的同一复现约1.009秒失败退出，最终源码另由九版真实锁等待场景验证。该限制按每次加锁计时，不是整个构造的硬截止时间。

正常构造、较短原策略、结构拒绝、读取失败、设置前后失败、回调改变策略及清理失败均有覆盖。普通SQL初始化不可用继续使用原`storage.schema`原因码；首版新增读取曾返回`storage.database`，由原隐私用例实际发现并修正，原失败保留。畸形策略以`storage.corrupt`拒绝，游标关闭或恢复不确定以`storage.cleanup`拒绝并要求重建连接。公开签名、278个公开类型、DDL、数据格式与默认参数未改。

最终SDK源码快照下，PHP7.2、7.3、7.4、8.0—8.5共378场景覆盖空闲、PDO开启和SQL开启的宿主事务。初轮28项通过后，PHP7.2测试误将`PDO::inTransaction()`的false当成事务丢失；诊断确认数据库事务仍为active、本连接保有未提交行、另一连接看不到该行。测试改用数据库实际事务探测，并保留探测前后的两连接数据可见性及调用方回滚检查；只补未执行的350项，均通过，未重跑已通过场景。

九版API检查、PHPStan，以及两端旧存储行为／事务归属／隐私回归通过；另有24项真实权限可见性、撤权和触发器场景通过。MySQL服务器为8.0.46；`MySqlStore`只支持MySQL，本批未将SQLite检查列为其验收。

归档与离线全新消费者的原6步骤为5通过／1测试状态假设失败：PHP7.2已有28项构造通过，PHP8.5全部42项构造和40项存储操作通过。随后重建消费者，仅补PHP7.2未执行的14项SQL宿主构造和40项操作，4步骤全部通过。两端共164项场景取得通过证据，367个源码／SQL文件摘要与安装来源一致，临时资源已清理；原失败与初轮测试源码均保留。

证据：[结果](mysql-store-constructor-evidence-2026-10-24/delivery.json)、[输入](mysql-store-constructor-evidence-2026-10-24/inputs.json)、[源码差异](mysql-store-constructor-evidence-2026-10-24/scope.diff)、[数据库实际状态诊断](mysql-store-constructor-evidence-2026-10-24/sql-host-diagnostic.log)、[原消费者](mysql-store-constructor-evidence-2026-10-24/consumer/consumer.json)、[消费者补充](mysql-store-constructor-evidence-2026-10-24/consumer-supplement/consumer.json)。

这不是全项目验收。默认原生签发预算、历史时钟／原生集成失败及最终非暂缓候选仍开放。未运行暂缓链路、未知回执续办或外部验收，未提交／推送／部署，goal保持active。
