# MySqlStore索引隔离修复（2026-10-23）

## 已复现的缺陷

原实现只比较主键及清理索引的列名，接受字段前缀、错误唯一性和额外唯一索引。将主键的 `state_key` 截断为一个字符后，两个不同测试键的哈希前缀相同，`ON DUPLICATE KEY UPDATE` 把第二个键写入了第一个键的记录，实际读到 `{"owned":"first-key"}`。额外唯一索引也复现了同样的跨键混用。测试仅使用自建数据库和合成数据。

仅修构造检查后，又确认复用对象期间修改索引仍能绕过检查，因此补齐每次写入和清理的检查。原始反例、阶段源码和每阶段结果均保留，未用后续绿色结果覆盖：见 [首次跨键反例](mysql-store-index-evidence-2026-10-23/before.log)、[三类结构反例](mysql-store-index-evidence-2026-10-23/before-all.log)、[复用对象反例](mysql-store-index-evidence-2026-10-23/phase1-cached.log)、[额外唯一索引反例](mysql-store-index-evidence-2026-10-23/before-extra.log)。

## 最终行为与兼容

主键和清理索引须完整覆盖规范列、使用BTREE并保持指定唯一性；拒绝字段前缀和其他唯一索引。允许无关的非唯一索引。构造时检查，自有事务内再次取得表元数据锁并检查，拒绝发生在业务回调及状态修改前。相关索引元数据最多读取五行，不依赖无界遍历。

规范DDL、数据格式、公开方法签名及277个公开类型保持。此前被错误接受的结构现在抛出配置异常，需要部署流程修正；没有自动修改用户表或删除数据。[本批补丁](mysql-store-index-evidence-2026-10-23/batch.patch)只修改MySqlStore，外键查询优化另见[专项记录](foreign-constraint-query-2026-10-23.md)。

## 最终验证

- PHP7.2、7.3、7.4、8.0、8.1、8.2、8.3、8.4、8.5：真实私有MySQL8.0.46索引检查81/81通过，共180条断言。含规范结构下两键隔离、三类错误索引、额外唯一约束，以及复用对象的写入／清理拒绝。
- PHP7.2／8.5原有MySQL驱动测试各41条断言通过；12项真实SQL BEGIN／autocommit=0事务归属检查通过，保留宿主事务及跨连接可见性约束。
- 离线归档、全新消费者安装、vendor来源和消费者MySQL执行六个步骤全部通过，其中包含两端18个索引用例。安装源码摘要一致，自建消费者已清理。
- PHPStan与公开API契约通过；可选turbo扩展的既有GLIBC告警保留。最终运行时及测试摘要未在矩阵期间变化。

结果见 [汇总](mysql-store-index-evidence-2026-10-23/summary.json)、[最终矩阵](mysql-store-index-evidence-2026-10-23/matrix-final.json)、[其他检查](mysql-store-index-evidence-2026-10-23/verification-final.json)、[最终归档](mysql-store-index-evidence-2026-10-23/final-archive/archive.json)。初步七用例矩阵与最终九用例矩阵分开存放，不把初步结果替代最终结果。本模块只支持MySQL，未把SQLite测试算作本模块验收。

本批没有执行暂缓功能、生产数据库操作、外部投递、提交、推送或部署。默认凭据整体预算失败、既有PHP7.2默认时钟问题及剩余非暂缓候选核对未关闭，不代表完整稳定版验收；goal保持active。
