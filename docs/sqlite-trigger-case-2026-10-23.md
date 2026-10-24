# SQLite 触发器表名大小写绕过修复（2026-10-23）

本批独立复现并修复 SqlSchema 的 SQLite 触发器漏检，不代表完整项目或稳定发行验收。原生恢复、跨安全代际交接、未知回执续办和完整 F01 均未执行。

SQLite 通过不区分大小写的标识符解析访问表，但旧触发器查询对 sqlite_master.tbl_name 使用区分大小写的比较。因此规范小写入口能读写大写声明的表，却漏掉该表上的触发器。修改前测试实际输出 `UNEXPECTED_ACCEPT`，表名为 `SOSECURITY_CASE_PROBE`，主库触发器产生一条业务副作用；见 [before.log](sqlite-trigger-case-evidence-2026-10-23/before.log)。

修复仅将主库／临时库触发器所属表名比较改为 `COLLATE NOCASE`。规范无触发器结构仍允许，不相关表的触发器不影响操作；大写或混合大小写声明不再绕过拒绝。公开签名、DDL、存储格式、默认预算及 MySQL 分支均保持。精确本轮差异见 [runtime.patch](sqlite-trigger-case-evidence-2026-10-23/runtime.patch)，其中不混入此前未提交修复。

新增 tests/sql-schema-trigger-case.php 使用独立 SQLite 文件，覆盖三种表名、无触发器／主库触发器／临时触发器／其他表触发器，以及独立事务和加入调用方事务。拒绝后业务回调不执行、没有副作用；加入已有事务时保留调用方预先写入的记录，最后由测试回滚。新测试已加入 bin/check.sh 的 SQLite 区段；未运行包含暂缓链路的完整脚本。

已执行并通过：PHP7.2、7.3、7.4、8.0—8.5 的 SQLite 36项程序／4338项断言；PHP8.5／私有 MySQL8.0.46 的结构、复用和依赖3项程序／376项断言；归档与两端全新消费者8步；PHPStan、API277及脚本语法和差异检查。原失败复现单独保留，没有改写为通过。

当前验证结果以 [verification.json](sqlite-trigger-case-evidence-2026-10-23/verification.json) 为准，源码摘要见 inputs.json；归档与全新消费者见 [archive-fixed.json](sqlite-trigger-case-evidence-2026-10-23/archive-fixed.json)。测试仅使用自有临时数据和私有 MySQL，不访问生产环境。

默认 MySQL 签发预算仍开放。本轮核对原执行计划，触发器子查询已标记 run only once，没有依据再次为它添加物化或缓存；未修改授权检查、提高预算或重跑未知结果。此前 PHP7.2 墙钟失败、其余非暂缓门禁和外部验收仍按各自证据保留，goal 保持 active。未提交、推送或部署。
